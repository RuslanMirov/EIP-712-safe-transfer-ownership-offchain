import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;

async function buildDomain(contract) {
  const { chainId } = await ethers.provider.getNetwork();
  return {
    name: "OwnableOTP",
    version: "1",
    chainId,
    verifyingContract: await contract.getAddress(),
  };
}

const TYPES = {
  TransferOwnership: [
    { name: "newOwner",     type: "address" },
    { name: "passwordHash", type: "bytes32" },
  ],
};

async function signTransfer(signer, domain, newOwner, password) {
  const passwordHash = ethers.keccak256(ethers.toUtf8Bytes(password));
  const signature = await signer.signTypedData(domain, TYPES, { newOwner, passwordHash });
  return { signature, passwordHash };
}

describe("OwnableOTP", function () {
  const PASS = "super-secret-123";
  let contract, owner, newOwner, relayer, attacker, domain;

  beforeEach(async function () {
    [owner, newOwner, relayer, attacker] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("OwnableOTP");
    contract = await Factory.connect(owner).deploy(PASS);
    await contract.waitForDeployment();
    domain = await buildDomain(contract);
  });

  describe("Deployment", function () {
    it("sets deployer as owner", async function () {
      expect(await contract.owner()).to.equal(owner.address);
    });
    it("stores hashed password", async function () {
      const expected = ethers.keccak256(ethers.toUtf8Bytes(PASS));
      expect(await contract.storedPasswordHash()).to.equal(expected);
    });
    it("OTP not used on deploy", async function () {
      expect(await contract.otpUsed()).to.equal(false);
    });
  });

  describe("transferOwnership — happy path", function () {
    it("transfers ownership with valid sig + password", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature);
      expect(await contract.owner()).to.equal(newOwner.address);
    });
    it("emits OwnershipTransferred", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await expect(contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature))
        .to.emit(contract, "OwnershipTransferred")
        .withArgs(owner.address, newOwner.address);
    });
    it("burns OTP after transfer", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature);
      expect(await contract.otpUsed()).to.equal(true);
    });
    it("relayer (not owner, not newOwner) can submit", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature);
      expect(await contract.owner()).to.equal(newOwner.address);
    });
    it("newOwner can submit their own transfer", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(newOwner).transferOwnership(newOwner.address, PASS, signature);
      expect(await contract.owner()).to.equal(newOwner.address);
    });
  });

  describe("transferOwnership — wrong password", function () {
    it("reverts with wrong password", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await expect(
        contract.connect(relayer).transferOwnership(newOwner.address, "wrong", signature)
      ).to.be.revertedWith("OTP: wrong password");
    });
    it("reverts with empty password", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await expect(
        contract.connect(relayer).transferOwnership(newOwner.address, "", signature)
      ).to.be.revertedWith("OTP: wrong password");
    });
  });

  describe("transferOwnership — invalid signature", function () {
    it("reverts when attacker signs", async function () {
      const { signature } = await signTransfer(attacker, domain, newOwner.address, PASS);
      await expect(
        contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature)
      ).to.be.revertedWith("OTP: invalid signature");
    });
    it("reverts when newOwner is swapped", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await expect(
        contract.connect(attacker).transferOwnership(attacker.address, PASS, signature)
      ).to.be.revertedWith("OTP: invalid signature");
    });
    it("reverts with zero address", async function () {
      const { signature } = await signTransfer(owner, domain, ethers.ZeroAddress, PASS);
      await expect(
        contract.connect(relayer).transferOwnership(ethers.ZeroAddress, PASS, signature)
      ).to.be.revertedWith("OTP: zero address");
    });
  });

  describe("transferOwnership — replay protection", function () {
    it("reverts on replay after success", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature);
      await expect(
        contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature)
      ).to.be.revertedWith("OTP: already used");
    });
  });

  describe("setPassword", function () {
    it("owner can rotate password and reset OTP", async function () {
      await contract.connect(owner).setPassword("new-pass");
      const expected = ethers.keccak256(ethers.toUtf8Bytes("new-pass"));
      expect(await contract.storedPasswordHash()).to.equal(expected);
      expect(await contract.otpUsed()).to.equal(false);
    });
    it("emits PasswordUpdated", async function () {
      await expect(contract.connect(owner).setPassword("new-pass"))
        .to.emit(contract, "PasswordUpdated");
    });
    it("non-owner cannot set password", async function () {
      await expect(contract.connect(attacker).setPassword("hacked"))
        .to.be.revertedWith("OTP: not owner");
    });
    it("old sig fails after password rotation", async function () {
      const { signature } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(owner).setPassword("rotated");
      await expect(
        contract.connect(relayer).transferOwnership(newOwner.address, PASS, signature)
      ).to.be.revertedWith("OTP: wrong password");
    });
    it("chain of transfers works", async function () {
      const { signature: sig1 } = await signTransfer(owner, domain, newOwner.address, PASS);
      await contract.connect(relayer).transferOwnership(newOwner.address, PASS, sig1);
      expect(await contract.owner()).to.equal(newOwner.address);

      await contract.connect(newOwner).setPassword("next-pass");
      const { signature: sig2 } = await signTransfer(newOwner, domain, attacker.address, "next-pass");
      await contract.connect(relayer).transferOwnership(attacker.address, "next-pass", sig2);
      expect(await contract.owner()).to.equal(attacker.address);
    });
  });

  describe("getDigest", function () {
    it("matches off-chain computation", async function () {
      const passwordHash = ethers.keccak256(ethers.toUtf8Bytes(PASS));
      const onChain = await contract.getDigest(newOwner.address, passwordHash);
      const offChain = ethers.TypedDataEncoder.hash(domain, TYPES, { newOwner: newOwner.address, passwordHash });
      expect(onChain).to.equal(offChain);
    });
  });
});