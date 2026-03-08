// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract OwnableOTP is EIP712 {
    address public owner;

    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "TransferOwnership(address newOwner,bytes32 passwordHash)"
    );

    bytes32 public storedPasswordHash;
    bool public otpUsed;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PasswordUpdated();

    constructor(string memory _password) EIP712("OwnableOTP", "1") {
        owner = msg.sender;
        storedPasswordHash = keccak256(abi.encodePacked(_password));
    }

    function transferOwnership(
        address newOwner,
        string calldata password,
        bytes calldata signature
    ) external {
        require(newOwner != address(0), "OTP: zero address");
        require(!otpUsed, "OTP: already used");

        bytes32 passwordHash = keccak256(abi.encodePacked(password));
        require(passwordHash == storedPasswordHash, "OTP: wrong password");

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(TRANSFER_TYPEHASH, newOwner, passwordHash))
        );
        address signer = ECDSA.recover(digest, signature);
        require(signer == owner, "OTP: invalid signature");

        otpUsed = true;

        address previous = owner;
        owner = newOwner;

        emit OwnershipTransferred(previous, newOwner);
    }

    function setPassword(string calldata newPassword) external {
        require(msg.sender == owner, "OTP: not owner");
        storedPasswordHash = keccak256(abi.encodePacked(newPassword));
        otpUsed = false;
        emit PasswordUpdated();
    }

    function getDigest(address newOwner, bytes32 passwordHash) external view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(TRANSFER_TYPEHASH, newOwner, passwordHash))
        );
    }
}