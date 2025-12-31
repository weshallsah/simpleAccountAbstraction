// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/test/utils/cryptography/MessageHashUtils.t.sol";

contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;
    function run() public {}

    function geberateSignedUserOperation(
        bytes memory callData,
        address sender,
        HelperConfig.NetworkConfig memory config
    ) public returns (PackedUserOperation memory) {
        uint256 nonce = vm.getNonce(config.account);
        PackedUserOperation memory unsignedUserOp = _generateUnsignedUserOperation(sender, nonce, callData);

        bytes32 userOpHash = IEntryPoint(config.entryPoint).getUserOpHash(unsignedUserOp);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(config.account, digest);
        unsignedUserOp.signature = abi.encodePacked(v, r, s);
        return unsignedUserOp;
    }

    function _generateUnsignedUserOperation(address sender, uint256 nonce, bytes memory callData)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        uint128 verificationGasLimit = 16777276;
        uint128 callGasLimit = verificationGasLimit;
        uint128 maxpriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxpriorityFeePerGas;
        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: uint256(verificationGasLimit),
            gasFees: bytes32(uint256(maxpriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: hex"",
            signature: hex""
        });
    }
}

