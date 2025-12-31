// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {USDC} from "../src/ERC20/USDC.sol";

contract USDCTest is Test {
    USDC public usdc;

    address public owner;
    address public minter;
    address public user1;
    address public user2;

    uint256 public user1PrivateKey;
    uint256 public user2PrivateKey;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    function setUp() public {
        owner = address(this);
        minter = makeAddr("minter");

        user1PrivateKey = 0x1234;
        user2PrivateKey = 0x5678;
        user1 = vm.addr(user1PrivateKey);
        user2 = vm.addr(user2PrivateKey);
        
        usdc = new USDC("USDC Token", "USDC", "1");
    }

    // ============ Constructor Tests ============

    function test_constructor() public view {
        assertEq(usdc.name(), "USDC Token");
        assertEq(usdc.symbol(), "USDC");
        assertEq(usdc.decimals(), 6);
        assertEq(usdc.owner(), owner);
        assertTrue(usdc.hasRole(DEFAULT_ADMIN_ROLE, owner));
        assertTrue(usdc.hasRole(MINTER_ROLE, owner));
    }

    // ============ Decimals Tests ============

    function test_decimals() public view {
        assertEq(usdc.decimals(), 6);
    }

    // ============ Mint Tests ============

    function test_mint() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);
        assertEq(usdc.balanceOf(user1), amount);
    }

    function test_mint_multipleUsers() public {
        usdc.mint(user1, 1000 * 10 ** 6);
        usdc.mint(user2, 2000 * 10 ** 6);

        assertEq(usdc.balanceOf(user1), 1000 * 10 ** 6);
        assertEq(usdc.balanceOf(user2), 2000 * 10 ** 6);
        assertEq(usdc.totalSupply(), 3000 * 10 ** 6);
    }

    function test_mint_withMinterRole() public {
        usdc.grantRole(MINTER_ROLE, minter);

        vm.prank(minter);
        usdc.mint(user1, 1000 * 10 ** 6);

        assertEq(usdc.balanceOf(user1), 1000 * 10 ** 6);
    }

    function test_mint_revertWithoutMinterRole() public {
        vm.prank(user1);
        vm.expectRevert();
        usdc.mint(user1, 1000 * 10 ** 6);
    }

    // ============ Burn Tests ============

    function test_burn() public {
        uint256 mintAmount = 1000 * 10 ** 6;
        uint256 burnAmount = 400 * 10 ** 6;

        usdc.mint(user1, mintAmount);

        vm.prank(user1);
        usdc.burn(user1, burnAmount);

        assertEq(usdc.balanceOf(user1), mintAmount - burnAmount);
    }

    function test_burn_entireBalance() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        vm.prank(user1);
        usdc.burn(user1, amount);

        assertEq(usdc.balanceOf(user1), 0);
    }

    function test_burn_revertInsufficientBalance() public {
        usdc.mint(user1, 1000 * 10 ** 6);

        vm.prank(user1);
        vm.expectRevert();
        usdc.burn(user1, 2000 * 10 ** 6);
    }

    // ============ Access Control Tests ============

    function test_grantMinterRole() public {
        usdc.grantRole(MINTER_ROLE, minter);
        assertTrue(usdc.hasRole(MINTER_ROLE, minter));
    }

    function test_revokeMinterRole() public {
        usdc.grantRole(MINTER_ROLE, minter);
        usdc.revokeRole(MINTER_ROLE, minter);
        assertFalse(usdc.hasRole(MINTER_ROLE, minter));
    }

    // ============ ERC3009 transferWithAuthorization Tests ============

    function test_transferWithAuthorization() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);

        assertEq(usdc.balanceOf(user1), 0);
        assertEq(usdc.balanceOf(user2), amount);
        assertTrue(usdc.authorizationState(user1, nonce));
    }

    function test_transferWithAuthorization_revertNotYetValid() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        uint256 validAfter = block.timestamp + 1 hours;
        uint256 validBefore = block.timestamp + 2 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        vm.expectRevert("Authorization not yet valid");
        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_revertExpired() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        // Warp to a future time to avoid underflow
        vm.warp(block.timestamp + 3 hours);

        uint256 validAfter = block.timestamp - 2 hours;
        uint256 validBefore = block.timestamp - 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        vm.expectRevert("Authorization expired");
        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_revertAlreadyUsed() public {
        uint256 amount = 500 * 10 ** 6;
        usdc.mint(user1, 1000 * 10 ** 6);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);

        vm.expectRevert("Authorization already used");
        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);
    }

    function test_transferWithAuthorization_revertInvalidSignature() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user2PrivateKey, digest); // wrong signer

        vm.expectRevert("Invalid signature");
        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);
    }

    // ============ ERC3009 receiveWithAuthorization Tests ============

    function test_receiveWithAuthorization() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        vm.prank(user2);
        usdc.receiveWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);

        assertEq(usdc.balanceOf(user1), 0);
        assertEq(usdc.balanceOf(user2), amount);
        assertTrue(usdc.authorizationState(user1, nonce));
    }

    function test_receiveWithAuthorization_revertCallerNotPayee() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        // Call from different address than payee
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        vm.expectRevert("Caller must be the payee");
        usdc.receiveWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);
    }

    // ============ ERC3009 cancelAuthorization Tests ============

    function test_cancelAuthorization() public {
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, user1, nonce));

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        usdc.cancelAuthorization(user1, nonce, v, r, s);

        assertTrue(usdc.authorizationState(user1, nonce));
    }

    function test_cancelAuthorization_revertAlreadyUsed() public {
        uint256 amount = 1000 * 10 ** 6;
        usdc.mint(user1, amount);

        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, user1, user2, amount, validAfter, validBefore, nonce)
        );

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user1PrivateKey, digest);

        usdc.transferWithAuthorization(user1, user2, amount, validAfter, validBefore, nonce, v, r, s);

        // Try to cancel already used nonce
        bytes32 cancelStructHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, user1, nonce));
        bytes32 cancelDigest = _getTypedDataHash(cancelStructHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user1PrivateKey, cancelDigest);

        vm.expectRevert("Authorization already used");
        usdc.cancelAuthorization(user1, nonce, v2, r2, s2);
    }

    function test_cancelAuthorization_revertInvalidSignature() public {
        bytes32 nonce = keccak256("nonce1");

        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, user1, nonce));

        bytes32 digest = _getTypedDataHash(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user2PrivateKey, digest); // wrong signer

        vm.expectRevert("Invalid signature");
        usdc.cancelAuthorization(user1, nonce, v, r, s);
    }

    // ============ Helper Functions ============

    function _getTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _getDomainSeparator(), structHash));
    }

    function _getDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("USDC Token")),
                keccak256(bytes("1")),
                block.chainid,
                address(usdc)
            )
        );
    }
}
