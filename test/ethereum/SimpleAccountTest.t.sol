// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SimpleAccout} from "../../src/ethereum/MinimalAcount.sol";
import {DeploySimple} from "../../script/deploySimple.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SendPackedUserOp} from "../../script/SendPackedUserOp.s.sol";

contract SimpleAccountTest is Test {
    SimpleAccout private simpleAccount;
    HelperConfig private config;
    ERC20Mock usdc;
    SendPackedUserOp sendpackuedserOp;

    function setUp() public {
        DeploySimple deploy = new DeploySimple();
        (config, simpleAccount) = deploy.deploySimpleAccount();
        usdc = new ERC20Mock();
        sendpackuedserOp = new SendPackedUserOp();
    }

    // USDC Mint

    // msg.sender => SimpleAccount
    // approve some amount
    // USDC contract
    // come from the entryPoint

    function testownerCanExecuteCommands() public {
        assertEq(usdc.balanceOf(address(simpleAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(simpleAccount), 100);
        vm.prank(simpleAccount.owner());
        simpleAccount.execute(dest, value, functionData);

        assertEq(usdc.balanceOf(address(simpleAccount)), 100);
    }

    function testNonOwnerCannotExecuteCommands() public {
        address user = makeAddr("Randomuser");
        assertEq(usdc.balanceOf(address(simpleAccount)), 0);
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(simpleAccount), 100);
        vm.prank(user);
        vm.expectRevert(SimpleAccout.SimpleAccout__NotFromEntryPointOrOwner.selector);
        simpleAccount.execute(dest, value, functionData);

        // assertEq(usdc.balanceOf(address(simpleAccount)), 100);
    }

    function testRecoverSignedOp() public {
        
    }

    function testValidationOfUserOps() public {

    }
}
