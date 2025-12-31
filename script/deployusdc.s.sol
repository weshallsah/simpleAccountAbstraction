// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {USDC} from "../src/ERC20/USDC.sol";

contract DeployUSDC is Script {
    USDC private usdc;

    function run() public returns (address) {
        vm.startBroadcast();
        usdc = new USDC("USDC Token", "USDC", "1");
        usdc.setMinter(0xc6377415Ee98A7b71161Ee963603eE52fF7750FC);
        vm.stopBroadcast();
        return address(usdc);
    }
}
