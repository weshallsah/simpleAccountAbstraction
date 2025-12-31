// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {SimpleAccout} from "../src/ethereum/MinimalAcount.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract DeploySimple is Script {
    SimpleAccout private simpleAccount;

    function run() public {}

    function deploySimpleAccount() public returns (HelperConfig, SimpleAccout) {
        HelperConfig helper = new HelperConfig();
        HelperConfig.NetworkConfig memory config = helper.getConfig();
        vm.startBroadcast(config.account);
        simpleAccount = new SimpleAccout(config.entryPoint);
        simpleAccount.transferOwnership(msg.sender);
        vm.stopBroadcast();
        return (helper, simpleAccount);
    }
}
