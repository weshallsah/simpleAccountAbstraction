// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC3009} from "./ERC3009.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract USDC is ERC3009, AccessControl, Ownable {
    bytes32 private constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(string memory _name, string memory _symbol, string memory _version)
        ERC3009(_name, _symbol, _version)
        Ownable(msg.sender)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
    }

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }

    function mint(address account, uint256 value) external onlyRole(MINTER_ROLE) {
        _mint(account, value);
    }

    function burn(address account, uint256 value) external {
        _burn(account, value);
    }

    function setMinter(address user) external onlyOwner {
        _grantRole(MINTER_ROLE, user);
    }
}

