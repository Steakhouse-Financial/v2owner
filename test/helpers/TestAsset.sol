// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.33;

import { ERC20 } from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract TestAsset is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}
}
