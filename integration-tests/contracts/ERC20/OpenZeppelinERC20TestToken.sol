// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// import "./ERC20.sol";
import "../vendor/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract OpenZeppelinERC20TestToken is ERC20 {
    constructor(address owner) ERC20("TestToken1", "TT1") {
        _mint(owner, 999999 * 18 ** decimals());
    }
}

