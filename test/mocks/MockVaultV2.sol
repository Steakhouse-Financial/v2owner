// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract MockVaultV2 {
    address public owner;
    address public curator;
    string public name;
    string public symbol;

    mapping(address => bool) public isSentinel;

    bytes public lastRevokeData;

    event OwnerSet(address indexed newOwner);
    event CuratorSet(address indexed newCurator);
    event NameSet(string newName);
    event SymbolSet(string newSymbol);
    event SentinelSet(address indexed account, bool isSentinel);
    event RevokeCalled(bytes data);

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
        emit OwnerSet(newOwner);
    }

    function setCurator(address newCurator) external {
        curator = newCurator;
        emit CuratorSet(newCurator);
    }

    function setName(string memory newName) external {
        name = newName;
        emit NameSet(newName);
    }

    function setSymbol(string memory newSymbol) external {
        symbol = newSymbol;
        emit SymbolSet(newSymbol);
    }

    function setIsSentinel(address account, bool sentinel) external {
        isSentinel[account] = sentinel;
        emit SentinelSet(account, sentinel);
    }

    // Vault-level timelock revoke stub
    function revoke(bytes memory data) external {
        lastRevokeData = data;
        emit RevokeCalled(data);
    }
}
