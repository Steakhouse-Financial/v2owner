/*
// SPDX-License-Identifier: UNLICENSED
*/
pragma solidity ^0.8.28;

import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";

contract V2Owner {
    error NotOwner();
    error ZeroAddress();
    error NotGuardian();
    error NoPendingRemoval();
    error TimelockNotExpired();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RemoveSentinelSubmitted(address indexed vault, address indexed account, uint256 executeAfter);
    event RemoveSentinelRevoked(address indexed vault, address indexed account, address indexed guardian);
    event RemoveSentinelAccepted(address indexed vault, address indexed account);

    address public owner;
    uint256 private _removeSentinelDelay; // in seconds

    mapping(address vault => mapping(address sentinel => uint)) private _pendingRemoveSentinel;

    // Owner only modifier
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // Guardian only modifier, a guardian is a sentinel on the underlying vault
    modifier onlyGuardian(IVaultV2 vault) {
        if(!vault.isSentinel(msg.sender)) revert NotGuardian();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        _removeSentinelDelay = 7 days;
    }

    /* Owner functions */
    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address previous = owner;
        owner = newOwner;
        emit OwnershipTransferred(previous, newOwner);
    }

    ////////////////////////////////////////////////////////
    // Vault V2 Owner functions with no timelock
    ////////////////////////////////////////////////////////

    function setOwner(IVaultV2 vault, address newOwner) external onlyOwner {
        vault.setOwner(newOwner);
    }

    function setCurator(IVaultV2 vault, address newCurator) external onlyOwner {
        vault.setCurator(newCurator);
    }

    function setName(IVaultV2 vault, string memory newName) external onlyOwner {
        vault.setName(newName);
    }

    function setSymbol(IVaultV2 vault, string memory newSymbol) external onlyOwner {
        vault.setSymbol(newSymbol);
    }

    function addSentinel(IVaultV2 vault, address account) external onlyOwner {
        vault.setIsSentinel(account, true);
    }

    ////////////////////////////////////////////////////////
    // Vault V2 Sentinel removal with timelock
    ////////////////////////////////////////////////////////

    function submitRemoveSentinel(IVaultV2 vault, address sentinel) external onlyOwner {
        address v = address(vault);
        uint256 t = block.timestamp + _removeSentinelDelay;
        _pendingRemoveSentinel[v][sentinel] = t;
        emit RemoveSentinelSubmitted(v, sentinel, t);
    }

    function revokeRemoveSentinel(IVaultV2 vault, address sentinel) external onlyGuardian(vault) {
        address v = address(vault);
        uint256 t = _pendingRemoveSentinel[v][sentinel];
        if (t == 0) revert NoPendingRemoval();
        emit RemoveSentinelRevoked(v, sentinel, msg.sender);
    }

    function acceptRemoveSentinel(IVaultV2 vault, address sentinel) external onlyOwner {
        address v = address(vault);
        uint256 t = _pendingRemoveSentinel[v][sentinel];
        if (t == 0) revert NoPendingRemoval();
        if (block.timestamp < t) revert TimelockNotExpired();

        delete _pendingRemoveSentinel[v][sentinel];

        vault.setIsSentinel(sentinel, false);
        emit RemoveSentinelAccepted(v, sentinel);
    }
}