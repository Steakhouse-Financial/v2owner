/*
// SPDX-License-Identifier: UNLICENSED
*/
pragma solidity ^0.8.28;

import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";

contract VaultV2Supervisor {
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
    uint256 public timelock; // in seconds

    mapping(bytes data => uint256) public executableAt;

    mapping(address vault => mapping(address guardian => bool)) private _guardians;

    // Owner only modifier
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // Guardian only modifier, a guardian is a sentinel on the underlying vault
    modifier onlyGuardian(IVaultV2 vault) {
        if(!_guardians[address(vault)][msg.sender]) revert NotGuardian();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        timelock = 7 days;
    }

    /* Owner functions */
    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address previous = owner;
        owner = newOwner;
        emit OwnershipTransferred(previous, newOwner);
    }


    ////////////////////////////////////////////////////////
    // Timelocking
    ////////////////////////////////////////////////////////

    function submit(bytes calldata data) external onlyOwner {
        require(executableAt[data] == 0, DataAlreadyTimelocked());
        require(data.length >= 4, InvalidAmount());

        executableAt[data] = block.timestamp + timelock;
    }

    function timelocked() internal {
        require(executableAt[msg.data] > 0, DataNotTimelocked());
        require(block.timestamp >= executableAt[msg.data], TimelockNotExpired());

        executableAt[msg.data] = 0;
    }

    function revoke(bytes calldata data) external {
        address vault = address(bytes20(data[4:24])); // TODO: extract the vault address from the data
        require(_guardians[vault][msg.sender] || msg.sender == owner, OnlyOwnerOrGuardian());
        require(executableAt[data] > 0, DataNotTimelocked());

        executableAt[data] = 0;

        emit TimelockRevoked(bytes4(data), data, msg.sender);
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

    /** @notice Adds a guardian for a vault
     * @param vault The vault to add the guardian for
     * @param guardian The guardian address to add
     * @dev Can be called by the owner or the vault owner so we can register a guardian before ownership transfer
     */
    function addGuardian(IVaultV2 vault, address guardian) external {
        // TODO: need to protect that a bit more to avoid spam
        require(msg.sender == owner || msg.sender == vault.owner(), OnlyOwnerOrVaultOwner());
        _guardians[address(vault)][guardian] = true;
    }

    ////////////////////////////////////////////////////////
    // Timelocked function that guardians can challenge
    ////////////////////////////////////////////////////////

    function removeSentinel(IVaultV2 vault, address sentinel) external {
        timelocked();

        vault.setIsSentinel(sentinel, false);
    }

    function removeGuardian(IVaultV2 vault, address guardian) external {
        timelocked();

        _guardians[address(vault)][guardian] = false;
    }

    ////////////////////////////////////////////////////////
    // Guardian functions to protect the vault
    ////////////////////////////////////////////////////////
    function revoke(IVaultV2 vault, bytes data) external onlyGuardian(vault) {
        vault.revoke(data);
    }
}