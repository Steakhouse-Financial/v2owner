/*
// SPDX-License-Identifier: UNLICENSED
*/
pragma solidity ^0.8.33;

import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";
import { EnumerableSet } from "openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title VaultV2Supervisor
 * @author Steakhouse Financial
 * @notice A contract to manage multiple VaultV2 contracts with timelocked owner functions and guardian protections.
 */
contract VaultV2Supervisor {
    using EnumerableSet for EnumerableSet.AddressSet;

    error NotOwner();
    error ZeroAddress();
    error NotGuardian();
    error NoPendingRemoval();
    error TimelockNotExpired();
    error OnlyOwnerOrVaultOwner();
    error DataAlreadyTimelocked();
    error DataNotTimelocked();
    error OnlyOwnerOrGuardian();
    error InvalidAmount();
    error NotAllowedVaultOwner();
    error NoOp();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RemoveSentinelSubmitted(address indexed vault, address indexed account, uint256 executeAfter);
    event RemoveSentinelRevoked(address indexed vault, address indexed account, address indexed guardian);
    event RemoveSentinelAccepted(address indexed vault, address indexed account);
    event AllowedVaultOwnerSet(address indexed vaultOwner, bool allowed);

    address public owner;
    uint256 public immutable timelock; // in seconds

    mapping(bytes data => uint256) public executableAt;

    mapping(address vaultOwner => bool) public allowedVaultOwners;

    mapping(address vault => EnumerableSet.AddressSet) private _guardians;

    // Owner only modifier
    modifier onlyOwner() {
        require(msg.sender == owner, NotOwner());
        _;
    }

    // Guardian only modifier, a guardian is a sentinel on the underlying vault
    modifier onlyGuardian(IVaultV2 vault) {
        require(_guardians[address(vault)].contains(msg.sender), NotGuardian());
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        timelock = 14 days;
    }

    /* Owner functions */
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), ZeroAddress());
        require(newOwner != owner, NoOp());
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
        uint256 eta = executableAt[msg.data];
        require(eta != 0, DataNotTimelocked());
        require(block.timestamp >= eta, TimelockNotExpired());

        executableAt[msg.data] = 0;
    }

    function revoke(bytes calldata data) external {
        address vault = _extractVaultAddress(data);
        require(_guardians[vault].contains(msg.sender) || msg.sender == owner, OnlyOwnerOrGuardian());
        require(executableAt[data] != 0, DataNotTimelocked());

        executableAt[data] = 0;
    }

    function _extractVaultAddress(bytes calldata data) internal pure returns (address v) {
        // data = 4-byte selector + abi-encoded args; first arg is address(IVaultV2)
        if (data.length < 36) return address(0);
        v = abi.decode(data[4:36], (address));
    }

    ////////////////////////////////////////////////////////
    // Vault V2 Owner functions with no timelock
    ////////////////////////////////////////////////////////

    function setCurator(IVaultV2 vault, address newCurator) external onlyOwner {
        require(vault.curator() != newCurator, NoOp());
        vault.setCurator(newCurator);
    }

    function setName(IVaultV2 vault, string memory newName) external onlyOwner {
        require(keccak256(bytes(vault.name())) != keccak256(bytes(newName)), NoOp());
        vault.setName(newName);
    }

    function setSymbol(IVaultV2 vault, string memory newSymbol) external onlyOwner {
        require(keccak256(bytes(vault.symbol())) != keccak256(bytes(newSymbol)), NoOp());
        vault.setSymbol(newSymbol);
    }

    function addSentinel(IVaultV2 vault, address account) external onlyOwner {
        vault.setIsSentinel(account, true);
    }

    function setAllowedVaultOwner(address vaultOwner, bool allowed) external onlyOwner {
        require(vaultOwner != address(0), ZeroAddress());
        require(allowedVaultOwners[vaultOwner] != allowed, NoOp());
        allowedVaultOwners[vaultOwner] = allowed;
        emit AllowedVaultOwnerSet(vaultOwner, allowed);
    }

    /** @notice Adds a guardian for a vault
     * @param vault The vault to add the guardian for
     * @param guardian The guardian address to add
     * @dev Can be called by the owner or the vault owner so we can register a guardian before ownership transfer
     */
    function addGuardian(IVaultV2 vault, address guardian) external {
        address vaultOwner = vault.owner();
        require(
            msg.sender == owner || (msg.sender == vaultOwner && allowedVaultOwners[vaultOwner]),
            OnlyOwnerOrVaultOwner()
        );
        _guardians[address(vault)].add(guardian);
    }

    function getGuardians(IVaultV2 vault) external view returns (address[] memory) {
        return _guardians[address(vault)].values();
    }

    ////////////////////////////////////////////////////////
    // Timelocked function that guardians can challenge
    ////////////////////////////////////////////////////////


    function setOwner(IVaultV2 vault, address newOwner) external onlyOwner {
        timelocked();

        require(vault.owner() != newOwner, NoOp());
        vault.setOwner(newOwner);
    }

    function removeSentinel(IVaultV2 vault, address sentinel) external onlyOwner {
        timelocked();

        require(sentinel != address(this), "Supervisor can't be removed as sentinel");

        vault.setIsSentinel(sentinel, false);
    }

    function removeGuardian(IVaultV2 vault, address guardian) external onlyOwner {
        timelocked();

        _guardians[address(vault)].remove(guardian);
    }

    ////////////////////////////////////////////////////////
    // Guardian functions to protect the vault
    ////////////////////////////////////////////////////////
    function revoke(IVaultV2 vault, bytes memory data) external onlyGuardian(vault) {
        vault.revoke(data);
    }


    /**
     * @notice Sets the supervisor contract as a sentinel on the vault (permissionless)
     * @param vault The vault to set the sentinel on
     * @dev This ensure that the supervisor can always act as a sentinel
     */
    function setSupervisorAsGuardian(IVaultV2 vault) external {
        require(!vault.isSentinel(address(this)), NoOp());
        vault.setIsSentinel(address(this), true);
    }
}
