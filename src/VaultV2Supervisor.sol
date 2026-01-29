// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.33;

import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";
import { EnumerableSet } from "openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

/// @title VaultV2Supervisor
/// @author Steakhouse Financial
/// @notice Supervises Vault V2 instances with timelocked owner actions and guardian vetoes.
/// @dev The supervisor is intended to own one or more Vault V2 contracts.
contract VaultV2Supervisor {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev Caller is not the supervisor owner.
    error NotOwner();
    /// @dev Provided address is zero.
    error ZeroAddress();
    /// @dev Caller is not a registered guardian for the vault.
    error NotGuardian();
    /// @dev Reserved for future use.
    error NoPendingRemoval();
    /// @dev Timelock has not expired yet.
    error TimelockNotExpired();
    /// @dev Caller is neither the supervisor owner nor the vault owner.
    error OnlyOwnerOrVaultOwner();
    /// @dev Timelock data is already scheduled.
    error DataAlreadyTimelocked();
    /// @dev Timelock data is not scheduled.
    error DataNotTimelocked();
    /// @dev Caller is neither the supervisor owner nor a guardian.
    error OnlyOwnerOrGuardian();
    /// @dev Calldata length is invalid.
    error InvalidAmount();
    /// @dev Vault owner is not allowlisted to self-manage guardians.
    error NotAllowedVaultOwner();
    /// @dev Operation would not change state.
    error NoOp();
    /// @dev Sentinel removal attempted for the supervisor address.
    error CannotRemoveSupervisorSentinel();

    /// @notice Emitted when the supervisor owner changes.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    /// @notice Emitted when a sentinel removal is scheduled.
    event RemoveSentinelSubmitted(address indexed vault, address indexed account, uint256 executeAfter);
    /// @notice Emitted when a sentinel removal is revoked.
    event RemoveSentinelRevoked(address indexed vault, address indexed account, address indexed guardian);
    /// @notice Emitted when a sentinel removal is executed.
    event RemoveSentinelAccepted(address indexed vault, address indexed account);
    /// @notice Emitted when a vault owner is allowlisted or removed.
    event AllowedVaultOwnerSet(address indexed vaultOwner, bool allowed);

    /// @notice Address of the supervisor owner.
    address public owner;
    /// @notice Timelock duration for sensitive actions, in seconds.
    uint256 public immutable timelock;
    /// @notice Execution timestamp for scheduled calldata.
    /// @dev Keyed by the exact calldata of the action.
    mapping(bytes data => uint256) public executableAt;
    /// @notice Allowlist for vault owners that may add guardians for their vaults.
    mapping(address vaultOwner => bool) public allowedVaultOwners;
    /// @dev Per-vault guardian set.
    mapping(address vault => EnumerableSet.AddressSet) private _guardians;

    /// @dev Restricts execution to the supervisor owner.
    modifier onlyOwner() {
        require(msg.sender == owner, NotOwner());
        _;
    }

    /// @dev Restricts execution to a guardian registered for the vault.
    modifier onlyGuardian(IVaultV2 vault) {
        require(_guardians[address(vault)].contains(msg.sender), NotGuardian());
        _;
    }

    /// @notice Initializes the supervisor with msg.sender as owner and a 14 day timelock.
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        timelock = 14 days;
    }

    /// @notice Transfers supervisor ownership.
    /// @param newOwner The new owner address.
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), ZeroAddress());
        require(newOwner != owner, NoOp());
        address previous = owner;
        owner = newOwner;
        emit OwnershipTransferred(previous, newOwner);
    }

    /// @notice Schedules a timelocked action.
    /// @param data Full calldata of the action to execute later.
    function submit(bytes calldata data) external onlyOwner {
        require(executableAt[data] == 0, DataAlreadyTimelocked());
        require(data.length >= 4, InvalidAmount());
        executableAt[data] = block.timestamp + timelock;
    }

    /// @notice Cancels a pending timelocked action.
    /// @param data Full calldata that was previously submitted.
    function revoke(bytes calldata data) external {
        address vault = _extractVaultAddress(data);
        require(_guardians[vault].contains(msg.sender) || msg.sender == owner, OnlyOwnerOrGuardian());
        require(executableAt[data] != 0, DataNotTimelocked());
        executableAt[data] = 0;
    }

    /// @dev Validates and consumes the timelock for the current calldata.
    function timelocked() internal {
        uint256 eta = executableAt[msg.data];
        require(eta != 0, DataNotTimelocked());
        require(block.timestamp >= eta, TimelockNotExpired());
        executableAt[msg.data] = 0;
    }

    /// @notice Sets the curator on a vault (no timelock).
    /// @param vault The vault to update.
    /// @param newCurator The new curator address.
    function setCurator(IVaultV2 vault, address newCurator) external onlyOwner {
        require(vault.curator() != newCurator, NoOp());
        vault.setCurator(newCurator);
    }

    /// @notice Sets the name on a vault (no timelock).
    /// @param vault The vault to update.
    /// @param newName The new name.
    function setName(IVaultV2 vault, string memory newName) external onlyOwner {
        require(keccak256(bytes(vault.name())) != keccak256(bytes(newName)), NoOp());
        vault.setName(newName);
    }

    /// @notice Sets the symbol on a vault (no timelock).
    /// @param vault The vault to update.
    /// @param newSymbol The new symbol.
    function setSymbol(IVaultV2 vault, string memory newSymbol) external onlyOwner {
        require(keccak256(bytes(vault.symbol())) != keccak256(bytes(newSymbol)), NoOp());
        vault.setSymbol(newSymbol);
    }

    /// @notice Adds a sentinel on a vault (no timelock).
    /// @param vault The vault to update.
    /// @param account The sentinel address to add.
    function addSentinel(IVaultV2 vault, address account) external onlyOwner {
        vault.setIsSentinel(account, true);
    }

    /// @notice Allowlists or removes a vault owner for guardian self-management.
    /// @param vaultOwner The vault owner address.
    /// @param allowed Whether the owner is allowed to add guardians for its vaults.
    function setAllowedVaultOwner(address vaultOwner, bool allowed) external onlyOwner {
        require(vaultOwner != address(0), ZeroAddress());
        require(allowedVaultOwners[vaultOwner] != allowed, NoOp());
        allowedVaultOwners[vaultOwner] = allowed;
        emit AllowedVaultOwnerSet(vaultOwner, allowed);
    }

    /// @notice Adds a guardian for a vault.
    /// @param vault The vault to add the guardian for.
    /// @param guardian The guardian address to add.
    /// @dev Vault owners can call only if allowlisted; the supervisor owner can always call.
    function addGuardian(IVaultV2 vault, address guardian) external {
        address vaultOwner = vault.owner();
        require(
            msg.sender == owner || (msg.sender == vaultOwner && allowedVaultOwners[vaultOwner]),
            OnlyOwnerOrVaultOwner()
        );
        _guardians[address(vault)].add(guardian);
    }

    /// @notice Returns the guardians registered for a vault.
    /// @param vault The vault to query.
    function getGuardians(IVaultV2 vault) external view returns (address[] memory) {
        return _guardians[address(vault)].values();
    }

    /// @notice Transfers vault ownership after the timelock.
    /// @param vault The vault to update.
    /// @param newOwner The new owner address.
    function setOwner(IVaultV2 vault, address newOwner) external onlyOwner {
        timelocked();
        require(vault.owner() != newOwner, NoOp());
        vault.setOwner(newOwner);
    }

    /// @notice Removes a sentinel from a vault after the timelock.
    /// @param vault The vault to update.
    /// @param sentinel The sentinel address to remove.
    function removeSentinel(IVaultV2 vault, address sentinel) external onlyOwner {
        timelocked();
        require(sentinel != address(this), CannotRemoveSupervisorSentinel());
        vault.setIsSentinel(sentinel, false);
    }

    /// @notice Removes a guardian from a vault after the timelock.
    /// @param vault The vault to update.
    /// @param guardian The guardian address to remove.
    function removeGuardian(IVaultV2 vault, address guardian) external onlyOwner {
        timelocked();
        _guardians[address(vault)].remove(guardian);
    }

    /// @notice Forwards a revoke to the vault's timelock.
    /// @param vault The vault to target.
    /// @param data The vault calldata to revoke.
    function revoke(IVaultV2 vault, bytes memory data) external onlyGuardian(vault) {
        vault.revoke(data);
    }

    /// @notice Sets the supervisor contract as a sentinel on a vault (permissionless).
    /// @param vault The vault to update.
    function setSupervisorAsGuardian(IVaultV2 vault) external {
        require(!vault.isSentinel(address(this)), NoOp());
        vault.setIsSentinel(address(this), true);
    }

    /// @dev Extracts the vault address from a supervisor calldata payload.
    /// @param data Full calldata (selector + ABI args) for a supervisor action.
    /// @return v The decoded vault address, or address(0) if data is too short.
    function _extractVaultAddress(bytes calldata data) internal pure returns (address v) {
        if (data.length < 36) return address(0);
        v = abi.decode(data[4:36], (address));
    }
}
