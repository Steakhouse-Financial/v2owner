// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {IVaultV2} from "vault-v2/src/interfaces/IVaultV2.sol";
import {EnumerableSet} from "openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

interface IRevokable {
    function revoke(bytes calldata data) external;
}

interface ISkimRecipient {
    function setSkimRecipient(address newSkimRecipient) external;
}

/// @title VaultV2Supervisor
/// @author Steakhouse Financial
/// @notice Act as improved owner for Vault V2 instances with timelocked owner actions and guardian vetoes.
/// @dev The supervisor is intended to own one or more Vault V2 contracts.
contract VaultV2Supervisor {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev Caller is not the supervisor owner.
    error NotOwner();
    /// @dev Provided address is zero.
    error ZeroAddress();
    /// @dev Caller is not a registered guardian for the vault.
    error NotGuardian();
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
    /// @dev Provided timelock duration is invalid.
    error InvalidTimelock();
    /// @dev An ownership change is already scheduled.
    error OwnershipChangeAlreadyScheduled();
    /// @dev Operation would not change state.
    error NoOp();
    /// @dev Caller is not the pending supervisor owner.
    error NotPendingSupervisorOwner();
    /// @dev Sentinel removal attempted for the supervisor address.
    error CannotRemoveSupervisorSentinel();

    /// @notice Emitted when the supervisor owner changes.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    /// @notice Emitted when a new supervisor owner is proposed.
    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
    /// @notice Emitted when a vault owner is allowlisted or removed.
    event AllowedVaultOwnerSet(address indexed vaultOwner, bool allowed);
    /// @notice Emitted when a timelocked action is submitted.
    event TimelockSubmitted(
        address indexed sender, address indexed vault, bytes4 indexed selector, bytes data, uint256 executeAfter
    );
    /// @notice Emitted when a timelocked action is revoked.
    event TimelockRevoked(address indexed sender, address indexed vault, bytes4 indexed selector, bytes data);
    /// @notice Emitted when a guardian is added for a vault.
    event GuardianAdded(address indexed vault, address indexed guardian, address indexed sender);
    /// @notice Emitted when a guardian is removed for a vault.
    event GuardianRemoved(address indexed vault, address indexed guardian, address indexed sender);
    /// @notice Emitted when a vault-level revoke is forwarded.
    event VaultRevokeForwarded(address indexed sender, address indexed vault, bytes4 indexed selector, bytes data);

    /// @notice Address of the supervisor owner.
    address public owner;
    /// @notice Proposed supervisor owner waiting to accept ownership.
    address public pendingSupervisorOwner;
    /// @notice Timelock duration for sensitive actions, in seconds.
    uint256 public immutable timelock;
    /// @notice Execution timestamp for scheduled calldata.
    /// @dev Keyed by the exact calldata of the action.
    mapping(bytes data => uint256) public executableAt;
    /// @notice Map listing the vaults for which a new owner is submitted but not executed, if any
    mapping(address vault => address) public scheduledNewOwner;
    /// @notice Allowlist for vault owners that may add guardians for their vaults.
    mapping(address vaultOwner => bool) public allowedVaultOwners;
    /// @dev Set of vaults with at least one registered guardian.
    EnumerableSet.AddressSet private _vaults;
    /// @dev Per-vault guardian set.
    mapping(address vault => EnumerableSet.AddressSet) private _guardians;

    /// @dev Restricts execution to the supervisor owner.
    modifier onlyOwner() {
        require(msg.sender == owner, NotOwner());
        _;
    }

    /// @dev Restricts execution to a guardian registered for the vault.
    modifier onlyGuardian(address vault) {
        require(_guardians[vault].contains(msg.sender), NotGuardian());
        _;
    }

    /// @notice Initializes the supervisor owner and timelock.
    /// @param timelock_ Timelock duration for sensitive actions, in seconds.
    constructor(uint256 timelock_) {
        require(timelock_ > 0, InvalidTimelock());
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        timelock = timelock_;
    }

    /// @notice Starts a two-step transfer of supervisor ownership.
    /// @param newOwner The proposed new owner address.
    function transferSupervisorOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), ZeroAddress());
        require(newOwner != owner, NoOp());
        require(newOwner != pendingSupervisorOwner, NoOp());

        pendingSupervisorOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Accepts supervisor ownership as the pending owner.
    function acceptSupervisorOwnership() external {
        require(msg.sender == pendingSupervisorOwner, NotPendingSupervisorOwner());

        address previous = owner;
        owner = msg.sender;
        pendingSupervisorOwner = address(0);
        emit OwnershipTransferred(previous, msg.sender);
    }

    /// @notice Schedules a timelocked action.
    /// @param data Full calldata of the action to execute later.
    function submit(bytes calldata data) external onlyOwner {
        require(executableAt[data] == 0, DataAlreadyTimelocked());
        require(data.length >= 4, InvalidAmount());

        bytes4 selector = _selector(data);
        address vault = _extractVaultAddress(selector, data);
        uint256 executeAfter = block.timestamp + timelock;

        if (selector == this.setOwner.selector) {
            (address v, address newO) = abi.decode(data[4:], (address, address));
            require(v != address(0) && newO != address(0), ZeroAddress());
            require(newO != IVaultV2(v).owner(), NoOp());
            require(scheduledNewOwner[v] == address(0), OwnershipChangeAlreadyScheduled());
            scheduledNewOwner[v] = newO;
        }

        executableAt[data] = executeAfter;
        emit TimelockSubmitted(msg.sender, vault, selector, data, executeAfter);
    }

    /// @notice Cancels a pending timelocked action.
    /// @param data Full calldata that was previously submitted.
    function revoke(bytes calldata data) external {
        bytes4 selector = _selector(data);
        address vault = _extractVaultAddress(selector, data);

        require(_guardians[vault].contains(msg.sender) || msg.sender == owner, OnlyOwnerOrGuardian());
        require(executableAt[data] != 0, DataNotTimelocked());

        if (selector == this.setOwner.selector) {
            scheduledNewOwner[vault] = address(0);
        }

        executableAt[data] = 0;
        emit TimelockRevoked(msg.sender, vault, selector, data);
    }

    /// @notice Cancels a pending guardian removal timelock.
    /// @param vault The vault whose guardian removal was submitted.
    /// @param guardian The guardian address being removed.
    function revokeGuardianRemoval(IVaultV2 vault, address guardian) external {
        address vaultAddress = address(vault);
        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, guardian);
        _revokeKnownVault(data, vaultAddress, VaultV2Supervisor.removeGuardian.selector);
    }

    /// @notice Cancels a pending vault ownership transfer timelock.
    /// @param vault The vault whose ownership transfer was submitted.
    function revokeVaultOwnerChange(IVaultV2 vault) external {
        address vaultAddress = address(vault);
        bytes memory data =
            abi.encodeWithSelector(VaultV2Supervisor.setOwner.selector, vault, scheduledNewOwner[vaultAddress]);
        _revokeKnownVault(data, vaultAddress, VaultV2Supervisor.setOwner.selector);
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
    function setName(IVaultV2 vault, string calldata newName) external onlyOwner {
        require(keccak256(bytes(vault.name())) != keccak256(bytes(newName)), NoOp());
        vault.setName(newName);
    }

    /// @notice Sets the symbol on a vault (no timelock).
    /// @param vault The vault to update.
    /// @param newSymbol The new symbol.
    function setSymbol(IVaultV2 vault, string calldata newSymbol) external onlyOwner {
        require(keccak256(bytes(vault.symbol())) != keccak256(bytes(newSymbol)), NoOp());
        vault.setSymbol(newSymbol);
    }

    /// @notice Sets the skim recipient on a vault adapter (no timelock).
    /// @param skimable The adapter to update.
    /// @param newSkimRecipient The new skim recipient address.
    function setSkimRecipient(address skimable, address newSkimRecipient) external onlyOwner {
        ISkimRecipient(skimable).setSkimRecipient(newSkimRecipient);
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
    function addGuardian(address vault, address guardian) external {
        require(vault != address(0) && guardian != address(0), ZeroAddress());

        address vaultOwner = IVaultV2(vault).owner();
        require(
            msg.sender == owner || (msg.sender == vaultOwner && allowedVaultOwners[vaultOwner]), OnlyOwnerOrVaultOwner()
        );

        require(_guardians[vault].add(guardian), NoOp());
        _vaults.add(vault);
        emit GuardianAdded(vault, guardian, msg.sender);
    }

    /// @notice Transfers vault ownership after the timelock.
    /// @param vault The vault to update.
    /// @param newOwner The new owner address.
    function setOwner(IVaultV2 vault, address newOwner) external onlyOwner {
        timelocked();
        require(vault.owner() != newOwner, NoOp());
        scheduledNewOwner[address(vault)] = address(0);
        vault.setOwner(newOwner);
    }

    /// @notice Removes a sentinel from a vault.
    /// @param vault The vault to update.
    /// @param sentinel The sentinel address to remove.
    function removeSentinel(IVaultV2 vault, address sentinel) external onlyOwner {
        require(sentinel != address(this), CannotRemoveSupervisorSentinel());
        vault.setIsSentinel(sentinel, false);
    }

    /// @notice Removes a guardian from a vault after the timelock.
    /// @param vault The vault to update.
    /// @param guardian The guardian address to remove.
    function removeGuardian(IVaultV2 vault, address guardian) external onlyOwner {
        timelocked();
        address vaultAddress = address(vault);

        require(_guardians[vaultAddress].remove(guardian), NoOp());

        if (_guardians[vaultAddress].length() == 0) {
            _vaults.remove(vaultAddress);
        }

        emit GuardianRemoved(vaultAddress, guardian, msg.sender);
    }

    /// @notice Forwards a revoke to the vault's timelock.
    /// @param vault The vault to target.
    /// @param data The vault calldata to revoke.
    function revoke(address vault, bytes calldata data) external onlyGuardian(vault) {
        IRevokable(vault).revoke(data);
        emit VaultRevokeForwarded(msg.sender, vault, _selector(data), data);
    }

    /// @notice Sets the supervisor contract as a sentinel on a vault (permissionless).
    /// @param vault The vault to update.
    /// @dev This makes sure the supervisor can revoke submitted operations on behalf of the guardians.
    /// @dev For a `Box` contract, the curator should add the supervisor as guardian manually.
    function setSupervisorAsSentinel(IVaultV2 vault) external {
        require(!vault.isSentinel(address(this)), NoOp());
        vault.setIsSentinel(address(this), true);
    }

    /// @notice Returns vaults with at least one registered guardian.
    function getVaults() external view returns (address[] memory) {
        return _vaults.values();
    }

    /// @notice Returns tracked vaults currently owned by this supervisor.
    function getOwnedVaults() external view returns (address[] memory ownedVaults) {
        ownedVaults = _filterVaultsByOwnership(true);
    }

    /// @notice Returns tracked vaults not currently owned by this supervisor.
    function getNonOwnedVaults() external view returns (address[] memory nonOwnedVaults) {
        nonOwnedVaults = _filterVaultsByOwnership(false);
    }

    /// @notice Returns the guardians registered for a vault.
    /// @param vault The vault to query.
    function getGuardians(address vault) external view returns (address[] memory) {
        return _guardians[vault].values();
    }

    /// @notice Returns whether a vault ownership transfer is currently scheduled.
    /// @param vault The vault to query.
    function isOwnershipChanging(address vault) external view returns (bool) {
        return scheduledNewOwner[vault] != address(0);
    }

    /// @notice Returns whether guardian removal is currently scheduled.
    /// @param vault The vault to query.
    /// @param guardian The guardian to query.
    function isGuardianBeingRemoved(address vault, address guardian) external view returns (bool) {
        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, guardian);
        return executableAt[data] > 0;
    }

    /// @notice Returns whether a vault-like contract is currently supervised by this contract.
    /// @param vault The vault address to query.
    function isVaultSupervised(address vault) external view returns (bool) {
        return _ownerOf(vault) == address(this);
    }

    /// @dev Internal revoke routine when the vault and selector are known.
    function _revokeKnownVault(bytes memory data, address vault, bytes4 selector) internal {
        require(_guardians[vault].contains(msg.sender) || msg.sender == owner, OnlyOwnerOrGuardian());
        require(executableAt[data] != 0, DataNotTimelocked());

        if (selector == this.setOwner.selector) {
            scheduledNewOwner[vault] = address(0);
        }

        executableAt[data] = 0;
        emit TimelockRevoked(msg.sender, vault, selector, data);
    }

    /// @dev Validates and consumes the timelock for the current calldata.
    function timelocked() internal {
        uint256 eta = executableAt[msg.data];
        require(eta != 0, DataNotTimelocked());
        require(block.timestamp >= eta, TimelockNotExpired());
        executableAt[msg.data] = 0;
    }

    /// @dev Returns tracked vaults filtered by ownership status.
    function _filterVaultsByOwnership(bool ownedBySupervisor) internal view returns (address[] memory vaults_) {
        uint256 length = _vaults.length();
        vaults_ = new address[](length);
        uint256 count;

        for (uint256 i; i < length; ++i) {
            address vault = _vaults.at(i);
            bool isOwned = _ownerOf(vault) == address(this);
            if (isOwned == ownedBySupervisor) {
                vaults_[count] = vault;
                ++count;
            }
        }

        assembly {
            mstore(vaults_, count)
        }
    }

    /// @dev Extracts the vault address from a supervisor calldata payload.
    /// @dev Returns address(0) for selectors that do not target a vault.
    /// @param selector Function selector parsed from data.
    /// @param data Full calldata (selector + ABI args) for a supervisor action.
    /// @return v The decoded vault address, or address(0) if data is too short.
    function _extractVaultAddress(bytes4 selector, bytes calldata data) internal pure returns (address v) {
        if (!_selectorUsesVault(selector)) return address(0);
        if (data.length < 36) return address(0);
        v = abi.decode(data[4:36], (address));
    }

    function _selector(bytes calldata data) internal pure returns (bytes4 selector) {
        if (data.length < 4) return bytes4(0);
        assembly {
            selector := calldataload(data.offset)
        }
    }

    /// @dev Returns whether a selector encodes a vault as first argument.
    function _selectorUsesVault(bytes4 selector) internal pure returns (bool) {
        return selector == this.setOwner.selector || selector == this.removeSentinel.selector
            || selector == this.removeGuardian.selector;
    }

    function _ownerOf(address vault) internal view returns (address owner_) {
        (bool success, bytes memory returnData) = vault.staticcall(abi.encodeWithSelector(IVaultV2.owner.selector));
        if (!success || returnData.length < 32) return address(0);
        owner_ = abi.decode(returnData, (address));
    }
}
