# VaultV2Supervisor

VaultV2Supervisor is an ownership and safety module designed to operate as the privileged controller for one or more Vault V2 instances. It provides:

- **Two-step supervisor ownership transfer** with proposal and acceptance
- **Per-vault guardian registration** with allowlisting for vault owners to manage their own guardians
- **Generic timelock system** for sensitive operations with guardian revocation capabilities
- **Vault tracking and filtering** to monitor supervised and non-supervised vaults
- **Pass-through functions** for immediate vault operations (curator, name, symbol, sentinels)
- **Guardian proxy functionality** to act as a multi-guardian for Box contracts

The contract is at [src/VaultV2Supervisor.sol](src/VaultV2Supervisor.sol).

## Overview

`VaultV2Supervisor` is designed to own one or more Vault V2 (`IVaultV2`) contracts and add governance controls to sensitive operations. Rather than calling vault functions directly, operators interact with the vault through the supervisor, which enforces delays and guardian oversight for critical actions.

The supervisor can also serve as a guardian for Box contracts, enabling multi-guardian setups where any registered guardian can revoke pending Box operations.

### Roles

- **Supervisor Owner**: Controls the supervisor contract itself. Can perform vault admin calls, submit timelocked actions, execute them after delay, and manage guardians.
- **Pending Supervisor Owner**: Proposed new owner who must accept to complete ownership transfer.
- **Guardian**: Vault-specific safety role registered per vault. Guardians can revoke pending timelocked actions for their assigned vault(s).
- **Allowed Vault Owner**: Vault owners who have been allowlisted to register guardians for their own vaults.

### Timelock System

The supervisor uses a configurable timelock (set at deployment) for sensitive operations:

1. **Submit**: Owner calls `submit(bytes data)` to schedule a timelocked action. The full calldata is stored with an execution timestamp.
2. **Delay**: Actions cannot be executed until the timelock period has passed.
3. **Revoke**: Guardians of the target vault (or the supervisor owner) can call `revoke(bytes data)` to cancel pending actions.
4. **Execute**: After the timelock expires, the owner calls the original function, which validates the timelock internally.

Timelocked actions include:
- Vault ownership transfers (`setOwner`)
- Guardian removal (`removeGuardian`)

The timelock duration is immutable and set during deployment.

## Public API

### Deployment

- `constructor(uint256 timelock_)` → Deploy supervisor with custom timelock duration

### Supervisor Ownership

- `owner()` → Current supervisor owner
- `pendingSupervisorOwner()` → Pending owner waiting to accept
- `transferSupervisorOwnership(address newOwner)` → Propose new supervisor owner
- `acceptSupervisorOwnership()` → Accept pending ownership transfer

### Guardian Management

- `setAllowedVaultOwner(address vaultOwner, bool allowed)` → Allow/disallow vault owner to manage guardians (in addition to the supervisor)
- `addGuardian(address vault, address guardian)` → Add guardian for a vault (by supervisor owner or allowlisted vault owner)
- `getGuardians(address vault)` → List all guardians for a vault
- `removeGuardian(IVaultV2 vault, address guardian)` → **Timelocked** guardian removal

### Vault Discovery

- `getVaults()` → All vaults with at least one registered guardian
- `getOwnedVaults()` → Tracked vaults currently owned by this supervisor
- `getNonOwnedVaults()` → Tracked vaults not currently owned by this supervisor
- `isVaultSupervised(address vault)` → Check if vault is owned by this supervisor

### Timelock Operations

- `submit(bytes data)` → Schedule a timelocked action for later execution
- `revoke(bytes data)` → Cancel pending supervisor action (by guardian or owner)
- `revokeGuardianRemoval(IVaultV2 vault, address guardian)` → Cancel pending guardian removal
- `revokeVaultOwnerChange(IVaultV2 vault)` → Cancel pending vault ownership transfer
- `revoke(address vault, bytes data)` → Forward revoke to vault's own timelock (guardian-only)

### Immediate Vault Operations (No Timelock)

- `setCurator(IVaultV2 vault, address newCurator)` → Set vault curator
- `setName(IVaultV2 vault, string newName)` → Set vault name
- `setSymbol(IVaultV2 vault, string newSymbol)` → Set vault symbol  
- `addSentinel(IVaultV2 vault, address account)` → Add sentinel to vault
- `removeSentinel(IVaultV2 vault, address sentinel)` → Remove sentinel from vault (cannot remove supervisor itself)
- `setSkimRecipient(address skimable, address newSkimRecipient)` → Set skim recipient on adapter
- `setSupervisorAsSentinel(IVaultV2 vault)` → Add supervisor as sentinel (permissionless)

### Timelocked Vault Operations

- `setOwner(IVaultV2 vault, address newOwner)` → **Timelocked** vault ownership transfer

### Status Queries

- `scheduledNewOwner(address vault)` → Pending new owner for vault (if any)
- `isOwnershipChanging(address vault)` → Whether vault ownership transfer is scheduled
- `isGuardianBeingRemoved(address vault, address guardian)` → Whether guardian removal is scheduled
- `executableAt(bytes data)` → Execution timestamp for submitted calldata (0 if not submitted)


## Security Notes

- Timelock duration is immutable and set at deployment
- Supervisor cannot remove itself as a sentinel (prevents lockout)
- Guardian removal requires timelock to prevent hostile takeovers
- Vault ownership changes are tracked to prevent multiple pending transfers
- Two-step supervisor ownership prevents accidental transfers to wrong addresses