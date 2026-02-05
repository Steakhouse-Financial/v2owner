# VaultV2Supervisor

VaultV2Supervisor is an ownership and safety module intended to operate as the privileged controller for one or more Vault V2 instances. It provides:

- A standard owner role that can be transfered and revoke actions on the underlying vaults.
- A guardian role that can revoke sensitive actions before they execute during the timelock.
- A timelocked flow for removing sentinels on the vault, so removals cannot be executed immediately and can be revoked by a guardian while pending.
- Pass-through to call selected `IVaultV2` owner functions (e.g., `setCurator`, `setName`, `setSymbol`).

The contract is at [src/VaultV2Supervisor.sol](src/VaultV2Supervisor.sol).

## Overview

`VaultV2Supervisor` assumes it holds the `owner` privileges on one or more Vault V2 (`IVaultV2`) contracts. Rather than calling the vault directly, operators call the vault via `VaultV2Supervisor`, which adds delay and revocation controls to riskier operations like removing sentinels.
The `VaultV2Supervisor` can also be used as guardian for Box smart contract to enable having more than one guardian for a `Box`. In such case,
only the `revoke(address,bytes)` function is used. Removing the `VaultV2Supervisor` from guardian at the `Box` level (under a timelock) is 
initiared by the `Box` curator but can be revoked by any guardian defined at the `VaultV2Supervisor` fr such a `Box`.

### Roles
- **Owner**: Full admin of `VaultV2Supervisor`. Can perform safe vault admin calls, submit timelocked actions, and execute them after delay.
- **Guardian**: A vault-specific safety role, registered per vault via `addGuardian(vault, guardian)`. Guardians can revoke pending timelocked actions for that vault (issued at the Supervisor or at the Vault level).

### Timelock Model
Supervisor uses a generic timelock keyed by calldata:

1. Owner calls `submit(bytes data)` to schedule any timelocked action. `data` is the full calldata of the target function to be executed later.
2. After `timelock` (14 days), the Owner calls the target function; execution checks `timelocked()` internally to enforce the delay.
3. A guardian of the relevant vault or the Owner can `revoke(bytes data)` to cancel a pending action before it executes.

Default timelock: 14 days (immutable).

## Public API (selected)

Core ownership:
- `owner()` / `pendingOwner()`
- `transferOwnership(address newOwner)` → emits `OwnershipTransferStarted`
- `acceptOwnership()` → finalizes transfer
- `renounceOwnership()` → sets owner to zero
- `setOwner(address newOwner)` → direct owner set (use with care)

Guardians:
- `addGuardian(address vault, address guardian)` → register guardian for a vault
- `removeGuardian(address vault, address guardian)` → timelocked removal of guardian

Sentinel management:
- `addSentinel(IVaultV2 vault, address account)` → immediate add
- `removeSentinel(IVaultV2 vault, address account)` → timelocked removal (requires prior `submit` with matching calldata)

Vault owner helpers (no timelock):
- `setCurator(IVaultV2 vault, address newCurator)`
- `setName(IVaultV2 vault, string newName)`
- `setSymbol(IVaultV2 vault, string newSymbol)`