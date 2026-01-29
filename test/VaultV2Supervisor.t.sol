// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import { VaultV2Supervisor } from "src/VaultV2Supervisor.sol";
import { MockVaultV2 } from "test/mocks/MockVaultV2.sol";
import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";

contract VaultV2SupervisorTest is Test {
    VaultV2Supervisor supervisor;
    MockVaultV2 vault;
    address OWNER = address(this);
    address GUARDIAN = address(0xBEEF);
    address SENTINEL = address(0xCAFE);

    function setUp() public {
        supervisor = new VaultV2Supervisor();
        vault = new MockVaultV2(OWNER);
    }

    function test_SetCurator_Name_Symbol() public {
        // Only owner can call
        supervisor.setCurator(IVaultV2(address(vault)), address(0x01));
        assertEq(vault.curator(), address(0x01));

        supervisor.setName(IVaultV2(address(vault)), "TestVault");
        assertEq(vault.name(), "TestVault");

        supervisor.setSymbol(IVaultV2(address(vault)), "TVLT");
        assertEq(vault.symbol(), "TVLT");
    }

    function test_AddGuardian_byOwner_and_VaultOwner() public {
        // Owner adds guardian
        supervisor.addGuardian(IVaultV2(address(vault)), GUARDIAN);
        // Simulate vault owner adding guardian
        vm.prank(OWNER);
        supervisor.addGuardian(IVaultV2(address(vault)), address(0xA11CE));
        // No direct getter; rely on permission checks via revoke(bytes)
        bytes memory data = abi.encodeWithSelector(
            VaultV2Supervisor.removeSentinel.selector,
            IVaultV2(address(vault)),
            SENTINEL
        );
        // Owner can revoke
        supervisor.submit(data);
        supervisor.revoke(data);
        // After revoke, execution should fail: DataNotTimelocked
        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.removeSentinel(IVaultV2(address(vault)), SENTINEL);
    }

    function test_Timelocked_RemoveSentinel_Flow() public {
        // Add sentinel immediately
        supervisor.addSentinel(IVaultV2(address(vault)), SENTINEL);
        assertTrue(vault.isSentinel(SENTINEL));

        // Schedule removal via submit(bytes)
        bytes memory data = abi.encodeWithSelector(
            VaultV2Supervisor.removeSentinel.selector,
            IVaultV2(address(vault)),
            SENTINEL
        );
        supervisor.submit(data);

        // Before timelock expiry, execution reverts
        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.removeSentinel(IVaultV2(address(vault)), SENTINEL);

        // Advance time beyond timelock (14 days)
        vm.warp(block.timestamp + 14 days + 1);
        supervisor.removeSentinel(IVaultV2(address(vault)), SENTINEL);
        assertFalse(vault.isSentinel(SENTINEL));
    }

    function test_RevokeByGuardian_CancelsSupervisorTimelock() public {
        // Register guardian for this vault
        supervisor.addGuardian(IVaultV2(address(vault)), GUARDIAN);

        bytes memory data = abi.encodeWithSelector(
            VaultV2Supervisor.removeSentinel.selector,
            IVaultV2(address(vault)),
            SENTINEL
        );
        supervisor.submit(data);

        // Guardian revokes pending action
        vm.prank(GUARDIAN);
        supervisor.revoke(data);

        // Now execution fails due to no timelock
        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.removeSentinel(IVaultV2(address(vault)), SENTINEL);
    }

    function test_GuardianCanRevokeVaultTimelock() public {
        // Register guardian
        supervisor.addGuardian(IVaultV2(address(vault)), GUARDIAN);

        // Guardian calls supervisor.revoke(vault, data) which proxies to vault.revoke(data)
        bytes memory vdata = abi.encodeWithSelector(bytes4(0xDEADBEEF), uint256(123));
        vm.prank(GUARDIAN);
        supervisor.revoke(IVaultV2(address(vault)), vdata);
        assertEq(vault.lastRevokeData(), vdata);
    }

    function test_Timelocked_SetOwner() public {
        address newOwner = address(0x999);
        bytes memory data = abi.encodeWithSignature(
            "setOwner(address,address)",
            address(vault),
            newOwner
        );
        supervisor.submit(data);

        // Not executable before timelock
        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.setOwner(IVaultV2(address(vault)), newOwner);

        vm.warp(block.timestamp + 14 days + 1);
        supervisor.setOwner(IVaultV2(address(vault)), newOwner);
        assertEq(vault.owner(), newOwner);
    }

}
