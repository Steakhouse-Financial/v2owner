// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { VaultV2Supervisor } from "src/VaultV2Supervisor.sol";
import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";
import { VaultV2Factory } from "vault-v2/src/VaultV2Factory.sol";

import { IBox } from "box/src/interfaces/IBox.sol";
import { BoxFactory } from "box/src/factories/BoxFactory.sol";

import { TestAsset } from "test/helpers/TestAsset.sol";

contract VaultV2SupervisorTest is Test {
    VaultV2Supervisor supervisor;
    VaultV2Factory vaultFactory;
    BoxFactory boxFactory;

    TestAsset asset;
    IVaultV2 vault;
    IBox box;

    address OWNER = address(this);
    address CURATOR = address(0xC0FFEE);
    address GUARDIAN = address(0xBEEF);
    address SENTINEL = address(0xCAFE);

    function setUp() public {
        supervisor = new VaultV2Supervisor();
        vaultFactory = new VaultV2Factory();
        boxFactory = new BoxFactory();
        asset = new TestAsset("Test Asset", "TAST");

        vault = IVaultV2(vaultFactory.createVaultV2(OWNER, address(asset), keccak256("vault-main")));
        box = boxFactory.createBox(
            IERC20(address(asset)),
            OWNER,
            OWNER,
            "Test Box",
            "TBOX",
            0.005 ether,
            1 days,
            7 days,
            1 days,
            keccak256("box-main")
        );

        vault.setOwner(address(supervisor));
        supervisor.setCurator(vault, CURATOR);
        supervisor.setSupervisorAsSentinel(vault);
        bytes memory guardianData = abi.encodeCall(IBox.setGuardian, (address(supervisor)));
        box.submit(guardianData);
        box.setGuardian(address(supervisor));
        supervisor.setAllowedVaultOwner(OWNER, true);
    }

    function test_SetCurator_Name_Symbol() public {
        supervisor.setCurator(vault, address(0x01));
        assertEq(vault.curator(), address(0x01));

        supervisor.setName(vault, "TestVault");
        assertEq(vault.name(), "TestVault");

        supervisor.setSymbol(vault, "TVLT");
        assertEq(vault.symbol(), "TVLT");
    }

    function test_AddGuardian_byOwner_and_VaultOwner() public {
        supervisor.addGuardian(address(vault), GUARDIAN);
        assertEq(supervisor.getGuardians(address(vault))[0], GUARDIAN);

        address vaultOwner = address(0xA11CE);
        IVaultV2 otherVault = IVaultV2(vaultFactory.createVaultV2(vaultOwner, address(asset), keccak256("vault-other")));
        supervisor.setAllowedVaultOwner(vaultOwner, true);

        vm.prank(vaultOwner);
        supervisor.addGuardian(address(otherVault), address(0xA11CE));
        assertEq(supervisor.getGuardians(address(otherVault))[0], address(0xA11CE));
    }

    function test_AddGuardian_RevertsWhenVaultOwnerNotAllowed() public {
        address disallowedOwner = address(0xB0B);
        IVaultV2 disallowedVault =
            IVaultV2(vaultFactory.createVaultV2(disallowedOwner, address(asset), keccak256("vault-disallowed")));

        vm.prank(disallowedOwner);
        vm.expectRevert(VaultV2Supervisor.OnlyOwnerOrVaultOwner.selector);
        supervisor.addGuardian(address(disallowedVault), GUARDIAN);
    }

    function test_Timelocked_RemoveSentinel_Flow() public {
        supervisor.addSentinel(vault, SENTINEL);
        assertTrue(vault.isSentinel(SENTINEL));

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeSentinel.selector, vault, SENTINEL);
        supervisor.submit(data);

        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.removeSentinel(vault, SENTINEL);

        vm.warp(block.timestamp + 14 days + 1);
        supervisor.removeSentinel(vault, SENTINEL);
        assertFalse(vault.isSentinel(SENTINEL));
    }

    function test_RevokeByGuardian_CancelsSupervisorTimelock() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeSentinel.selector, vault, SENTINEL);
        supervisor.submit(data);

        vm.prank(GUARDIAN);
        supervisor.revoke(data);

        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.removeSentinel(vault, SENTINEL);
    }

    function test_GuardianCanRevokeVaultTimelock() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        bytes memory vdata = abi.encodeCall(IVaultV2.setIsAllocator, (address(0x1234), true));
        vm.prank(CURATOR);
        vault.submit(vdata);
        assertGt(vault.executableAt(vdata), 0);

        vm.prank(GUARDIAN);
        supervisor.revoke(address(vault), vdata);
        assertEq(vault.executableAt(vdata), 0);
    }

    function test_GuardianCanRevokeBoxTimelock() public {
        supervisor.addGuardian(address(box), GUARDIAN);

        bytes memory bdata = abi.encodeCall(IBox.setIsFeeder, (address(0x1234), true));
        box.submit(bdata);
        assertGt(box.executableAt(bdata), 0);

        vm.prank(GUARDIAN);
        supervisor.revoke(address(box), bdata);
        assertEq(box.executableAt(bdata), 0);
    }

    function test_Timelocked_SetOwner() public {
        address newOwner = address(0x999);
        bytes memory data = abi.encodeWithSignature("setOwner(address,address)", address(vault), newOwner);
        supervisor.submit(data);

        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.setOwner(vault, newOwner);

        vm.warp(block.timestamp + 14 days + 1);
        supervisor.setOwner(vault, newOwner);
        assertEq(vault.owner(), newOwner);
    }
}
