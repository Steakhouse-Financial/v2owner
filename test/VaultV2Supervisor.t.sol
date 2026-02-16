// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import "forge-std/Test.sol";

import {VaultV2Supervisor} from "src/VaultV2Supervisor.sol";
import {IVaultV2} from "vault-v2/src/interfaces/IVaultV2.sol";
import {VaultV2Factory} from "vault-v2/src/VaultV2Factory.sol";
import {IMorphoVaultV1Adapter} from "vault-v2/src/adapters/interfaces/IMorphoVaultV1Adapter.sol";
import {MorphoVaultV1AdapterFactory} from "vault-v2/src/adapters/MorphoVaultV1AdapterFactory.sol";

import {TestAsset} from "test/helpers/TestAsset.sol";

contract VaultV2SupervisorTest is Test {
    uint256 constant TIMELOCK = 14 days;

    VaultV2Supervisor supervisor;
    VaultV2Factory vaultFactory;
    MorphoVaultV1AdapterFactory adapterFactory;

    TestAsset asset;
    IVaultV2 vault;
    IVaultV2 nonOwnedVault;
    IVaultV2 morphoVaultLike;
    IMorphoVaultV1Adapter mv1Adapter;

    address OWNER = address(this);
    address CURATOR = address(0xC0FFEE);
    address GUARDIAN = address(0xBEEF);
    address SENTINEL = address(0xCAFE);

    function setUp() public {
        supervisor = new VaultV2Supervisor(TIMELOCK);
        vaultFactory = new VaultV2Factory();
        adapterFactory = new MorphoVaultV1AdapterFactory();
        asset = new TestAsset("Test Asset", "TAST");

        vault = IVaultV2(vaultFactory.createVaultV2(OWNER, address(asset), keccak256("vault-main")));
        nonOwnedVault =
            IVaultV2(vaultFactory.createVaultV2(address(0xA11CE), address(asset), keccak256("vault-non-owned")));
        morphoVaultLike = IVaultV2(vaultFactory.createVaultV2(OWNER, address(asset), keccak256("vault-mv1-like")));
        mv1Adapter =
            IMorphoVaultV1Adapter(adapterFactory.createMorphoVaultV1Adapter(address(vault), address(morphoVaultLike)));

        vault.setOwner(address(supervisor));
        supervisor.setCurator(vault, CURATOR);
        supervisor.setSupervisorAsSentinel(vault);
        supervisor.setAllowedVaultOwner(OWNER, true);
    }

    function test_Constructor_RevertsOnZeroTimelock() public {
        vm.expectRevert(VaultV2Supervisor.InvalidTimelock.selector);
        new VaultV2Supervisor(0);
    }

    function test_SetCurator_Name_Symbol() public {
        supervisor.setCurator(vault, address(0x01));
        assertEq(vault.curator(), address(0x01));

        supervisor.setName(vault, "TestVault");
        assertEq(vault.name(), "TestVault");

        supervisor.setSymbol(vault, "TVLT");
        assertEq(vault.symbol(), "TVLT");
    }

    function test_SetCurator_Name_Symbol_RevertOnNoOp() public {
        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.setCurator(vault, CURATOR);

        supervisor.setName(vault, "TestVault");
        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.setName(vault, "TestVault");

        supervisor.setSymbol(vault, "TVLT");
        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.setSymbol(vault, "TVLT");
    }

    function test_SetSkimRecipient_ForwardsToTarget() public {
        address recipient = address(0xD00D);

        supervisor.setSkimRecipient(address(mv1Adapter), recipient);

        assertEq(mv1Adapter.skimRecipient(), recipient);
    }

    function test_SetSkimRecipient_RevertsForNonSupervisorOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(VaultV2Supervisor.NotOwner.selector);
        supervisor.setSkimRecipient(address(mv1Adapter), address(0xD00D));
    }

    function test_SetAllowedVaultOwner_RevertsOnZeroAddressAndNoOp() public {
        vm.expectRevert(VaultV2Supervisor.ZeroAddress.selector);
        supervisor.setAllowedVaultOwner(address(0), true);

        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.setAllowedVaultOwner(OWNER, true);

        supervisor.setAllowedVaultOwner(OWNER, false);

        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.setAllowedVaultOwner(OWNER, false);
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

    function test_GetVaults_AndOwnedBuckets() public {
        supervisor.addGuardian(address(vault), GUARDIAN);
        supervisor.addGuardian(address(nonOwnedVault), address(0xABCD));

        address[] memory vaults = supervisor.getVaults();
        assertEq(vaults.length, 2);
        assertTrue(_contains(vaults, address(vault)));
        assertTrue(_contains(vaults, address(nonOwnedVault)));

        address[] memory ownedVaults = supervisor.getOwnedVaults();
        assertEq(ownedVaults.length, 1);
        assertEq(ownedVaults[0], address(vault));

        address[] memory nonOwnedVaults = supervisor.getNonOwnedVaults();
        assertEq(nonOwnedVaults.length, 1);
        assertEq(nonOwnedVaults[0], address(nonOwnedVault));
    }

    function test_RemoveGuardian_RemovesVaultFromTrackedSetWhenEmpty() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        supervisor.submit(data);

        vm.warp(block.timestamp + TIMELOCK + 1);
        supervisor.removeGuardian(vault, GUARDIAN);

        assertEq(supervisor.getGuardians(address(vault)).length, 0);
        assertEq(supervisor.getVaults().length, 0);
    }

    function test_GetOwnedAndNonOwnedVaults_WhenTrackedSetEmpty() public view {
        assertEq(supervisor.getVaults().length, 0);
        assertEq(supervisor.getOwnedVaults().length, 0);
        assertEq(supervisor.getNonOwnedVaults().length, 0);
    }

    function test_RemoveGuardian_KeepsVaultTrackedWhenGuardiansRemain() public {
        address guardian2 = address(0xBEE2);

        supervisor.addGuardian(address(vault), GUARDIAN);
        supervisor.addGuardian(address(vault), guardian2);

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        supervisor.submit(data);

        vm.warp(block.timestamp + TIMELOCK + 1);
        supervisor.removeGuardian(vault, GUARDIAN);

        address[] memory guardians = supervisor.getGuardians(address(vault));
        assertEq(guardians.length, 1);
        assertEq(guardians[0], guardian2);

        address[] memory vaults = supervisor.getVaults();
        assertEq(vaults.length, 1);
        assertEq(vaults[0], address(vault));
    }

    function test_RemoveSentinel_Flow() public {
        supervisor.addSentinel(vault, SENTINEL);
        assertTrue(vault.isSentinel(SENTINEL));

        supervisor.removeSentinel(vault, SENTINEL);
        assertFalse(vault.isSentinel(SENTINEL));
    }

    function test_RemoveSentinel_RevertsWhenTryingToRemoveSupervisor() public {
        vm.expectRevert(VaultV2Supervisor.CannotRemoveSupervisorSentinel.selector);
        supervisor.removeSentinel(vault, address(supervisor));
    }

    function test_RemoveSentinel_RevertsForNonOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(VaultV2Supervisor.NotOwner.selector);
        supervisor.removeSentinel(vault, SENTINEL);
    }

    function test_RevokeGuardianRemoval_CancelsSupervisorTimelock() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        supervisor.submit(data);

        vm.prank(GUARDIAN);
        supervisor.revokeGuardianRemoval(vault, GUARDIAN);

        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.removeGuardian(vault, GUARDIAN);
    }

    function test_Revoke_RevertsWhenUnauthorized() public {
        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        supervisor.submit(data);

        vm.prank(address(0xBAD));
        vm.expectRevert(VaultV2Supervisor.OnlyOwnerOrGuardian.selector);
        supervisor.revoke(data);
    }

    function test_Revoke_RevertsWhenDataNotTimelocked() public {
        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);

        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.revoke(data);
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

    function test_GuardianRevokeForwarder_RevertsForNonGuardian() public {
        bytes memory vdata = abi.encodeCall(IVaultV2.setIsAllocator, (address(0x1234), true));

        vm.prank(address(0xBAD));
        vm.expectRevert(VaultV2Supervisor.NotGuardian.selector);
        supervisor.revoke(address(vault), vdata);
    }

    function test_Timelocked_SetOwner() public {
        address newOwner = address(0x999);
        bytes memory data = abi.encodeWithSignature("setOwner(address,address)", address(vault), newOwner);
        supervisor.submit(data);
        assertEq(supervisor.scheduledNewOwner(address(vault)), newOwner);

        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.setOwner(vault, newOwner);

        vm.warp(block.timestamp + TIMELOCK + 1);
        supervisor.setOwner(vault, newOwner);
        assertFalse(supervisor.isOwnershipChanging(address(vault)));
        assertEq(vault.owner(), newOwner);
        assertEq(supervisor.scheduledNewOwner(address(vault)), address(0));
    }

    function test_SetOwner_RevertsWhenNotTimelocked() public {
        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.setOwner(vault, address(0x999));
    }

    function test_Submit_RevertsOnInvalidDataAndDuplicateSubmission() public {
        vm.expectRevert(VaultV2Supervisor.InvalidAmount.selector);
        supervisor.submit(hex"123456");

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        supervisor.submit(data);

        vm.expectRevert(VaultV2Supervisor.DataAlreadyTimelocked.selector);
        supervisor.submit(data);
    }

    function test_Submit_SetOwner_RevertsOnZeroAddressOrNoOpOwner() public {
        bytes memory zeroVault = abi.encodeWithSignature("setOwner(address,address)", address(0), address(0x111));
        vm.expectRevert(VaultV2Supervisor.ZeroAddress.selector);
        supervisor.submit(zeroVault);

        bytes memory zeroOwner = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0));
        vm.expectRevert(VaultV2Supervisor.ZeroAddress.selector);
        supervisor.submit(zeroOwner);

        bytes memory noOp = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(supervisor));
        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.submit(noOp);
    }

    function test_Submit_SetOwner_RevertsIfOwnershipAlreadyScheduled() public {
        bytes memory first = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x111));
        bytes memory second = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x222));

        supervisor.submit(first);

        vm.expectRevert(VaultV2Supervisor.OwnershipChangeAlreadyScheduled.selector);
        supervisor.submit(second);
    }

    function test_Submit_SetOwner_RevertsOnTrailingOrDirtyBytes() public {
        bytes memory canonical = abi.encodeWithSelector(VaultV2Supervisor.setOwner.selector, vault, address(0x999));
        bytes memory trailing = abi.encodePacked(canonical, hex"11");

        vm.expectRevert(VaultV2Supervisor.InvalidAmount.selector);
        supervisor.submit(trailing);

        bytes32 dirtyVaultWord = bytes32(uint256(uint160(address(vault))) | (uint256(1) << 200));
        bytes memory dirty = abi.encodePacked(
            VaultV2Supervisor.setOwner.selector, dirtyVaultWord, bytes32(uint256(uint160(address(0x999))))
        );

        vm.expectRevert(VaultV2Supervisor.InvalidAmount.selector);
        supervisor.submit(dirty);

        assertFalse(supervisor.isOwnershipChanging(address(vault)));
    }

    function test_Submit_RemoveGuardian_RevertsOnTrailingOrDirtyBytes() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        bytes memory canonical = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        bytes memory trailing = abi.encodePacked(canonical, hex"11");

        vm.expectRevert(VaultV2Supervisor.InvalidAmount.selector);
        supervisor.submit(trailing);

        bytes32 dirtyGuardianWord = bytes32(uint256(uint160(GUARDIAN)) | (uint256(1) << 200));
        bytes memory dirty = abi.encodePacked(
            VaultV2Supervisor.removeGuardian.selector, bytes32(uint256(uint160(address(vault)))), dirtyGuardianWord
        );

        vm.expectRevert(VaultV2Supervisor.InvalidAmount.selector);
        supervisor.submit(dirty);

        assertFalse(supervisor.isGuardianBeingRemoved(address(vault), GUARDIAN));
    }

    function test_RevokeVaultOwnerChange_ClearsScheduledVaultOwner() public {
        bytes memory data = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x999));

        supervisor.submit(data);
        assertEq(supervisor.scheduledNewOwner(address(vault)), address(0x999));

        supervisor.revokeVaultOwnerChange(vault);
        assertEq(supervisor.scheduledNewOwner(address(vault)), address(0));
    }

    function test_RevokeVaultOwnerChange_RevertsWhenNotPending() public {
        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.revokeVaultOwnerChange(vault);
    }

    function test_TransferSupervisorOwnership_StartsTransfer() public {
        supervisor.transferSupervisorOwnership(address(0x111));

        assertEq(supervisor.owner(), OWNER);
        assertEq(supervisor.pendingSupervisorOwner(), address(0x111));
    }

    function test_TransferSupervisorOwnership_RevertsForNonOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(VaultV2Supervisor.NotOwner.selector);
        supervisor.transferSupervisorOwnership(address(0x111));
    }

    function test_TransferSupervisorOwnership_RevertsOnZeroAddressAndNoOp() public {
        vm.expectRevert(VaultV2Supervisor.ZeroAddress.selector);
        supervisor.transferSupervisorOwnership(address(0));

        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.transferSupervisorOwnership(OWNER);

        supervisor.transferSupervisorOwnership(address(0x111));
        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.transferSupervisorOwnership(address(0x111));
    }

    function test_AcceptSupervisorOwnership_FinalizesTransfer() public {
        supervisor.transferSupervisorOwnership(address(0x111));

        vm.prank(address(0x111));
        supervisor.acceptSupervisorOwnership();

        assertEq(supervisor.owner(), address(0x111));
        assertEq(supervisor.pendingSupervisorOwner(), address(0));
    }

    function test_AcceptSupervisorOwnership_RevertsForNonPendingOwner() public {
        supervisor.transferSupervisorOwnership(address(0x111));

        vm.prank(address(0x222));
        vm.expectRevert(VaultV2Supervisor.NotPendingSupervisorOwner.selector);
        supervisor.acceptSupervisorOwnership();
    }

    function test_AddGuardian_RevertsOnNoOpOrZeroAddress() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.addGuardian(address(vault), GUARDIAN);

        vm.expectRevert(VaultV2Supervisor.ZeroAddress.selector);
        supervisor.addGuardian(address(0), GUARDIAN);

        vm.expectRevert(VaultV2Supervisor.ZeroAddress.selector);
        supervisor.addGuardian(address(vault), address(0));
    }

    function test_RemoveGuardian_RevertsWhenGuardianNotRegistered() public {
        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        supervisor.submit(data);

        vm.warp(block.timestamp + TIMELOCK + 1);

        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.removeGuardian(vault, GUARDIAN);
    }

    function test_RemoveGuardian_RevertsWhenNotTimelocked() public {
        vm.expectRevert(VaultV2Supervisor.DataNotTimelocked.selector);
        supervisor.removeGuardian(vault, GUARDIAN);
    }

    function test_SetSupervisorAsSentinel_RevertsOnNoOp() public {
        vm.expectRevert(VaultV2Supervisor.NoOp.selector);
        supervisor.setSupervisorAsSentinel(vault);
    }

    function test_IsOwnershipChanging_View() public {
        bytes memory ownerData = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x999));
        assertFalse(supervisor.isOwnershipChanging(address(vault)));
        supervisor.submit(ownerData);
        assertTrue(supervisor.isOwnershipChanging(address(vault)));
        supervisor.revoke(ownerData);
        assertFalse(supervisor.isOwnershipChanging(address(vault)));
    }

    function test_IsGuardianBeingRemoved_View() public {
        supervisor.addGuardian(address(vault), GUARDIAN);

        bytes memory removeGuardianData =
            abi.encodeWithSelector(VaultV2Supervisor.removeGuardian.selector, vault, GUARDIAN);
        assertFalse(supervisor.isGuardianBeingRemoved(address(vault), GUARDIAN));
        supervisor.submit(removeGuardianData);
        assertTrue(supervisor.isGuardianBeingRemoved(address(vault), GUARDIAN));
        supervisor.revoke(removeGuardianData);
        assertFalse(supervisor.isGuardianBeingRemoved(address(vault), GUARDIAN));
    }

    function test_IsVaultSupervised() public view {
        assertTrue(supervisor.isVaultSupervised(address(vault)));
        assertFalse(supervisor.isVaultSupervised(address(nonOwnedVault)));
        assertFalse(supervisor.isVaultSupervised(address(0xB0B)));
    }

    function _contains(address[] memory list, address account) internal pure returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == account) return true;
        }
        return false;
    }
}
