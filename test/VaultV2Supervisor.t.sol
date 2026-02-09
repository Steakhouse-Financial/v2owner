// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import { IERC20 } from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import { VaultV2Supervisor } from "src/VaultV2Supervisor.sol";
import { IVaultV2 } from "vault-v2/src/interfaces/IVaultV2.sol";
import { VaultV2Factory } from "vault-v2/src/VaultV2Factory.sol";
import { MorphoVaultV1AdapterFactory } from "vault-v2/src/adapters/MorphoVaultV1AdapterFactory.sol";
import { IMorphoVaultV1Adapter } from "vault-v2/src/adapters/interfaces/IMorphoVaultV1Adapter.sol";

import { IBox } from "box/src/interfaces/IBox.sol";
import { BoxFactory } from "box/src/factories/BoxFactory.sol";

import { TestAsset } from "test/helpers/TestAsset.sol";

contract VaultV2SupervisorTest is Test {
    uint256 constant TIMELOCK = 14 days;

    VaultV2Supervisor supervisor;
    VaultV2Factory vaultFactory;
    MorphoVaultV1AdapterFactory adapterFactory;
    BoxFactory boxFactory;

    TestAsset asset;
    IVaultV2 vault;
    IVaultV2 morphoVaultLike;
    IBox box;
    IMorphoVaultV1Adapter mv1Adapter;

    address OWNER = address(this);
    address CURATOR = address(0xC0FFEE);
    address GUARDIAN = address(0xBEEF);
    address SENTINEL = address(0xCAFE);

    function setUp() public {
        supervisor = new VaultV2Supervisor(TIMELOCK);
        vaultFactory = new VaultV2Factory();
        adapterFactory = new MorphoVaultV1AdapterFactory();
        boxFactory = new BoxFactory();
        asset = new TestAsset("Test Asset", "TAST");

        vault = IVaultV2(vaultFactory.createVaultV2(OWNER, address(asset), keccak256("vault-main")));
        morphoVaultLike = IVaultV2(vaultFactory.createVaultV2(OWNER, address(asset), keccak256("vault-mv1-like")));
        mv1Adapter = IMorphoVaultV1Adapter(
            adapterFactory.createMorphoVaultV1Adapter(address(vault), address(morphoVaultLike))
        );
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
        supervisor.addGuardian(address(box), address(0xABCD));

        address[] memory vaults = supervisor.getVaults();
        assertEq(vaults.length, 2);
        assertTrue(_contains(vaults, address(vault)));
        assertTrue(_contains(vaults, address(box)));

        address[] memory ownedVaults = supervisor.getOwnedVaults();
        assertEq(ownedVaults.length, 1);
        assertEq(ownedVaults[0], address(vault));

        address[] memory nonOwnedVaults = supervisor.getNonOwnedVaults();
        assertEq(nonOwnedVaults.length, 1);
        assertEq(nonOwnedVaults[0], address(box));
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

    function test_Timelocked_RemoveSentinel_Flow() public {
        supervisor.addSentinel(vault, SENTINEL);
        assertTrue(vault.isSentinel(SENTINEL));

        bytes memory data = abi.encodeWithSelector(VaultV2Supervisor.removeSentinel.selector, vault, SENTINEL);
        supervisor.submit(data);

        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.removeSentinel(vault, SENTINEL);

        vm.warp(block.timestamp + TIMELOCK + 1);
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
        assertEq(supervisor.scheduledNewOwner(address(vault)), newOwner);

        vm.expectRevert(VaultV2Supervisor.TimelockNotExpired.selector);
        supervisor.setOwner(vault, newOwner);

        vm.warp(block.timestamp + TIMELOCK + 1);
        supervisor.setOwner(vault, newOwner);
        assertEq(vault.owner(), newOwner);
        assertEq(supervisor.scheduledNewOwner(address(vault)), address(0));
    }

    function test_Submit_SetOwner_RevertsIfOwnershipAlreadyScheduled() public {
        bytes memory first = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x111));
        bytes memory second = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x222));

        supervisor.submit(first);

        vm.expectRevert(VaultV2Supervisor.OwnershipChangeAlreadyScheduled.selector);
        supervisor.submit(second);
    }

    function test_Revoke_ClearsScheduledVaultOwner() public {
        bytes memory data = abi.encodeWithSignature("setOwner(address,address)", address(vault), address(0x999));

        supervisor.submit(data);
        assertEq(supervisor.scheduledNewOwner(address(vault)), address(0x999));

        supervisor.revoke(data);
        assertEq(supervisor.scheduledNewOwner(address(vault)), address(0));
    }

    function test_SubmitAndRevoke_SetSupervisorOwnerScheduling() public {
        bytes memory first = abi.encodeWithSelector(VaultV2Supervisor.setSupervisorOwner.selector, address(0x111));
        bytes memory second = abi.encodeWithSelector(VaultV2Supervisor.setSupervisorOwner.selector, address(0x222));

        assertFalse(supervisor.isSupervisorOwnershipChanging());

        supervisor.submit(first);
        assertEq(supervisor.scheduledSupervisorOwner(), address(0x111));
        assertTrue(supervisor.isSupervisorOwnershipChanging());

        vm.expectRevert(VaultV2Supervisor.OwnershipChangeAlreadyScheduled.selector);
        supervisor.submit(second);

        supervisor.revoke(first);
        assertEq(supervisor.scheduledSupervisorOwner(), address(0));
        assertFalse(supervisor.isSupervisorOwnershipChanging());
    }

    function test_IsVaultSupervised() public view {
        assertTrue(supervisor.isVaultSupervised(address(vault)));
        assertFalse(supervisor.isVaultSupervised(address(box)));
        assertFalse(supervisor.isVaultSupervised(address(0xB0B)));
    }

    function _contains(address[] memory list, address account) internal pure returns (bool) {
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == account) return true;
        }
        return false;
    }
}
