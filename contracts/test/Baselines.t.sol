// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {FullLog, Gated, HashLog, MerkleLog, SequencedLog} from "../src/Baselines.sol";
import {Registry} from "../src/Registry.sol";

/// @notice Functional checks for the baseline archetypes. Gas per call comes from `forge test --gas-report`
///         (steady state: a fresh slot per event/batch, as in a long-running deployment).
contract BaselinesTest is Test {
    address gw = address(0xBEEF);
    FullLog b1;
    HashLog b2;
    MerkleLog b3;
    SequencedLog b4;
    Registry reg;

    function setUp() public {
        b1 = new FullLog();
        b2 = new HashLog();
        b3 = new MerkleLog();
        b4 = new SequencedLog();
        reg = new Registry(300);
        b1.registerGateway(gw);
        b2.registerGateway(gw);
        b3.registerGateway(gw);
        b4.registerGateway(gw);
        reg.registerGateway(gw);
    }

    function test_B1_storesRecord() public {
        int256[] memory f = new int256[](3);
        f[0] = 1050;
        vm.prank(gw);
        // representative HAI payload: "P1_FT01Z,12345,1234.567890" (26 bytes)
        b1.logEvent(7, 1, 1_700_000_000, f, bytes("P1_FT01Z,12345,1234.567890"));
        (uint64 ts,,) = b1.records(7, 1);
        assertEq(ts, 1_700_000_000);
    }

    function test_B2_anchorsHash() public {
        vm.prank(gw);
        b2.anchorHash(keccak256("e"));
        assertEq(b2.anchoredAt(keccak256("e")), block.timestamp);
    }

    function test_B3_sameShapeAsRegistryAnchor() public {
        vm.startPrank(gw);
        b3.anchor(keccak256("r"));
        reg.anchor(keccak256("r"));
        vm.stopPrank();
        assertEq(b3.anchoredAt(gw, keccak256("r")), reg.anchoredAt(gw, keccak256("r")));
    }

    function test_B4_rejectsGap() public {
        vm.startPrank(gw);
        b4.append(1, keccak256("a"));
        vm.expectRevert(SequencedLog.BadSeq.selector);
        b4.append(3, keccak256("b"));
        vm.stopPrank();
    }

    function test_onlyGateway() public {
        vm.expectRevert(Gated.NotGateway.selector);
        b3.anchor(keccak256("x"));
    }
}
