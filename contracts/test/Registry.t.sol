// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Registry} from "../src/Registry.sol";

/// Tests are organised by the attack taxonomy of the paper (A1-A7) plus the
/// non-frameability property of Definition 3.
contract RegistryTest is Test {
    Registry reg;

    uint64 constant WINDOW = 20;
    uint64 constant DEV = 7;
    uint64 constant OTHER_DEV = 8;

    uint256 gwKey = 0xA11CE;
    uint256 devKey = 0xB0B;
    uint256 otherDevKey = 0xCAFE;
    address gw;

    // device chain for DEV
    Registry.EventHeader[] evs;
    bytes32[] evHashes; // evHashes[i] = hash of event with counter i+1
    bytes32[] heads; // heads[c] = H_c, heads[0] = 0

    function setUp() public {
        gw = vm.addr(gwKey);
        reg = new Registry(WINDOW);
        reg.registerGateway(gw);
        reg.registerDevice(DEV, vm.addr(devKey), gw);
        reg.registerDevice(OTHER_DEV, vm.addr(otherDevKey), gw);

        // Policy v0 (active from now): feature[0] is an alarm flag; alarm == 1 => FULL.
        Registry.Rule[] memory rules = new Registry.Rule[](1);
        rules[0] = Registry.Rule(0, Registry.Op.EQ, 1);
        reg.setPolicy(rules, uint64(block.timestamp));
        vm.warp(100);
    }

    // ---------------------------------------------------------------- helpers

    /// Generates events 1..n for DEV; event `alarmAt` (if nonzero) carries alarm=1.
    function _makeChain(uint64 n, uint64 alarmAt) internal {
        heads.push(bytes32(0));
        for (uint64 c = 1; c <= n; ++c) {
            int256[] memory f = new int256[](2);
            f[0] = c == alarmAt ? int256(1) : int256(0);
            f[1] = int256(uint256(c)) * 10;
            Registry.EventHeader memory e =
                Registry.EventHeader(DEV, c, uint64(block.timestamp), f, keccak256(abi.encode("payload", c)));
            evs.push(e);
            bytes32 eh = reg.eventHash(e);
            evHashes.push(eh);
            heads.push(reg.chainStep(heads[c - 1], eh));
        }
    }

    function _slice(uint64 fromExcl, uint64 toIncl) internal view returns (bytes32[] memory out) {
        out = new bytes32[](toIncl - fromExcl);
        for (uint64 i = fromExcl; i < toIncl; ++i) {
            out[i - fromExcl] = evHashes[i];
        }
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _receipt(uint64 c, uint64 deadline) internal view returns (Registry.Receipt memory r, bytes memory sig) {
        r = Registry.Receipt(DEV, c, heads[c], deadline);
        sig = _sign(gwKey, reg.receiptDigest(r));
    }

    function _devSig(uint64 deviceId, uint64 c, bytes32 head, uint256 key) internal view returns (bytes memory) {
        return _sign(key, reg.checkpointDigest(Registry.Checkpoint(deviceId, c, head)));
    }

    /// Anchors a 2-leaf batch {DEV at c, OTHER_DEV at 1} and returns DEV's coverage proof.
    function _anchorBatch(uint64 c) internal returns (Registry.Coverage memory cov) {
        bytes32 otherHead = keccak256("other-device-head");
        bytes32 a = reg.leafOf(DEV, c, heads[c]);
        bytes32 b = reg.leafOf(OTHER_DEV, 1, otherHead);
        bytes32 root = a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
        vm.prank(gw);
        reg.anchor(root);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = b;
        cov = Registry.Coverage(root, c, heads[c], _devSig(DEV, c, heads[c], devKey), proof);
    }

    function _status(uint256 id) internal view returns (Registry.Status s) {
        (, s,,,,,,,) = reg.challenges(id);
    }

    // --------------------------------------------------- honest behaviour

    function test_HonestCustody_Dismissed() public {
        _makeChain(10, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(6, uint64(block.timestamp + 10));
        Registry.Coverage memory cov = _anchorBatch(10); // anchors a later head, before the deadline
        vm.warp(block.timestamp + 11);
        uint256 id = reg.challengeCustody(r, sig);
        reg.respondCoverage(id, cov, _slice(6, 10));
        assertEq(uint8(_status(id)), uint8(Registry.Status.Dismissed));
        assertFalse(reg.convicted(gw));
    }

    function test_CustodyChallengeBeforeDeadline_Reverts() public {
        _makeChain(3, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(3, uint64(block.timestamp + 10));
        vm.expectRevert(Registry.DeadlineNotPassed.selector);
        reg.challengeCustody(r, sig);
    }

    // ------------------------------------------- A1 / A2 tail truncation

    /// A1: gateway receipts event 8 but only ever anchors up to event 5.
    function test_A1_TailTruncation_Convicted() public {
        _makeChain(8, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(8, uint64(block.timestamp + 5));
        Registry.Coverage memory cov = _anchorBatch(5);
        vm.warp(block.timestamp + 6);
        uint256 id = reg.challengeCustody(r, sig);

        // The stale head cannot be linked forward to the receipted head.
        vm.expectRevert(Registry.BadLink.selector);
        reg.respondCoverage(id, cov, new bytes32[](0));

        vm.warp(block.timestamp + WINDOW + 1);
        reg.finalize(id);
        assertTrue(reg.convicted(gw));
    }

    /// A2: mid-stream drop. The gateway anchors a fabricated head that skips event 4.
    /// The device never signed that head, so coverage cannot be shown.
    function test_A2_MidStreamDrop_CannotForgeHead() public {
        _makeChain(6, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(3, uint64(block.timestamp + 5));
        bytes32 forged = reg.chainStep(heads[3], evHashes[4]); // skips event 4
        bytes32 leaf = reg.leafOf(DEV, 5, forged);
        vm.prank(gw);
        reg.anchor(leaf);
        vm.warp(block.timestamp + 6);
        uint256 id = reg.challengeCustody(r, sig);

        // The leaf is genuinely anchored (single-leaf batch, empty proof), but only the device can
        // sign a head: replaying the device's signature on its real head 5 does not cover the forgery.
        Registry.Coverage memory cov =
            Registry.Coverage(leaf, 5, forged, _devSig(DEV, 5, heads[5], devKey), new bytes32[](0));
        vm.expectRevert(Registry.BadSignature.selector);
        reg.respondCoverage(id, cov, _slice(3, 5));
    }

    // ---------------------------------------------------- A3 stonewalling

    /// A3: the gateway never receipts; a witness posts the device-signed head.
    function test_A3_Stonewall_NoticeConvicted() public {
        _makeChain(4, 0);
        uint256 id = reg.notice(Registry.Checkpoint(DEV, 4, heads[4]), _devSig(DEV, 4, heads[4], devKey));
        vm.warp(block.timestamp + WINDOW + 1);
        reg.finalize(id);
        assertTrue(reg.convicted(gw));
    }

    function test_A3_NoticeAnswered_Dismissed() public {
        _makeChain(4, 0);
        uint256 id = reg.notice(Registry.Checkpoint(DEV, 4, heads[4]), _devSig(DEV, 4, heads[4], devKey));
        Registry.Coverage memory cov = _anchorBatch(4);
        reg.respondCoverage(id, cov, new bytes32[](0));
        assertEq(uint8(_status(id)), uint8(Registry.Status.Dismissed));
    }

    function test_A3_NoticeForgedDeviceSig_Reverts() public {
        _makeChain(4, 0);
        bytes memory wrongSig = _devSig(DEV, 4, heads[4], otherDevKey); // before expectRevert: it makes a call
        vm.expectRevert(Registry.BadSignature.selector);
        reg.notice(Registry.Checkpoint(DEV, 4, heads[4]), wrongSig);
    }

    // ------------------------------- A4 suppression disguised as non-selection

    /// A4: event 3 is an alarm (FULL under the committed policy); the gateway withholds its payload.
    function test_A4_DisguisedSuppression_Convicted() public {
        _makeChain(5, 3);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(5, uint64(block.timestamp + 5));
        uint256 id = reg.challengeAvailability(r, sig, heads[2], evs[2], _slice(3, 5));
        vm.warp(block.timestamp + WINDOW + 1);
        reg.finalize(id);
        assertTrue(reg.convicted(gw));
    }

    function test_A4_PayloadPublished_Dismissed() public {
        _makeChain(5, 3);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(5, uint64(block.timestamp + 5));
        uint256 id = reg.challengeAvailability(r, sig, heads[2], evs[2], _slice(3, 5));
        reg.respondPayload(id, abi.encode("payload", uint64(3)));
        assertEq(uint8(_status(id)), uint8(Registry.Status.Dismissed));
    }

    /// Non-alarm events are DIGEST: nobody can demand their payload.
    function test_A4_DigestEvent_NotChallengeable() public {
        _makeChain(5, 3);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(5, uint64(block.timestamp + 5));
        vm.expectRevert(Registry.NotRequired.selector);
        reg.challengeAvailability(r, sig, heads[1], evs[1], _slice(2, 5));
    }

    /// A tampered event header does not link to the receipted head.
    function test_A4_TamperedHeader_Reverts() public {
        _makeChain(5, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(5, uint64(block.timestamp + 5));
        Registry.EventHeader memory e = evs[2];
        e.features[0] = 1; // claim it was an alarm
        vm.expectRevert(Registry.BadLink.selector);
        reg.challengeAvailability(r, sig, heads[2], e, _slice(3, 5));
    }

    // ---------------------------------------------------- A5 equivocation

    function test_A5_Equivocation_Convicted() public {
        _makeChain(4, 0);
        (Registry.Receipt memory a, bytes memory sigA) = _receipt(4, uint64(block.timestamp + 5));
        Registry.Receipt memory b = Registry.Receipt(DEV, 4, keccak256("other history"), a.deadline);
        reg.proveEquivocation(a, sigA, b, _sign(gwKey, reg.receiptDigest(b)));
        assertTrue(reg.convicted(gw));
    }

    function test_A5_SameHead_NotEquivocation() public {
        _makeChain(4, 0);
        (Registry.Receipt memory a, bytes memory sigA) = _receipt(4, uint64(block.timestamp + 5));
        Registry.Receipt memory b = Registry.Receipt(DEV, 4, heads[4], a.deadline + 3);
        bytes memory sigB = _sign(gwKey, reg.receiptDigest(b));
        vm.expectRevert(Registry.NotEquivocation.selector);
        reg.proveEquivocation(a, sigA, b, sigB);
    }

    // ---------------------------------------------------- A6 deadline delay

    function test_A6_LateAnchor_MarkedLateNotConvicted() public {
        _makeChain(5, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(5, uint64(block.timestamp + 3));
        vm.warp(block.timestamp + 4);
        uint256 id = reg.challengeCustody(r, sig);
        Registry.Coverage memory cov = _anchorBatch(5); // anchored after the deadline
        reg.respondCoverage(id, cov, new bytes32[](0));
        assertEq(uint8(_status(id)), uint8(Registry.Status.Late));
        assertFalse(reg.convicted(gw));
    }

    // ----------------------------------------------------- window mechanics

    function test_FinalizeInsideWindow_Reverts() public {
        _makeChain(2, 0);
        uint256 id = reg.notice(Registry.Checkpoint(DEV, 2, heads[2]), _devSig(DEV, 2, heads[2], devKey));
        vm.expectRevert(Registry.WindowOpen.selector);
        reg.finalize(id);
    }

    function test_RespondAfterWindow_Reverts() public {
        _makeChain(2, 0);
        uint256 id = reg.notice(Registry.Checkpoint(DEV, 2, heads[2]), _devSig(DEV, 2, heads[2], devKey));
        vm.warp(block.timestamp + WINDOW + 1);
        Registry.Coverage memory cov = _anchorBatch(2);
        vm.expectRevert(Registry.WindowClosed.selector);
        reg.respondCoverage(id, cov, new bytes32[](0));
    }

    function test_PolicyCannotBeRetroactive() public {
        Registry.Rule[] memory rules = new Registry.Rule[](0);
        vm.warp(1000);
        vm.expectRevert(Registry.PolicyNotForward.selector);
        reg.setPolicy(rules, 999);
    }

    // ------------------------------------------- non-frameability (fuzz)

    /// Definition 3(3): for any honest history (n events, receipt at k, anchored head m >= k
    /// before the deadline), the honest gateway's response is always accepted and it is never convicted.
    function testFuzz_NonFrameability_Custody(uint8 nRaw, uint8 kRaw, uint8 mRaw, uint8 slack) public {
        uint64 n = uint64(bound(nRaw, 1, 64));
        uint64 k = uint64(bound(kRaw, 1, n));
        uint64 m = uint64(bound(mRaw, k, n));
        _makeChain(n, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(k, uint64(block.timestamp + 1 + slack));
        Registry.Coverage memory cov = _anchorBatch(m);
        vm.warp(r.deadline + 1);
        uint256 id = reg.challengeCustody(r, sig);
        reg.respondCoverage(id, cov, _slice(k, m));
        assertEq(uint8(_status(id)), uint8(Registry.Status.Dismissed));
        assertFalse(reg.convicted(gw));
    }

    /// Soundness counterpart: if the anchored head is older than the receipted one (m < k),
    /// no response is accepted, so the omission is always convicted.
    function testFuzz_TruncationAlwaysCaught(uint8 nRaw, uint8 kRaw, uint8 mRaw) public {
        uint64 n = uint64(bound(nRaw, 2, 64));
        uint64 k = uint64(bound(kRaw, 2, n));
        uint64 m = uint64(bound(mRaw, 1, k - 1));
        _makeChain(n, 0);
        (Registry.Receipt memory r, bytes memory sig) = _receipt(k, uint64(block.timestamp + 2));
        Registry.Coverage memory cov = _anchorBatch(m);
        vm.warp(r.deadline + 1);
        uint256 id = reg.challengeCustody(r, sig);
        vm.expectRevert(Registry.BadLink.selector);
        reg.respondCoverage(id, cov, _slice(m, k));
        vm.warp(block.timestamp + WINDOW + 1);
        reg.finalize(id);
        assertTrue(reg.convicted(gw));
    }
}
