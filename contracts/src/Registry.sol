// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title PROVE-CPS evidence registry
/// @notice The ledger as a clocked adjudicator (design doc, insight I4). In the honest case a
///         gateway only calls `anchor` (one storage write per batch, independent of the number of
///         devices and events). Every other function is a dispute path, used only when someone cheats.
/// @dev Data model (design doc section 2):
///      - Device chain:   H_c = keccak256(abi.encode(H_{c-1}, eventHash(e_c))), H_0 = 0.
///      - Batch leaf:     keccak256(bytes.concat(keccak256(abi.encode(deviceId, counter, head)))).
///      - Receipt:        EIP-712, signed by a gateway; transfers custody of all events <= counter.
///      - Checkpoint:     EIP-712, signed by a device; attests its own chain head.
///      All times are block timestamps (unix seconds), never block numbers: on an on-demand chain
///      block height stops advancing while the chain idles, so it cannot serve as the adjudicator's
///      clock. Policy activation uses the event's
///      device-signed timestamp, so a gateway cannot choose which policy applies.
contract Registry is EIP712 {
    using ECDSA for bytes32;

    // ------------------------------------------------------------------ types

    struct Receipt {
        uint64 deviceId;
        uint64 counter;
        bytes32 head;
        uint64 deadline; // unix time by which a head >= counter must be anchored
    }

    struct Checkpoint {
        uint64 deviceId;
        uint64 counter;
        bytes32 head;
    }

    struct EventHeader {
        uint64 deviceId;
        uint64 counter;
        uint64 timestamp; // device clock, unix seconds
        int256[] features; // policy features (design rule: everything the policy reads is signed)
        bytes32 payloadHash;
    }

    /// @notice Proof that a device-signed head is inside a batch the gateway anchored.
    struct Coverage {
        bytes32 root;
        uint64 counter;
        bytes32 head;
        bytes deviceSig; // Checkpoint signature by the device
        bytes32[] proof;
    }

    enum Op {
        GE,
        LE,
        EQ,
        NE
    }

    struct Rule {
        uint16 feature;
        Op op;
        int256 threshold;
    }

    enum Kind {
        Custody,
        Notice,
        Availability
    }

    enum Status {
        None,
        Open,
        Dismissed,
        Late,
        Convicted
    }

    struct Device {
        address key;
        address gateway;
    }

    struct Challenge {
        Kind kind;
        Status status;
        address gateway;
        uint64 deviceId;
        uint64 counter;
        uint64 deadline;
        uint64 respondBy;
        bytes32 head;
        bytes32 payloadHash;
    }

    // ------------------------------------------------------------- constants

    bytes32 public constant RECEIPT_TYPEHASH =
        keccak256("Receipt(uint64 deviceId,uint64 counter,bytes32 head,uint64 deadline)");
    bytes32 public constant CHECKPOINT_TYPEHASH = keccak256("Checkpoint(uint64 deviceId,uint64 counter,bytes32 head)");

    // ----------------------------------------------------------------- state

    address public immutable admin;
    uint64 public immutable responseWindow;

    mapping(uint64 => Device) public devices;
    mapping(address => bool) public isGateway;
    mapping(address => bool) public convicted;
    /// @notice gateway => batch root => block timestamp at which it was anchored (0 = never).
    mapping(address => mapping(bytes32 => uint256)) public anchoredAt;

    Rule[][] internal _policies;
    uint64[] public policyActivation; // unix seconds, strictly increasing

    mapping(uint256 => Challenge) public challenges;
    uint256 public challengeCount;

    // ---------------------------------------------------------------- events

    event GatewayRegistered(address indexed gateway);
    event DeviceRegistered(uint64 indexed deviceId, address key, address indexed gateway);
    event PolicySet(uint256 indexed version, uint64 activation);
    event Anchored(address indexed gateway, bytes32 indexed root);
    event ChallengeOpened(uint256 indexed id, Kind kind, address indexed gateway, uint64 deviceId, uint64 counter);
    event ChallengeResolved(uint256 indexed id, Status status);
    event Convicted(address indexed gateway, uint256 indexed challengeId);
    event EquivocationProven(address indexed gateway, uint64 deviceId, uint64 counter);

    // ---------------------------------------------------------------- errors

    error NotAdmin();
    error NotGateway();
    error UnknownDevice();
    error PolicyNotForward();
    error DeadlineNotPassed();
    error BadSignature();
    error NotAnchored();
    error BadProof();
    error BadLink();
    error NotOpen();
    error WrongKind();
    error WindowClosed();
    error WindowOpen();
    error NotRequired();
    error PayloadMismatch();
    error NotEquivocation();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(uint64 responseWindow_) EIP712("ProveCPS", "1") {
        admin = msg.sender;
        responseWindow = responseWindow_;
    }

    // ------------------------------------------------- consortium governance

    function registerGateway(address gateway) external onlyAdmin {
        isGateway[gateway] = true;
        emit GatewayRegistered(gateway);
    }

    function registerDevice(uint64 deviceId, address key, address gateway) external onlyAdmin {
        if (!isGateway[gateway]) revert NotGateway();
        devices[deviceId] = Device(key, gateway);
        emit DeviceRegistered(deviceId, key, gateway);
    }

    /// @notice Adds a policy version. Activation must be in the future and after every earlier
    ///         version: a policy can never be applied retroactively, so governance cannot
    ///         manufacture a conviction for events that were already handled correctly.
    function setPolicy(Rule[] calldata rules, uint64 activation) external onlyAdmin {
        uint256 n = policyActivation.length;
        if (activation < block.timestamp || (n > 0 && activation <= policyActivation[n - 1])) {
            revert PolicyNotForward();
        }
        Rule[] storage p = _policies.push();
        for (uint256 i; i < rules.length; ++i) {
            p.push(rules[i]);
        }
        policyActivation.push(activation);
        emit PolicySet(n, activation);
    }

    // ------------------------------------------------------------ honest path

    /// @notice Commit a batch root. The only call an honest gateway makes.
    function anchor(bytes32 root) external {
        if (!isGateway[msg.sender]) revert NotGateway();
        anchoredAt[msg.sender][root] = block.timestamp;
        emit Anchored(msg.sender, root);
    }

    // ------------------------------------------------------------ disputes

    /// @notice CUSTODY: a gateway receipted (deviceId, counter, head) but the deadline passed.
    function challengeCustody(Receipt calldata r, bytes calldata sig) external returns (uint256 id) {
        if (block.timestamp <= r.deadline) revert DeadlineNotPassed();
        address gw = receiptDigest(r).recover(sig);
        if (!isGateway[gw]) revert BadSignature();
        id = _open(Kind.Custody, gw, r.deviceId, r.counter, r.head, r.deadline, bytes32(0));
    }

    /// @notice NOTICE: a witness posts a device-signed head that was never receipted. From now on the
    ///         device's gateway knows the head (it is on the ledger) and must anchor it within the window.
    function notice(Checkpoint calldata cp, bytes calldata deviceSig) external returns (uint256 id) {
        Device memory d = devices[cp.deviceId];
        if (d.key == address(0)) revert UnknownDevice();
        if (checkpointDigest(cp).recover(deviceSig) != d.key) revert BadSignature();
        id = _open(Kind.Notice, d.gateway, cp.deviceId, cp.counter, cp.head, uint64(block.timestamp), bytes32(0));
    }

    /// @notice AVAILABILITY: the gateway took custody (receipt) of an event that the committed policy
    ///         classifies as FULL; it must publish the payload. Closes "suppression disguised as
    ///         non-selection" (insight I3).
    /// @param prevHead  the device chain head just before `e`
    /// @param later     event hashes from e.counter+1 up to r.counter, linking `e` to the receipted head
    function challengeAvailability(
        Receipt calldata r,
        bytes calldata sig,
        bytes32 prevHead,
        EventHeader calldata e,
        bytes32[] calldata later
    ) external returns (uint256 id) {
        address gw = receiptDigest(r).recover(sig);
        if (!isGateway[gw]) revert BadSignature();
        if (e.deviceId != r.deviceId || uint256(e.counter) + later.length != r.counter) revert BadLink();
        if (_link(chainStep(prevHead, eventHash(e)), later) != r.head) revert BadLink();
        if (!requiresFull(e.features, e.timestamp)) revert NotRequired();
        id = _open(Kind.Availability, gw, e.deviceId, e.counter, r.head, uint64(block.timestamp), e.payloadHash);
    }

    /// @notice Answer a CUSTODY or NOTICE challenge: show an anchored, device-signed head that extends
    ///         the challenged head. Anyone may submit it (e.g. an auditor on the gateway's behalf).
    /// @param later event hashes from challenge.counter+1 up to cov.counter
    function respondCoverage(uint256 id, Coverage calldata cov, bytes32[] calldata later) external {
        Challenge storage c = _openChallenge(id);
        if (c.kind == Kind.Availability) revert WrongKind();
        uint256 at = _verifyCoverage(c.gateway, c.deviceId, cov);
        if (cov.counter < c.counter || later.length != cov.counter - c.counter) revert BadLink();
        if (_link(c.head, later) != cov.head) revert BadLink();
        // Anchored after the receipt deadline: a deadline violation, not an omission.
        _resolve(id, c, (c.kind == Kind.Custody && at > c.deadline) ? Status.Late : Status.Dismissed);
    }

    /// @notice Answer an AVAILABILITY challenge by publishing the payload (as calldata).
    function respondPayload(uint256 id, bytes calldata payload) external {
        Challenge storage c = _openChallenge(id);
        if (c.kind != Kind.Availability) revert WrongKind();
        if (keccak256(payload) != c.payloadHash) revert PayloadMismatch();
        _resolve(id, c, Status.Dismissed);
    }

    /// @notice After the window, an unanswered challenge becomes a conviction.
    function finalize(uint256 id) external {
        Challenge storage c = challenges[id];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp <= c.respondBy) revert WindowOpen();
        _resolve(id, c, Status.Convicted);
        convicted[c.gateway] = true;
        emit Convicted(c.gateway, id);
    }

    /// @notice EQUIVOCATION: two receipts by the same gateway for the same device counter with
    ///         different heads. Convicts immediately; no response can explain it.
    function proveEquivocation(Receipt calldata a, bytes calldata sigA, Receipt calldata b, bytes calldata sigB)
        external
    {
        address gw = receiptDigest(a).recover(sigA);
        if (!isGateway[gw] || receiptDigest(b).recover(sigB) != gw) revert BadSignature();
        if (a.deviceId != b.deviceId || a.counter != b.counter || a.head == b.head) revert NotEquivocation();
        convicted[gw] = true;
        emit EquivocationProven(gw, a.deviceId, a.counter);
    }

    // ------------------------------------------------------------ views

    function receiptDigest(Receipt calldata r) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(RECEIPT_TYPEHASH, r.deviceId, r.counter, r.head, r.deadline)));
    }

    function checkpointDigest(Checkpoint calldata cp) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CHECKPOINT_TYPEHASH, cp.deviceId, cp.counter, cp.head)));
    }

    function eventHash(EventHeader calldata e) public pure returns (bytes32) {
        return keccak256(
            abi.encode(e.deviceId, e.counter, e.timestamp, keccak256(abi.encodePacked(e.features)), e.payloadHash)
        );
    }

    function chainStep(bytes32 head, bytes32 evHash) public pure returns (bytes32) {
        return keccak256(abi.encode(head, evHash));
    }

    function leafOf(uint64 deviceId, uint64 counter, bytes32 head) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(deviceId, counter, head))));
    }

    /// @notice True if the policy version in force at `timestamp` classifies `features` as FULL.
    ///         Before the first version, nothing is FULL.
    function requiresFull(int256[] calldata features, uint64 timestamp) public view returns (bool) {
        uint256 n = policyActivation.length;
        while (n > 0 && policyActivation[n - 1] > timestamp) {
            --n;
        }
        if (n == 0) return false;
        Rule[] storage rules = _policies[n - 1];
        for (uint256 i; i < rules.length; ++i) {
            Rule storage rule = rules[i];
            if (rule.feature >= features.length) continue;
            int256 x = features[rule.feature];
            if (
                (rule.op == Op.GE && x >= rule.threshold) || (rule.op == Op.LE && x <= rule.threshold)
                    || (rule.op == Op.EQ && x == rule.threshold) || (rule.op == Op.NE && x != rule.threshold)
            ) return true;
        }
        return false;
    }

    function policyRules(uint256 version) external view returns (Rule[] memory) {
        return _policies[version];
    }

    // --------------------------------------------------------- internals

    function _open(Kind kind, address gw, uint64 deviceId, uint64 counter, bytes32 head, uint64 deadline, bytes32 ph)
        internal
        returns (uint256 id)
    {
        id = ++challengeCount;
        challenges[id] =
            Challenge(kind, Status.Open, gw, deviceId, counter, deadline, uint64(block.timestamp) + responseWindow, head, ph);
        emit ChallengeOpened(id, kind, gw, deviceId, counter);
    }

    function _openChallenge(uint256 id) internal view returns (Challenge storage c) {
        c = challenges[id];
        if (c.status != Status.Open) revert NotOpen();
        if (block.timestamp > c.respondBy) revert WindowClosed();
    }

    function _resolve(uint256 id, Challenge storage c, Status s) internal {
        c.status = s;
        emit ChallengeResolved(id, s);
    }

    function _verifyCoverage(address gw, uint64 deviceId, Coverage calldata cov) internal view returns (uint256 at) {
        at = anchoredAt[gw][cov.root];
        if (at == 0) revert NotAnchored();
        if (!MerkleProof.verifyCalldata(cov.proof, cov.root, leafOf(deviceId, cov.counter, cov.head))) {
            revert BadProof();
        }
        bytes32 digest =
            _hashTypedDataV4(keccak256(abi.encode(CHECKPOINT_TYPEHASH, deviceId, cov.counter, cov.head)));
        if (digest.recover(cov.deviceSig) != devices[deviceId].key) revert BadSignature();
    }

    function _link(bytes32 from, bytes32[] calldata evHashes) internal pure returns (bytes32 h) {
        h = from;
        for (uint256 i; i < evHashes.length; ++i) {
            h = keccak256(abi.encode(h, evHashes[i]));
        }
    }
}
