// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title Baseline archetypes B1-B4 (see README), implemented for on-chain cost comparison.
/// @notice Each baseline uses the same gateway access check as Registry (one cold SLOAD), so measured gas
///         differences come from the evidence design, not from omitted access control.
///         B5 (device-signed chain, no receipts or witness) anchors roots exactly like B3 and is not repeated.
///         B6 (transparency log with gossip) has no on-chain component.
abstract contract Gated {
    address public immutable admin;
    mapping(address => bool) public isGateway;

    error NotGateway();

    constructor() {
        admin = msg.sender;
    }

    function registerGateway(address g) external {
        require(msg.sender == admin);
        isGateway[g] = true;
    }

    modifier onlyGateway() {
        if (!isGateway[msg.sender]) revert NotGateway();
        _;
    }
}

/// @notice B1: every event is written to contract storage (the most common archetype in the survey).
contract FullLog is Gated {
    struct Rec {
        uint64 ts;
        bytes32 featuresHash;
        bytes payload;
    }

    mapping(uint64 => mapping(uint64 => Rec)) public records;

    event Logged(uint64 indexed deviceId, uint64 counter);

    function logEvent(uint64 deviceId, uint64 counter, uint64 ts, int256[] calldata features, bytes calldata payload)
        external
        onlyGateway
    {
        records[deviceId][counter] = Rec(ts, keccak256(abi.encodePacked(features)), payload);
        emit Logged(deviceId, counter);
    }
}

/// @notice B2: one hash per event (data off-chain, integrity on-chain).
contract HashLog is Gated {
    mapping(bytes32 => uint256) public anchoredAt;

    function anchorHash(bytes32 h) external onlyGateway {
        anchoredAt[h] = block.timestamp;
    }
}

/// @notice B3 (and B5): one Merkle root per batch.
contract MerkleLog is Gated {
    mapping(address => mapping(bytes32 => uint256)) public anchoredAt;

    event Anchored(address indexed gateway, bytes32 indexed root);

    function anchor(bytes32 root) external onlyGateway {
        anchoredAt[msg.sender][root] = block.timestamp;
        emit Anchored(msg.sender, root);
    }
}

/// @notice B4: gateway-sequenced batches (sequence numbers assigned by the gateway, hash-chained on-chain).
contract SequencedLog is Gated {
    mapping(address => uint64) public seq;
    mapping(address => bytes32) public tip;

    event Appended(address indexed gateway, uint64 seq, bytes32 root);

    error BadSeq();

    function append(uint64 s, bytes32 root) external onlyGateway {
        if (s != seq[msg.sender] + 1) revert BadSeq();
        seq[msg.sender] = s;
        tip[msg.sender] = keccak256(abi.encode(tip[msg.sender], root));
        emit Appended(msg.sender, s, root);
    }
}
