// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Test } from "forge-std/Test.sol";
import { SecureMerkleTrie } from "src/libraries/trie/SecureMerkleTrie.sol";

contract SecureMerkleTrie_Test is Test {
    // ------------------------------
    // RLP encoding helpers (minimal)
    // ------------------------------

    function _rlpEncodeBytes(bytes memory data) internal pure returns (bytes memory out) {
        uint256 len = data.length;
        if (len == 1 && uint8(data[0]) < 0x80) {
            return data; // single byte, no header
        }
        if (len <= 55) {
            bytes memory header = new bytes(1);
            header[0] = bytes1(uint8(0x80 + len));
            return bytes.concat(header, data);
        }
        // long string
        bytes memory lenBytes = _encodeLengthBigEndian(len);
        bytes memory header2 = new bytes(1);
        header2[0] = bytes1(uint8(0xb7 + lenBytes.length));
        return bytes.concat(header2, lenBytes, data);
    }

    function _rlpEncodeList(bytes[] memory items) internal pure returns (bytes memory out) {
        bytes memory payload;
        for (uint256 i = 0; i < items.length; i++) {
            payload = bytes.concat(payload, items[i]);
        }
        uint256 len = payload.length;
        if (len <= 55) {
            bytes memory header = new bytes(1);
            header[0] = bytes1(uint8(0xc0 + len));
            return bytes.concat(header, payload);
        }
        bytes memory lenBytes = _encodeLengthBigEndian(len);
        bytes memory header2 = new bytes(1);
        header2[0] = bytes1(uint8(0xf7 + lenBytes.length));
        return bytes.concat(header2, lenBytes, payload);
    }

    function _encodeLengthBigEndian(uint256 len) internal pure returns (bytes memory out) {
        // compute minimal big-endian representation
        uint256 temp = len;
        uint256 size;
        while (temp != 0) {
            size++;
            temp >>= 8;
        }
        if (size == 0) size = 1; // for len==0
        out = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            out[size - 1 - i] = bytes1(uint8(len & 0xff));
            len >>= 8;
        }
    }

    // ------------------------------
    // Proof builders
    // ------------------------------

    function _buildLeafProof(bytes memory keyPreimage, bytes memory value)
        internal
        pure
        returns (bytes32 root, bytes[] memory proof)
    {
        bytes32 h = keccak256(keyPreimage);
        // Even-length leaf prefix: 0x20 || key-bytes (64 nibbles => 32 bytes)
        bytes memory path = bytes.concat(bytes1(0x20), bytes.concat(abi.encodePacked(h)));
        bytes[] memory leafItems = new bytes[](2);
        leafItems[0] = _rlpEncodeBytes(path);
        leafItems[1] = _rlpEncodeBytes(value);
        bytes memory leaf = _rlpEncodeList(leafItems);
        root = keccak256(leaf);
        proof = new bytes[](1);
        proof[0] = leaf;
    }

    function _buildExtensionToBranchEmptyValue(bytes memory keyPreimage)
        internal
        pure
        returns (bytes32 root, bytes[] memory proof)
    {
        bytes32 h = keccak256(keyPreimage);
        // Extension with entire key path (even): prefix 0x00 || key-bytes
        bytes memory extPath = bytes.concat(bytes1(0x00), bytes.concat(abi.encodePacked(h)));

        // Build branch node with all 16 children empty and EMPTY value (last element empty)
        bytes[] memory branchElems = new bytes[](17);
        for (uint256 i = 0; i < 17; i++) {
            // RLP empty string: 0x80
            branchElems[i] = _rlpEncodeBytes(bytes(""));
        }
        bytes memory branch = _rlpEncodeList(branchElems);
        bytes32 branchHash = keccak256(branch);

        // Extension node [extPath, branchHash]
        bytes[] memory extItems = new bytes[](2);
        extItems[0] = _rlpEncodeBytes(extPath);
        extItems[1] = _rlpEncodeBytes(abi.encodePacked(branchHash));
        bytes memory ext = _rlpEncodeList(extItems);

        root = keccak256(ext);
        proof = new bytes[](2);
        proof[0] = ext;
        proof[1] = branch;
    }

    // ------------------------------
    // Tests
    // ------------------------------

    function test_secureTrie_singleLeaf_valid_succeeds() external pure {
        bytes memory keyPreimage = hex"abcd";
        bytes memory val = hex"01"; // storage true
        (bytes32 root, bytes[] memory proof) = _buildLeafProof(keyPreimage, val);
        bool ok = SecureMerkleTrie.verifyInclusionProof({
            _key: keyPreimage,
            _value: val,
            _proof: proof,
            _root: root
        });
        assertTrue(ok);
    }

    function test_secureTrie_leaf_wrongValue_returnsFalse() external pure {
        bytes memory keyPreimage = hex"abcd";
        bytes memory val = hex"01";
        (bytes32 root, bytes[] memory proof) = _buildLeafProof(keyPreimage, val);
        // Mismatched expected value should return false (not revert)
        bool ok = SecureMerkleTrie.verifyInclusionProof({
            _key: keyPreimage,
            _value: hex"02",
            _proof: proof,
            _root: root
        });
        assertFalse(ok);
    }

    function test_secureTrie_leaf_extraNodeAppended_reverts() external {
        bytes memory keyPreimage = hex"abcd";
        bytes memory val = hex"01";
        (bytes32 root, bytes[] memory proof) = _buildLeafProof(keyPreimage, val);
        // Append an extra (duplicate) leaf node to simulate extra proof element
        bytes[] memory badProof = new bytes[](2);
        badProof[0] = proof[0];
        badProof[1] = proof[0];

        vm.expectRevert("MerkleTrie: value node must be last node in proof (leaf)");
        // Use harness pattern: call through MerkleTrie via SecureMerkleTrie to trigger revert
        SecureMerkleTrie.verifyInclusionProof({ _key: keyPreimage, _value: val, _proof: badProof, _root: root });
    }

    function test_secureTrie_branchEmptyValue_reverts() external {
        bytes memory keyPreimage = hex"abcd";
        (bytes32 root, bytes[] memory proof) = _buildExtensionToBranchEmptyValue(keyPreimage);

        vm.expectRevert("MerkleTrie: value length must be greater than zero (branch)");
        SecureMerkleTrie.verifyInclusionProof({
            _key: keyPreimage,
            _value: hex"01",
            _proof: proof,
            _root: root
        });
    }

    function test_secureTrie_leaf_pathMismatch_reverts() external {
        bytes memory keyPreimage = hex"abcd";
        bytes memory val = hex"01";
        (bytes32 root, bytes[] memory proof) = _buildLeafProof(keyPreimage, val);

        // Mutate one byte in the path remainder (after the first prefix byte) to break equality
        bytes memory mutatedLeaf = proof[0];
        // Find first byte of the path: list header + bytes header sizes are variable; however our
        // constructed leaf is [bytes(path), bytes(value)] and for path length 33 the RLP header is
        // 0x80 + 33 = 0xa1, so the first byte of path content is at offset: 1 (list hdr) + 1 (path hdr)
        // Safely compute by scanning for 0xa1 which we know we produced.
        uint256 idx;
        for (uint256 i = 0; i < mutatedLeaf.length - 1; i++) {
            if (mutatedLeaf[i] == bytes1(uint8(0xa1))) {
                idx = i + 1; // start of path content
                break;
            }
        }
        // Flip one bit in the last byte of the path content
        mutatedLeaf[idx + 33 - 1] = bytes1(uint8(mutatedLeaf[idx + 33 - 1]) ^ 0x01);
        bytes[] memory badProof = new bytes[](1);
        badProof[0] = mutatedLeaf;

        vm.expectRevert("MerkleTrie: key remainder must be identical to path remainder");
        SecureMerkleTrie.verifyInclusionProof({
            _key: keyPreimage,
            _value: val,
            _proof: badProof,
            _root: root
        });
    }

    function test_secureTrie_leaf_unknownPrefix_reverts() external {
        bytes memory keyPreimage = hex"abcd";
        bytes memory val = hex"01";
        (bytes32 root, bytes[] memory proof) = _buildLeafProof(keyPreimage, val);
        bytes memory mutatedLeaf = proof[0];

        // Locate the start of the path content as in the previous test
        uint256 idx;
        for (uint256 i = 0; i < mutatedLeaf.length - 1; i++) {
            if (mutatedLeaf[i] == bytes1(uint8(0xa1))) {
                idx = i + 1; // start of path content
                break;
            }
        }
        // Overwrite the prefix byte (first byte of path content) with an unknown prefix (>= 0x40)
        mutatedLeaf[idx] = bytes1(0x40);
        bytes[] memory badProof = new bytes[](1);
        badProof[0] = mutatedLeaf;

        vm.expectRevert("MerkleTrie: received a node with an unknown prefix");
        SecureMerkleTrie.verifyInclusionProof({
            _key: keyPreimage,
            _value: val,
            _proof: badProof,
            _root: root
        });
    }
}

