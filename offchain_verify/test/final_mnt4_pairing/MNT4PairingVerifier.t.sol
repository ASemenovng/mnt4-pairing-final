// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import "../../src/final_mnt4_pairing/MNT4PairingVerifier.sol";

contract EchoPairingProofChecker is IMNT4PairingProofChecker {
    function verify(bytes32 statementHash, bytes calldata proof) external pure returns (bool) {
        if (proof.length != 32) return false;
        return abi.decode(proof, (bytes32)) == statementHash;
    }
}

contract MNT4PairingVerifierTest is Test {
    MNT4PairingVerifier internal verifier;
    EchoPairingProofChecker internal checker;

    function setUp() public {
        checker = new EchoPairingProofChecker();
        verifier = new MNT4PairingVerifier(address(checker), 8);
    }

    function testVerifySinglePairingAcceptsBoundStatement() public view {
        MNT4PairingVerifier.G1Point memory p = _g1(1);
        MNT4PairingVerifier.G2Point memory q = _g2(10);
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        bytes32 resultDigest = keccak256("result");
        bytes32 statementHash = verifier.hashSingleStatement(p, q, resultDigest, commitments);

        bool ok = verifier.verifySinglePairing(p, q, resultDigest, commitments, abi.encode(statementHash));
        assertTrue(ok);
    }

    function testVerifySinglePairingRejectsTamperedResult() public {
        MNT4PairingVerifier.G1Point memory p = _g1(1);
        MNT4PairingVerifier.G2Point memory q = _g2(10);
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        bytes32 originalDigest = keccak256("result");
        bytes32 statementHash = verifier.hashSingleStatement(p, q, originalDigest, commitments);

        vm.expectRevert(MNT4PairingVerifier.InvalidProof.selector);
        verifier.verifySinglePairing(p, q, keccak256("tampered-result"), commitments, abi.encode(statementHash));
    }

    function testVerifySinglePairingRejectsBadLineCommitment() public {
        MNT4PairingVerifier.G1Point memory p = _g1(1);
        MNT4PairingVerifier.G2Point memory q = _g2(10);
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        commitments.lineCommitment = keccak256("bad-line-root");

        vm.expectRevert(MNT4PairingVerifier.InvalidLineCommitment.selector);
        verifier.verifySinglePairing(p, q, keccak256("result"), commitments, abi.encode(bytes32(0)));
    }

    function testVerifyMultiPairingAcceptsBoundStatement() public view {
        MNT4PairingVerifier.G1Point[] memory ps = new MNT4PairingVerifier.G1Point[](2);
        MNT4PairingVerifier.G2Point[] memory qs = new MNT4PairingVerifier.G2Point[](2);
        ps[0] = _g1(1);
        ps[1] = _g1(2);
        qs[0] = _g2(10);
        qs[1] = _g2(20);
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();
        bytes32 resultDigest = keccak256("multi-result");
        bytes32 statementHash = verifier.hashMultiStatement(ps, qs, resultDigest, commitments);

        bool ok = verifier.verifyMultiPairing(ps, qs, resultDigest, commitments, abi.encode(statementHash));
        assertTrue(ok);
    }

    function testVerifyMultiPairingRejectsLengthMismatch() public {
        MNT4PairingVerifier.G1Point[] memory ps = new MNT4PairingVerifier.G1Point[](2);
        MNT4PairingVerifier.G2Point[] memory qs = new MNT4PairingVerifier.G2Point[](1);
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();

        vm.expectRevert(MNT4PairingVerifier.PairLengthMismatch.selector);
        verifier.verifyMultiPairing(ps, qs, keccak256("result"), commitments, abi.encode(bytes32(0)));
    }

    function testVerifyMultiPairingRejectsTooManyPairs() public {
        MNT4PairingVerifier.G1Point[] memory ps = new MNT4PairingVerifier.G1Point[](9);
        MNT4PairingVerifier.G2Point[] memory qs = new MNT4PairingVerifier.G2Point[](9);
        MNT4PairingVerifier.ArtifactCommitments memory commitments = _commitments();

        vm.expectRevert(MNT4PairingVerifier.TooManyPairs.selector);
        verifier.verifyMultiPairing(ps, qs, keccak256("result"), commitments, abi.encode(bytes32(0)));
    }

    function _commitments() internal pure returns (MNT4PairingVerifier.ArtifactCommitments memory c) {
        c.doubleLineCommitment = keccak256("double-lines");
        c.addLineCommitment = keccak256("add-lines");
        c.lineCommitment = keccak256(abi.encode(c.doubleLineCommitment, c.addLineCommitment));
        c.millerTraceCommitment = keccak256("miller-trace");
        c.finalExponentiationCommitment = keccak256("final-exponentiation");
    }

    function _g1(uint256 seed) internal pure returns (MNT4PairingVerifier.G1Point memory p) {
        p.x = [seed, seed + 1, seed + 2];
        p.y = [seed + 3, seed + 4, seed + 5];
    }

    function _g2(uint256 seed) internal pure returns (MNT4PairingVerifier.G2Point memory q) {
        q.x = [seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5];
        q.y = [seed + 6, seed + 7, seed + 8, seed + 9, seed + 10, seed + 11];
    }
}
