// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Minimal proof checker interface for the final MNT4 pairing verifier.
/// @dev The concrete checker may be backed by any succinct proof system. The public
///      verifier does not expose the proof-system name in its contract name or ABI.
interface IMNT4PairingProofChecker {
    function verify(bytes32 statementHash, bytes calldata proof) external view returns (bool);
}

/// @notice Stateless public verifier for MNT4-753 pairing claims.
/// @dev This contract is the supervisor-facing minimal API: no owner, no mutable
///      registry, no replay state, no expiry, and no consume path. A caller submits
///      points, the claimed pairing-result digest, commitments to the untrusted
///      off-chain artifacts, and a proof that binds those objects together.
contract MNT4PairingVerifier {
    bytes32 public constant STATEMENT_DOMAIN = keccak256("MNT4_PAIRING_VERIFIER_V1");
    bytes32 public constant POINTS_DOMAIN = keccak256("MNT4_R8_POINTS_V3_PARAMQ");
    bytes32 public constant Q_DOMAIN = keccak256("MNT4_R8_PARAMETRIC_Q_V3");

    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IMNT4PairingProofChecker public immutable PROOF_CHECKER;
    uint256 public immutable MAX_PAIRS;

    struct G1Point {
        uint256[3] x;
        uint256[3] y;
    }

    struct G2Point {
        uint256[6] x;
        uint256[6] y;
    }

    struct ArtifactCommitments {
        bytes32 lineCommitment;
        bytes32 doubleLineCommitment;
        bytes32 addLineCommitment;
        bytes32 millerTraceCommitment;
        bytes32 finalExponentiationCommitment;
    }

    error InvalidProofChecker();
    error InvalidMaxPairs();
    error NoPairs();
    error PairLengthMismatch();
    error TooManyPairs();
    error InvalidLineCommitment();
    error InvalidProof();
    error InvalidPublicInputBinding();

    struct ProofData {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    constructor(address proofChecker_, uint256 maxPairs_) {
        if (proofChecker_ == address(0)) revert InvalidProofChecker();
        if (maxPairs_ == 0) revert InvalidMaxPairs();
        PROOF_CHECKER = IMNT4PairingProofChecker(proofChecker_);
        MAX_PAIRS = maxPairs_;
    }

    /// @notice Verify one MNT4 pairing claim.
    /// @param p G1 point over the MNT4 base field, encoded as 3-limb coordinates.
    /// @param q G2 point over the quadratic extension, encoded as two 6-limb coordinates.
    /// @param expectedResultDigest Digest of the claimed final pairing value in Fq4.
    /// @param commitments Commitments to line cache, Miller trace, and final exponentiation artifacts.
    /// @param proof Succinct proof accepted by `proofChecker`.
    function verifySinglePairing(
        G1Point calldata p,
        G2Point calldata q,
        bytes32 expectedResultDigest,
        ArtifactCommitments calldata commitments,
        bytes calldata proof
    ) external view returns (bool) {
        _validateCommitments(commitments);
        bytes32 statementHash = hashSingleStatement(p, q, expectedResultDigest, commitments);
        if (!PROOF_CHECKER.verify(statementHash, proof)) revert InvalidProof();
        return true;
    }

    /// @notice Verify a multi-pairing claim with a shared off-chain accumulator.
    /// @dev The proof must bind all pairs to the same claimed product/result digest.
    function verifyMultiPairing(
        G1Point[] calldata pointsP,
        G2Point[] calldata pointsQ,
        bytes32 expectedResultDigest,
        ArtifactCommitments calldata commitments,
        bytes calldata proof
    ) external view returns (bool) {
        uint256 n = pointsP.length;
        if (n == 0) revert NoPairs();
        if (n != pointsQ.length) revert PairLengthMismatch();
        if (n > MAX_PAIRS) revert TooManyPairs();

        _validateCommitments(commitments);
        bytes32 statementHash = hashMultiStatement(pointsP, pointsQ, expectedResultDigest, commitments);
        if (!PROOF_CHECKER.verify(statementHash, proof)) revert InvalidProof();
        return true;
    }

    /// @notice Verify a production-style MNT4 pairing claim against the public inputs
    ///         embedded in the succinct proof envelope.
    /// @dev This is the supervisor-facing path. The contract does not recompute MNT4
    ///      arithmetic on-chain; instead it checks that the proof public inputs are
    ///      exactly bound to the submitted points, claimed result, and artifact
    ///      commitments, then delegates proof validity to `PROOF_CHECKER`.
    function verifyPairingClaim(
        G1Point[] calldata pointsP,
        G2Point calldata q,
        bytes32 expectedResultDigest,
        bytes32 artifactRoot,
        bytes32 transcriptHash,
        bytes32 context,
        uint64 epoch,
        ArtifactCommitments calldata commitments,
        bytes calldata proof
    ) external view returns (bool) {
        uint256 n = pointsP.length;
        if (n == 0) revert NoPairs();
        if (n > MAX_PAIRS) revert TooManyPairs();

        uint256[19] memory publicSignals = _decodePublicSignals(proof);
        _validatePairingClaimPublicInputs(
            pointsP,
            q,
            expectedResultDigest,
            artifactRoot,
            transcriptHash,
            context,
            epoch,
            commitments,
            publicSignals
        );

        bytes32 statementHash = bytes32(publicSignals[12]);
        if (!PROOF_CHECKER.verify(statementHash, proof)) revert InvalidProof();
        return true;
    }

    function hashSingleStatement(
        G1Point calldata p,
        G2Point calldata q,
        bytes32 expectedResultDigest,
        ArtifactCommitments calldata commitments
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                STATEMENT_DOMAIN,
                uint256(1),
                _hashG1(p),
                _hashG2(q),
                expectedResultDigest,
                _hashCommitments(commitments)
            )
        );
    }

    function hashMultiStatement(
        G1Point[] calldata pointsP,
        G2Point[] calldata pointsQ,
        bytes32 expectedResultDigest,
        ArtifactCommitments calldata commitments
    ) public pure returns (bytes32) {
        uint256 n = pointsP.length;
        bytes32[] memory pairHashes = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            pairHashes[i] = keccak256(abi.encode(_hashG1(pointsP[i]), _hashG2(pointsQ[i])));
        }
        return keccak256(
            abi.encode(
                STATEMENT_DOMAIN,
                n,
                keccak256(abi.encode(pairHashes)),
                expectedResultDigest,
                _hashCommitments(commitments)
            )
        );
    }

    function _validateCommitments(ArtifactCommitments calldata commitments) private pure {
        if (commitments.lineCommitment != keccak256(abi.encode(commitments.doubleLineCommitment, commitments.addLineCommitment))) {
            revert InvalidLineCommitment();
        }
    }

    function _decodePublicSignals(bytes calldata proof) private pure returns (uint256[19] memory publicSignals) {
        (, publicSignals,) = abi.decode(proof, (bytes32, uint256[19], ProofData));
    }

    function _validatePairingClaimPublicInputs(
        G1Point[] calldata pointsP,
        G2Point calldata q,
        bytes32 expectedResultDigest,
        bytes32 artifactRoot,
        bytes32 transcriptHash,
        bytes32 context,
        uint64 epoch,
        ArtifactCommitments calldata commitments,
        uint256[19] memory publicSignals
    ) private pure {
        if (_toField(expectedResultDigest) != publicSignals[1]) revert InvalidPublicInputBinding();
        if (_toField(artifactRoot) != publicSignals[2]) revert InvalidPublicInputBinding();
        if (_toField(transcriptHash) != publicSignals[3]) revert InvalidPublicInputBinding();
        if (_toField(commitments.lineCommitment) != publicSignals[4]) revert InvalidPublicInputBinding();
        if (_toField(commitments.doubleLineCommitment) != publicSignals[5]) revert InvalidPublicInputBinding();
        if (_toField(commitments.addLineCommitment) != publicSignals[6]) revert InvalidPublicInputBinding();
        if (_toField(hashPoints(pointsP)) != publicSignals[7]) revert InvalidPublicInputBinding();
        if (_toField(context) != publicSignals[8]) revert InvalidPublicInputBinding();
        if (uint256(epoch) != publicSignals[9]) revert InvalidPublicInputBinding();
        if (pointsP.length != publicSignals[10]) revert InvalidPublicInputBinding();
        if (_toField(commitments.millerTraceCommitment) != publicSignals[11]) revert InvalidPublicInputBinding();
        if (_toField(commitments.finalExponentiationCommitment) != publicSignals[13]) revert InvalidPublicInputBinding();
        if (_toField(hashParametricQ(q)) != publicSignals[14]) revert InvalidPublicInputBinding();
    }

    function hashPoints(G1Point[] calldata pointsP) public pure returns (bytes32 acc) {
        acc = POINTS_DOMAIN;
        uint256 n = pointsP.length;
        for (uint256 i = 0; i < n; ++i) {
            G1Point calldata p = pointsP[i];
            acc = keccak256(abi.encodePacked(acc, p.x[0], p.x[1], p.x[2], p.y[0], p.y[1], p.y[2]));
        }
    }

    function hashParametricQ(G2Point calldata q) public pure returns (bytes32 qHash) {
        qHash = keccak256(
            abi.encodePacked(
                Q_DOMAIN,
                q.x[0],
                q.x[1],
                q.x[2],
                q.x[3],
                q.x[4],
                q.x[5],
                q.y[0],
                q.y[1],
                q.y[2],
                q.y[3],
                q.y[4],
                q.y[5]
            )
        );
    }

    function _toField(bytes32 value) private pure returns (uint256) {
        return uint256(value) % SNARK_SCALAR_FIELD;
    }

    function _hashCommitments(ArtifactCommitments calldata commitments) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                commitments.lineCommitment,
                commitments.doubleLineCommitment,
                commitments.addLineCommitment,
                commitments.millerTraceCommitment,
                commitments.finalExponentiationCommitment
            )
        );
    }

    function _hashG1(G1Point calldata p) private pure returns (bytes32) {
        return keccak256(abi.encode(p.x, p.y));
    }

    function _hashG2(G2Point calldata q) private pure returns (bytes32) {
        return keccak256(abi.encode(q.x, q.y));
    }
}
