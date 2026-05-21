// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "./MNT4PairingVerifier.sol";
import "./MNT4ProofSystemVerifier.sol";

/// @notice Neutral adapter from the final pairing verifier to the concrete proof-system verifier.
/// @dev The adapter binds the outer statement hash to a public signal before calling the
///      generated proof-system verifier. The public contract name intentionally does not
///      expose the concrete proof-system name.
contract MNT4PairingProofChecker is IMNT4PairingProofChecker {
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant PUBLIC_SIGNALS_COUNT = 19;
    uint256 private constant STATEMENT_HASH_SIGNAL_INDEX = 12;

    MNT4ProofSystemVerifier public immutable VERIFIER;

    struct ProofData {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    error InvalidVerifier();
    error BadProofEnvelope();

    constructor(MNT4ProofSystemVerifier verifier_) {
        if (address(verifier_) == address(0)) revert InvalidVerifier();
        VERIFIER = verifier_;
    }

    /// @notice Verify a proof envelope bound to the final verifier statement hash.
    /// @dev Envelope layout: `(bytes32 statementHash, uint256[19] publicSignals, ProofData proof)`.
    function verify(bytes32 statementHash, bytes calldata proof) external view returns (bool) {
        if (proof.length == 0) revert BadProofEnvelope();
        (bytes32 boundStatementHash, uint256[19] memory publicSignals, ProofData memory p) =
            abi.decode(proof, (bytes32, uint256[19], ProofData));

        if (boundStatementHash != statementHash) return false;
        if (publicSignals[STATEMENT_HASH_SIGNAL_INDEX] != uint256(statementHash) % SNARK_SCALAR_FIELD) return false;

        return VERIFIER.verifyProof(p.a, p.b, p.c, publicSignals);
    }

    /// @notice Fixture/tooling helper for checking raw public signals against a proof.
    function verifyForPublicSignals(uint256[19] memory publicSignals, bytes calldata proof)
        external
        view
        returns (bool)
    {
        if (proof.length == 0) revert BadProofEnvelope();
        ProofData memory p = abi.decode(proof, (ProofData));
        return VERIFIER.verifyProof(p.a, p.b, p.c, publicSignals);
    }
}
