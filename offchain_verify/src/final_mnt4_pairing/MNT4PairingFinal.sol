// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "./MNT4PairingVerifier.sol";
import "./MNT4PairingProofChecker.sol";
import "./MNT4ProofSystemVerifier.sol";

/// @notice Single deployable entrypoint for the final MNT4 pairing-verification path.
/// @dev The public API is inherited from `MNT4PairingVerifier`. The constructor
///      deploys the concrete proof-system verifier and the neutral checker adapter,
///      so users only need to interact with this contract address.
contract MNT4PairingFinal is MNT4PairingVerifier {
    constructor(uint256 maxPairs)
        MNT4PairingVerifier(address(new MNT4PairingProofChecker(new MNT4ProofSystemVerifier())), maxPairs)
    {}
}
