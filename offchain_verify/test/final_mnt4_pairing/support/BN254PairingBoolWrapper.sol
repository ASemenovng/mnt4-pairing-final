// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @notice Test-only wrapper around the Ethereum BN254 pairing precompile.
/// @dev This contract is not part of the MNT4 verifier. It exists only to test
///      precompile-style boolean semantics: valid proof/equation -> true, otherwise false.
contract BN254PairingBoolWrapper {
    function verify(bytes memory input) external view returns (bool ok) {
        bytes memory out = new bytes(32);
        bool success;
        assembly ("memory-safe") {
            success := staticcall(1000000, 0x08, add(input, 0x20), mload(input), add(out, 0x20), 0x20)
        }
        if (!success) return false;
        return abi.decode(out, (uint256)) == 1;
    }
}
