# Final MNT4 pairing verifier contracts

This folder is the minimal supervisor-facing code surface for the final version of the project.
It deliberately excludes the older experimental V2/V3 verifier contracts, mutable registries,
consume/replay state, expiry policies, and diagnostic on-chain recomputation paths.

## Files

- `MNT4PairingFinal.sol` - the single deployable entrypoint intended for the final
  supervisor-facing code surface. It deploys the neutral checker and generated verifier in
  the constructor, while users call only the inherited public verifier API.
- `MNT4PairingVerifier.sol` - the public stateless verifier contract. It accepts MNT4 points,
  a digest of the claimed pairing result, commitments to off-chain artifacts, and a succinct proof.
- `MNT4PairingProofChecker.sol` - a neutral proof-checker adapter. It binds the outer statement
  hash to public proof signals and then calls the generated proof-system verifier.
- `MNT4ProofSystemVerifier.sol` - generated verifier code under a neutral contract name.
- `BigIntMNT.sol` - base-field arithmetic for MNT4-753, copied from the project arithmetic core.
- `MNT4Extension.sol` - Fq2/Fq4 arithmetic over the MNT4 field tower.
- `MNT4TatePairing.sol` - the existing on-chain MNT4 ate/Tate pairing implementation used as the
  control arithmetic implementation and reference for tests.

## Design decisions

- Contract names do not contain the concrete proof-system name. The public verifier depends on
  the generic `IMNT4PairingProofChecker` interface.
- The contract is public and stateless: no ownership, no API freeze, no replay protection,
  no expiry window, and no consume path.
- Commitments remain part of the API because the verifier must not trust the line cache,
  Miller trace, or final-exponentiation artifacts supplied by the caller.
- `verifyPairingClaim` is the final end-to-end API: it checks that the proof public inputs
  are bound to the submitted points, dynamic `Q`, claimed result digest, artifact roots,
  context, epoch, and line-cache commitments before accepting the proof.
- Current tests cover three supervisor-requested checks:
  1. neutral real proof-checker fixture verification;
  2. MNT4 arithmetic/pairing cross-checks against arkworks-generated vectors;
  3. BN254 precompile-style boolean fuzzing, comparing wrapper return values with raw precompile calls.

## Reproducible release command

Run from the repository root:

```bash
python3 script/final_mnt4_pairing_release.py
```

The command runs the Rust off-chain backend, regenerates the final proof fixture, reads the
R1CS metadata, runs Foundry tests with `--gas-report`, and writes:

- `cache/final_mnt4_pairing/release_summary.json`;
- `cache/final_mnt4_pairing/forge_final_gas_report.log`;
- `FINAL_MNT4_PAIRING_RELEASE_REPORT.md`.
