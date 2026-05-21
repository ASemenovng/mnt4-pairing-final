# Proof-status boundary for the final implementation

This document fixes the interpretation of the final codebase.

## What is already implemented

The final Solidity-facing flow is:

```text
Rust MNT4 backend -> prepared proof input -> compact BN254 proof -> Solidity verifier
```

The deployed public contract verifies a proof and checks that proof public inputs are bound to:

- the submitted MNT4 G1 point(s);
- the submitted MNT4 G2 point Q;
- the claimed pairing-result digest;
- line-cache commitments;
- Miller-trace commitment;
- final-exponentiation commitment.

This is the correct EVM-compatible envelope because Ethereum can verify BN254 proofs cheaply through existing precompiles.

## What must not be claimed

The current BN254 circuit is not a full non-native proof of

\[
Y = e_{\mathrm{MNT4}}(P,Q).
\]

It proves a compact prepared relation over digests and commitments. The reported small circuit size is therefore the cost of the verification envelope, not the cost of a complete MNT4 pairing proof inside BN254.

## Why this is intentional

A full MNT4 pairing proof inside a BN254 circuit would require emulating 753-bit MNT4 arithmetic over the BN254 scalar field. That is the same non-native bottleneck seen in generic folding/recursive systems, and it is exactly what the project is trying to avoid.

The intended research path is:

```text
Rust backend -> MNT-native relation evidence -> future folding layer -> BN254 compression proof -> Solidity
```

The crate `crates/mnt_cycle_constraints` implements the first measurable version of that MNT-native relation layer as explicit constraint accounting.
