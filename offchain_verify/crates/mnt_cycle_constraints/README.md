# MNT-cycle constraint accounting

This crate is the Stage 2 research component of the final project. It does not replace the Solidity verifier and it is not a production CycleFold implementation.

Its purpose is narrower and important: it gives a reproducible constraint accounting model for the MNT-native relation layer that the future folding implementation should use.

The current EVM-compatible verifier still checks a compact BN254 proof. This crate measures the relation that should be proven before that final BN254 compression layer:

```text
Rust backend -> MNT-native relation evidence -> future folding layer -> BN254 compression proof -> Solidity
```

The model uses explicit operation accounting:

- one native field multiplication is one multiplication constraint;
- native additions/equalities are linear and cost zero multiplication constraints;
- Fq2 multiplication uses Karatsuba and costs three native multiplications;
- Fq4 multiplication is a quadratic-extension multiplication over Fq2;
- sparse line multiplication costs two Fq2 multiplications;
- final exponentiation is represented by a residue/relation estimate rather than a full direct exponentiation chain.

Run:

```bash
cargo test --offline --manifest-path crates/mnt_cycle_constraints/Cargo.toml
cargo run --offline --manifest-path crates/mnt_cycle_constraints/Cargo.toml -- --out cache/mnt_cycle_constraints/MNT_CYCLE_CONSTRAINTS_REPORT.md
```
