# Off-chain compute / on-chain verify implementation

Main deployment contract:

- `src/final_mnt4_pairing/MNT4PairingFinal.sol`

The public API verifies a pairing claim by checking proof validity and binding public inputs to:

- MNT4 G1 points `P_i`;
- dynamic MNT4 G2 point `Q`;
- claimed pairing-result digest;
- line-cache, Miller-trace, and final-exponentiation commitments.

No owner, replay state, expiry policy, registry, consume path, or diagnostic on-chain recomputation is included in this final contour.

Run tests:

```bash
forge test --offline
cargo test --offline --manifest-path crates/mnt4_trace_backend/Cargo.toml
```

Run release benchmark:

```bash
npm install
python3 script/final_mnt4_pairing_release.py
```

## Proof-status boundary

The current `stage6_single_strict` circuit is a compact prepared-relation envelope. It binds the Rust-generated pairing digest, line-cache commitments, Miller trace commitment, final-exponentiation commitment, point hash and Q hash. It intentionally does not replay every MNT4 field operation inside a BN254 circuit, because that would reproduce the non-native arithmetic bottleneck that this project is designed to avoid.

The research direction is instead:

```text
Rust backend -> MNT-native relation evidence -> future folding layer -> BN254 compression proof -> Solidity verifier
```

The first implementation step for that direction is `crates/mnt_cycle_constraints`, which provides reproducible MNT-native constraint accounting for Fp/Fq2/Fq4 arithmetic, sparse line multiplication, Miller transitions, line-cache checks and final-exponentiation residue checks.
