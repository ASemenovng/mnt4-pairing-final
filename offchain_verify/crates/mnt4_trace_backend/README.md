# MNT4 trace backend

This crate is the production-oriented off-chain compute source for MNT4-753 trace artifacts.
It replaces the previous Python -> anvil -> Solidity `PairingTraceWorker` oracle path for arithmetic and witness generation.
It computes MNT4-753 pairing trace artifacts with `arkworks` and writes deterministic JSON outputs for the later proof backend.

Boundary rule:

- use this crate for production-oriented off-chain arithmetic/witness generation;
- use `PairingTraceWorker` only as a Solidity test/reference harness;
- use Python stage6 scripts only as prototype orchestration around the harness.

Current P1 scope:

- fixed-Q single/multi artifacts with the arkworks MNT4-753 G2 generator as Q;
- parametric-Q artifacts, where Q may be supplied in Montgomery limb format;
- sparse line coefficient commitments compatible with the Solidity layout;
- Solidity-convention Miller digest (`no-inv` convention for the negative ate loop);
- final exponentiation chunks and public-input roots;
- JSON outputs: `trace.json`, `witness.json`, `public_inputs.json`, `proof_input.json`.

The final release pipeline consumes this crate directly through
`script/final_mnt4_pairing_release.py`: Rust writes `proof_input.json`, the proof
generator consumes that JSON, and the on-chain tests verify the resulting proof.

The current proof relation is a prepared algebraic/residue relation. It binds
the Rust-generated pairing digest, line-cache commitments, Miller trace
commitment, final-exponentiation commitment, point hash and Q hash without
replaying every non-native MNT4 field operation in-circuit.

## Default run

```bash
cargo run --offline -- --out-dir ../../cache/mnt4_trace_backend/default_fixed_q
```

## Request format

```json
{
  "mode": "parametric_q",
  "points": [],
  "q": null,
  "context": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "epoch": 1,
  "nonce": 0,
  "valid_until": 0,
  "fixed_q_id": null
}
```

If `points` is empty, the backend uses the canonical MNT4-753 G1 generator fixture. If `q` is absent in `parametric_q` mode, it uses the canonical MNT4-753 G2 generator fixture.

## Stage 4: Miller relation artifact

The backend now emits `MillerRelation` in addition to `LineCacheRelation`. The relation root binds:

- `pointsHash`, i.e. the submitted G1 inputs;
- `lineCacheRelationRoot`, i.e. the line cache already bound to Q;
- `millerDigest`, the shared-accumulator Miller output digest;
- `singlesDigest` and per-pair Miller digests for comparison paths;
- loop shape: number of Miller doubling rounds and addition steps.

The helper `validate_miller_relation(request, relation)` is an off-chain/reference validator: it rebuilds the artifact from the same request and rejects tampering. It is intentionally not an on-chain recomputation path.
