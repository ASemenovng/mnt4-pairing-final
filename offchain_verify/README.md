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
