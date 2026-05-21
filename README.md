# MNT4 Pairing Project Export

This export contains only the code needed for the final dissertation implementation.

## Structure

- `onchain_full/` - full Solidity MNT4-753 arithmetic and on-chain pairing baseline with tests.
- `offchain_verify/` - final architecture: Rust off-chain backend, succinct proof fixture, one public on-chain verifier entrypoint, and tests.
- `lib/forge-std/` - Foundry test dependency.

## Verify full on-chain baseline

```bash
cd onchain_full
forge test --offline
```

## Verify off-chain compute / on-chain verify architecture

```bash
cd offchain_verify
forge test --offline
cargo test --offline --manifest-path crates/mnt4_trace_backend/Cargo.toml
```

For the reproducible release pipeline, install `snarkjs` once in `offchain_verify`:

```bash
cd offchain_verify
npm install
python3 script/final_mnt4_pairing_release.py
```

The main public contract for deployment is:

```text
offchain_verify/src/final_mnt4_pairing/MNT4PairingFinal.sol
```
