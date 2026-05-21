# Full on-chain MNT4 implementation

This folder contains the Solidity arithmetic and full on-chain MNT4-753 pairing baseline used to prove the impracticality of direct EVM execution.

Included contracts:

- `BigIntMNT.sol`
- `MNT4Extension.sol`
- `MNT4TatePairing.sol`
- `MNT4TatePairingArithmetic.sol`
- comparison arithmetic variants `BigIntMNTBarrett.sol`, `BigIntMNTFIOS.sol`

Run tests:

```bash
forge test --offline
```
