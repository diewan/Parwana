# CSV Seal Sui Package

This package is the Sui on-chain counterpart for the `csv-sui` adapter.

It models a Sanad as an owned object. Consuming or locking a Sanad marks the object consumed and emits an event that the client-side verifier can bind to a checkpoint and transaction effects.

## Deploy

```bash
sui client publish --gas-budget 100000000
```

After publishing, set `seal_contract.package_id` in the Sui chain configuration to the published package id.
