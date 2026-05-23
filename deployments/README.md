# CSV Protocol Testnet Deployments

Governed deployment manifest for testnet contract and program anchors.

## Files

| File | Purpose |
|------|---------|
| `deployment-manifest.json` | Canonical addresses, bytecode hashes, deployment provenance |
| `../chains/*.toml` | Per-chain RPC, capabilities, and contract addresses |

## Updating After Deploy

**Ethereum (Sepolia):**

```bash
cd csv-contracts/ethereum
./scripts/deploy.sh
```

**Manifest only (existing addresses):**

```bash
cd csv-contracts/ethereum/scripts
cargo run --bin update_manifest -- <lock> <mint> <tx> <block>
```

Set `VERIFIER_ADDRESS` when updating CSVMint constructor args.

## Verification Checklist

- [ ] `bytecode_hash` populated from `deployments/artifacts/*.bin`
- [ ] `verified: true` after Etherscan / block explorer confirmation
- [ ] `chains/ethereum.toml` `lock_contract_address` / `mint_contract_address` match manifest
- [ ] `cargo test -p csv-core --test chains_load` passes
