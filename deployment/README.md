# Deployment framework (audit item 10)

Operator-facing deployment manifests and verification hooks.

## Layout

- `manifest.toml` — chain targets, contract addresses, finality depth
- `verify.sh` — post-deploy checks (ABI hash, event schema)

## Usage

```bash
./deployment/verify.sh --manifest deployment/manifest.toml
```
