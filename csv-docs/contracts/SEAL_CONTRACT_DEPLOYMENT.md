# Seal Contract Deployment Requirements

## Overview

The CSV protocol requires deployed seal contracts on each supported chain to enable Sanad creation and consumption. This document outlines the deployment requirements for each chain.

## Chain-Specific Requirements

### Solana

**Status**: ✅ Configured with default program ID

The Solana adapter uses a default program ID that is already configured:

- **Program ID**: `CCMF6BvAyTPNJAPtGMVJAR652Hv9VPy9NmVdgC9969dj`
- **Config File**: `chains/solana-devnet.toml`
- **Contract Location**: `csv-contracts/solana/contracts/programs/csv-seal/`

**Deployment**:

```bash
cd csv-contracts/solana/contracts
NO_DNA=1 anchor build
anchor deploy --program-id CCMF6BvAyTPNJAPtGMVJAR652Hv9VPy9NmVdgC9969dj
```

### Sui

**Status**: ⚠️ Contract deployment required

The Sui adapter requires a deployed CSVSeal package. The package ID must be configured in the chain config.

**Configuration**:

- **Config File**: `chains/sui-testnet.toml`
- **Required Field**: `custom_settings.package_id`

**Deployment**:

```bash
cd csv-contracts/sui/contracts
sui move build
sui client publish --gas-budget 1000000000
```

After deployment, update `chains/sui-testnet.toml`:

```toml
[custom_settings]
package_id = "0x..."  # Replace with deployed package ID
```

**Error**: If you see "Seal object does not exist on-chain", the contract is not deployed.

### Aptos

**Status**: ⚠️ Contract deployment required

The Aptos adapter requires a deployed CSVSeal module. The module address must be configured in the chain config.

**Configuration**:

- **Config File**: `chains/aptos-testnet.toml`
- **Required Field**: `custom_settings.module_address`

**Deployment**:

```bash
cd csv-contracts/aptos/contracts
aptos move compile
aptos move publish --package-name csv_seal --assume-yes
```

After deployment, update `chains/aptos-testnet.toml`:

```toml
[custom_settings]
module_address = "0x..."  # Replace with deployed module address
```

**Error**: If you see "Seal resource does not exist on-chain", the contract is not deployed.

### Ethereum

**Status**: ⚠️ Contract deployment required

The Ethereum adapter requires a deployed CSV seal contract.

**Configuration**:

- **Config File**: `chains/ethereum-sepolia.toml`
- **Required Field**: `custom_settings.contract_address`

**Deployment**:

```bash
cd csv-contracts/ethereum/contracts
forge build
forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

### Bitcoin

**Status**: ✅ No contract required

Bitcoin uses UTXO-based seals and does not require a smart contract deployment.

## Verification

After deployment, verify the contract is accessible:

```bash
# Solana
solana program show CCMF6BvAyTPNJAPtGMVJAR652Hv9VPy9NmVdgC9969dj

# Sui
sui client object <package_id>

# Aptos
aptos account resource --account <module_address> --resource-type 0x1::code::Module
```

## Troubleshooting

### "Solana CSV program ID must be configured"

- Ensure `program_id` is set in `chains/solana-devnet.toml`
- Check that the CLI config includes the program_id field

### "Seal object does not exist on-chain" (Sui)

- Deploy the CSVSeal package using the commands above
- Update the package_id in the chain config
- Verify the package exists on-chain

### "Seal resource does not exist on-chain" (Aptos)

- Deploy the CSVSeal module using the commands above
- Update the module_address in the chain config
- Verify the module exists on-chain

## References

- Solana contracts: `csv-contracts/solana/contracts/`
- Sui contracts: `csv-contracts/sui/contracts/`
- Aptos contracts: `csv-contracts/aptos/contracts/`
- Ethereum contracts: `csv-contracts/ethereum/contracts/`
