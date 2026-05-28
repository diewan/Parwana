# Ethereum Contract Deployment Guide

This guide explains how to deploy the CSVSeal contract (merged lock + mint) to Sepolia testnet.

## Prerequisites

1. **Install Foundry**

   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. **Get Sepolia ETH**
   - Visit <https://sepoliafaucet.com/> to get testnet ETH
   - Or use <https://faucet.quicknode.com/ethereum/sepolia>

3. **Set Environment Variables**

   ```bash
   export SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_PROJECT_ID
   export DEPLOYER_KEY=0xyour_private_key_with_0x_prefix
   export ETHERSCAN_API_KEY=your_etherscan_api_key  # Optional, for verification
   ```

## Deployment Steps

### Option 1: Automated Deployment (Recommended)

Use the provided deployment script:

```bash
cd csv-contracts/ethereum
./scripts/deploy.sh
```

This script will:

1. Build the contracts
2. Deploy CSVSeal to Sepolia
3. Verify contract on Etherscan (if ETHERSCAN_API_KEY is set)
4. Update deployment-manifest.json with deployment details
5. Update chains/ethereum.toml with contract address

### Option 2: Manual Deployment

If you prefer manual deployment:

```bash
cd csv-contracts/ethereum/contracts

# Build contracts
forge build --sizes

# Deploy to Sepolia
forge script script/Deploy.s.sol \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $DEPLOYER_KEY \
  --broadcast \
  --verify \
  -vvv
```

After deployment, update the manifest:

```bash
cd ../scripts
cargo run --bin update_manifest -- <seal_address> <deployment_tx> <block_number>
```

## Post-Deployment Steps

1. **Verify Contract on Etherscan**
   - CSVSeal: <https://sepolia.etherscan.io/address/><SEAL_ADDRESS>

2. **Update Bytecode Hash**
   - Get the deployed bytecode from Etherscan
   - Compute the hash and update `deployment-manifest.json`

3. **Set Verifier Address**
   - If you have a trusted verifier contract, update the CSVSeal constructor args
   - Otherwise, the deployer address is used as the initial verifier

4. **Mark Contract as Verified**
   - Set `verified: true` in `deployment-manifest.json` after manual verification

## Configuration Files Updated

After deployment, the following files are automatically updated:

1. **deployments/deployment-manifest.json**
   - Contract address
   - Deployment transaction hash
   - Block number
   - Constructor arguments

2. **chains/ethereum.toml**
   - `contract_address`

## Troubleshooting

### Insufficient Balance

```text
Error: Insufficient balance. Please fund your account with Sepolia ETH
```

Solution: Get more Sepolia ETH from a faucet.

### Gas Price Too High

```text
Error: Transaction underpriced
```

Solution: Wait for gas prices to drop or increase gas price in foundry.toml.

### Verification Fails

```text
Error: Contract verification failed
```

Solution: Manually verify on Etherscan using the flattened source code.

## Security Notes

- Never commit private keys to version control
- Use environment variables for sensitive data
- Verify contract address before using in production
- Review contract bytecode after deployment
- Test on testnet before mainnet deployment
