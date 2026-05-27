# CSV Protocol CLI Tutorial

> **Note:** This tutorial has been moved to the root of the repository. See `csv-cli-tutorial.md` for the latest version.

A comprehensive guide to using the CSV Protocol CLI for cross-chain Sanad management, proof generation, trust management, and content operations on testnet.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Chain Configuration](#chain-configuration)
3. [Wallet Management](#wallet-management)
4. [Sanad Operations](#sanad-operations)
5. [Proof Operations](#proof-operations)
6. [Cross-Chain Transfers](#cross-chain-transfers)
7. [Seal Operations](#seal-operations)
8. [Content Management](#content-management)
9. [Trust Management](#trust-management)
10. [Runtime Monitoring](#runtime-monitoring)
11. [Validation & Inspection](#validation--inspection)
12. [Schema Tooling](#schema-tooling)
13. [End-to-End Testing](#end-to-end-testing)
14. [Complete Workflow Example](#complete-workflow-example)

---

## Getting Started

### Prerequisites

- Rust 1.93+ installed
- Access to testnet RPC endpoints (configured by default)
- Basic understanding of blockchain concepts

### Installation

```bash
# Build the CLI
CXXFLAGS="-include cstdint" cargo build -p csv-cli --release

# The binary will be at target/release/csv
cp target/release/csv ~/.local/bin/csv
```

### First Run

When you run `csv` for the first time, you'll be prompted for:

- **Passphrase**: Used to encrypt your state file at `~/.csv/unified_storage.json`
- **Configuration**: Default testnet settings are loaded from `~/.csv/config.toml`

```bash
csv chain list
```

You'll see output like:

```
═══════════════════════════════════════════════════════════════
Chain List
═══════════════════════════════════════════════════════════════
  Chain            Network    RPC URL                                      Finality    Contract
  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  bitcoin          test       https://mempool.space/signet/api/            6           N/A
  ethereum         test       https://ethereum-sepolia-rpc.publicnode.com  15          0xac1E3Bd5...
  sui              test       https://fullnode.testnet.sui.io:443          1           N/A
  aptos            test       https://fullnode.testnet.aptoslabs.com/v1    1           N/A
  solana           test       https://api.devnet.solana.com                32          N/A
```

### Global Flags

All commands support these global flags:

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Enable debug logging |
| `--canonical` | | Emit canonical CBOR (hex) instead of pretty JSON |
| `--proof-tree` | | Emit proof DAG/Merkle tree structure for proof commands |
| `--config` | `-C` | Config file path (default: `~/.csv/config.toml`) |

Example:

```bash
csv --verbose wallet list
csv --canonical proof verify --chain ethereum --proof-file proof.json
```

---

## Chain Configuration

### List All Chains

```bash
csv chain list
```

### Check Chain Status

```bash
csv chain status --chain ethereum
```

Output:

```
═══════════════════════════════════════════════════════════════
Ethereum Status
═══════════════════════════════════════════════════════════════
  Chain            ethereum
  Network          test (Sepolia)
  RPC URL          https://ethereum-sepolia-rpc.publicnode.com
  Chain ID         11155111
  Finality Depth   15
  Default Fee      20 gwei
  Contract         0xac1E3Bd5FB767C6B6b23Ac19309FF3d1739D0fD2
  RPC Connected    Yes
```

### Set Custom RPC URL

```bash
csv chain set-rpc --chain ethereum https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
```

### Set Contract Address

```bash
csv chain set-contract --chain ethereum 0x70A035318c72C3dAa21F47Dd0f6A1C8633a05820
```

### Change Network

```bash
csv chain set-network --chain ethereum --network main
```

---

## Wallet Management

### Initialize Wallet (One-Command Setup)

This generates a BIP-39 mnemonic, derives keys for all 5 chains, and stores everything encrypted:

```bash
csv wallet init --network test --words 12
```

Output:

```
═══════════════════════════════════════════════════════════════
Wallet Initialization
═══════════════════════════════════════════════════════════════
  Network          test
  Words            12
  Account          0
  ─────────────────────────────────────────────────────────────
  Bitcoin (signet)  tb1p...[Taproot address]
  Ethereum (sepolia)  0x...[Address]
  Sui (testnet)     0x...[Address]
  Aptos (testnet)   0x...[Address]
  Solana (devnet)   [Base58 address]
  ─────────────────────────────────────────────────────────────
  ✓ Wallet initialized and stored encrypted
  ✓ Config saved to ~/.csv/config.toml
```

### Import Existing Wallet

```bash
csv wallet import "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --network test
```

### Export Wallet (View Mnemonic)

```bash
csv wallet export
```

Output:

```
═══════════════════════════════════════════════════════════════
Wallet Export
═══════════════════════════════════════════════════════════════
  SECRET  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
  WARNING Store this securely and never share it!
```

### Generate Wallet for Specific Chain

```bash
csv wallet generate --chain bitcoin --network test
```

### Check Wallet Balance

```bash
csv wallet balance --chain ethereum
```

Output:

```
═══════════════════════════════════════════════════════════════
Ethereum Balance
═══════════════════════════════════════════════════════════════
  Address          0x1234...5678
  Balance          1.5 ETH
  Balance (Wei)    1500000000000000000
```

### List All Wallet Addresses

```bash
csv wallet list
```

Output:

```
═══════════════════════════════════════════════════════════════
Wallet Addresses
═══════════════════════════════════════════════════════════════
  Chain            Network    Address
  ─────────────────────────────────────────────────────────────
  bitcoin          test       tb1p...[Taproot]
  ethereum         test       0x1234...5678
  sui              test       0xabcdef...123456
  aptos            test       0x9876...fedc
  solana           test       [Base58 address]
```

### View Private Key (Use with Caution)

```bash
csv wallet private-key --chain ethereum
```

Output:

```
═══════════════════════════════════════════════════════════════
Private Key
═══════════════════════════════════════════════════════════════
  SECRET  0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  WARNING This key provides full control over your wallet!
```

---

## Sanad Operations

### Create a Sanad

A Sanad is a cryptographic seal representing value on a chain. Create one on Bitcoin testnet:

```bash
csv sanad create --chain bitcoin --value 100000
```

Output:

```
═══════════════════════════════════════════════════════════════
Create Sanad
═══════════════════════════════════════════════════════════════
  Chain            bitcoin
  Value            100000 satoshi
  ─────────────────────────────────────────────────────────────
  [1/4] Creating seal...
  [2/4] Generating commitment...
  [3/4] Broadcasting to network...
  [4/4] Waiting for finality...
  ─────────────────────────────────────────────────────────────
  ✓ Sanad created successfully
  Sanad ID         0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  Seal Ref         0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  Status           Pending finality
```

### Show Sanad Details

```bash
csv sanad show 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

Output:

```
═══════════════════════════════════════════════════════════════
Sanad Details
═══════════════════════════════════════════════════════════════
  Sanad ID         0xabcdef...7890
  Chain            bitcoin
  Value            100000 satoshi
  Seal Ref         0x1234...5678
  Status           Confirmed
  Created          2024-01-15 10:30:00 UTC
  Owner            0x1234...5678
```

### List All Sanads

```bash
csv sanad list
csv sanad list --chain ethereum
```

Output:

```
═══════════════════════════════════════════════════════════════
Sanad List
═══════════════════════════════════════════════════════════════
  Sanad ID         Chain      Value        Status
  ─────────────────────────────────────────────────────────────
  0xabcdef...7890  bitcoin    100000 sat   Confirmed
  0x123456...abcd  ethereum   1.5 ETH      Confirmed
  0xfedcba...9876  sui        1000 MIST    Pending
```

### Transfer a Sanad

```bash
csv sanad transfer 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 bcrt1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
```

### Consume a Sanad

```bash
csv sanad consume 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

---

## Proof Operations

### Generate a Proof

Generate an inclusion proof for a Sanad on Ethereum:

```bash
csv proof generate --chain ethereum 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 -o proof.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Generate Proof
═══════════════════════════════════════════════════════════════
  Chain            ethereum
  Sanad ID         0xabcdef...7890
  ─────────────────────────────────────────────────────────────
  [1/3] Fetching block data...
  [2/3] Building Merkle Patricia Trie proof...
  [3/3] Saving proof bundle...
  ─────────────────────────────────────────────────────────────
  ✓ Proof generated and saved to proof.json
```

View the proof:

```bash
cat proof.json
```

Output:

```json
{
  "seal_ref": {
    "id": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  },
  "anchor_ref": {
    "anchor_id": "0xabcdef...1234",
    "block_height": 4567890,
    "metadata": "ethereum"
  },
  "inclusion_proof": {
    "key": "...",
    "value": "...",
    "proof": ["0x...", "0x..."],
    "root_hash": "0x..."
  },
  "transition_dag": {
    "nodes": [...]
  },
  "proof_type": "mpt",
  "signature_scheme": "secp256k1"
}
```

### Verify a Proof

Verify the proof on the destination chain (Sui testnet):

```bash
csv proof verify --chain sui --proof-file proof.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Verify Proof on Sui
═══════════════════════════════════════════════════════════════
  Proof Chain      ethereum
  Proof Type       mpt
  ─────────────────────────────────────────────────────────────
  [1/3] Parsing proof bundle...
  [2/3] Verifying cryptographic proof...
  [3/3] Checking seal registry...
  ─────────────────────────────────────────────────────────────
  Verification Level  high
  ✓ Proof is valid
```

### Verify Cross-Chain Proof

```bash
csv proof verify-cross-chain --source ethereum --dest sui proof.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Cross-Chain Proof Verification
═══════════════════════════════════════════════════════════════
  Source Chain       ethereum
  Destination Chain  sui
  ─────────────────────────────────────────────────────────────
  [1/4] Validating source chain proof...
  [2/4] Checking seal consumption...
  [3/4] Verifying destination chain compatibility...
  [4/4] Generating explorer links...
  ─────────────────────────────────────────────────────────────
  Explorer Links:
    Seal ID          https://sepolia.etherscan.io/tx/0x1234...5678
    Anchor Block     https://sepolia.etherscan.io/block/4567890
    Destination      https://suiscan.xyz/testnet
  ✓ Cross-chain proof is valid
```

### Generate Proof with Canonical CBOR

```bash
csv --canonical proof generate --chain bitcoin 0xabcdef... -o proof.cbor
```

### Generate Proof with Proof Tree Structure

```bash
csv --proof-tree proof generate --chain ethereum 0xabcdef... -o proof-tree.json
```

---

## Cross-Chain Transfers

### Initiate a Cross-Chain Transfer

Transfer a Sanad from Bitcoin to Sui:

```bash
csv cross-chain transfer --from bitcoin --to sui --sanad-id 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 --dest-owner 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678
```

Output:

```
═══════════════════════════════════════════════════════════════
Cross-Chain Transfer
═══════════════════════════════════════════════════════════════
  From             bitcoin (signet)
  To               sui (testnet)
  Sanad ID         0xabcdef...7890
  Dest Owner       0x1234...5678
  ─────────────────────────────────────────────────────────────
  [1/5] Locking Sanad on Bitcoin...
  [2/5] Waiting for finality (6 confirmations)...
  [3/5] Generating proof bundle...
  [4/5] Verifying on Sui...
  [5/5] Minting destination Sanad...
  ─────────────────────────────────────────────────────────────
  ✓ Transfer initiated successfully
  Transfer ID      0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
  Status           Processing
  Estimated Time   30-60 minutes
```

### Check Transfer Status

```bash
csv cross-chain status 0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

Output:

```
═══════════════════════════════════════════════════════════════
Transfer Status
═══════════════════════════════════════════════════════════════
  Transfer ID      0xfedcba...3210
  Status           Completed
  From             bitcoin (signet)
  To               sui (testnet)
  Sanad ID         0xabcdef...7890
  Dest Owner       0x1234...5678
  Created          2024-01-15 10:30:00 UTC
  Completed        2024-01-15 11:15:00 UTC
  Fee              10 sat/vB
  ─────────────────────────────────────────────────────────────
  ✓ Transfer completed successfully
```

### List All Transfers

```bash
csv cross-chain list
csv cross-chain list --from bitcoin
csv cross-chain list --to sui
```

Output:

```
═══════════════════════════════════════════════════════════════
Transfer List
═══════════════════════════════════════════════════════════════
  Transfer ID      From       To         Sanad ID           Status
  ────────────────────────────────────────────────────────────────────────────────────────
  0xfedcba...3210  bitcoin    sui        0xabcdef...7890    Completed
  0x123456...abcd  ethereum   aptos      0xfedcba...9876    Processing
  0xabcdef...1234  sui        ethereum   0x111111...222222  Pending
```

### Retry a Failed Transfer

```bash
csv cross-chain retry 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef5678
```

---

## Seal Operations

### Create a Seal

```bash
csv seal create --chain ethereum --value 1000000000000000000
```

Output:

```
═══════════════════════════════════════════════════════════════
Create Seal
═══════════════════════════════════════════════════════════════
  Chain            ethereum
  Value            1000000000000000000 wei (1 ETH)
  ─────────────────────────────────────────────────────────────
  [1/3] Creating seal...
  [2/3] Broadcasting to network...
  [3/3] Waiting for finality...
  ─────────────────────────────────────────────────────────────
  ✓ Seal created successfully
  Seal Ref         0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  Status           Confirmed
```

### Consume a Seal

```bash
csv seal consume --chain ethereum 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Verify a Seal

```bash
csv seal verify --chain ethereum 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

Output:

```
═══════════════════════════════════════════════════════════════
Seal Verification
═══════════════════════════════════════════════════════════════
  Seal Ref         0x1234...5678
  Chain            ethereum
  Status           Unconsumed
  Created          2024-01-15 10:30:00 UTC
  ─────────────────────────────────────────────────────────────
  ✓ Seal is available for consumption
```

### List Consumed Seals

```bash
csv seal list
csv seal list --chain bitcoin
```

---

## Content Management

### Create a Content Tree

Create a Merkleized content tree from a file with one leaf per line:

```bash
# Create input file with leaf data
echo -e "Hello World\nThis is a test\nContent tree example" > leaves.txt

# Create the content tree
csv content create --input leaves.txt --output content-tree.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Create Content Tree
═══════════════════════════════════════════════════════════════
  [1/4] Processing 3 leaves...
  [2/4] Building Merkle tree...
  [3/4] Computing root hash...
  [4/4] Saving content tree...
  ─────────────────────────────────────────────────────────────
  ✓ Content tree saved to content-tree.json
  Root Hash        0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  Leaf Count       3
  Tree Depth       2
  Verification CPU 150
  Verification Memory 2048 bytes

  Content Addresses:
    Leaf 0: 0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
    Leaf 1: 0xe7b122f4c9a3e5f6d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1
    Leaf 2: 0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7
```

### Generate a Merkle Proof

Generate a proof for leaf index 1:

```bash
csv content prove --tree content-tree.json --index 1
```

Output:

```
═══════════════════════════════════════════════════════════════
Generate Merkle Proof
═══════════════════════════════════════════════════════════════
  [1/3] Loading content tree...
  [2/3] Generating proof for leaf 1...
  [3/3] Proof generated
  ─────────────────────────────────────────────────────────────
  Tree Root        0xabcdef...7890
  Leaf Count       3
  Proof Valid      Yes

  {
    "leaf_index": 1,
    "leaf_hash": "0xe7b122f4c9a3e5f6d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1",
    "siblings": [
      "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
      "0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7"
    ],
    "root_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  }
```

### Verify a Content Tree

```bash
csv content verify --tree content-tree.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Verify Content Tree
═══════════════════════════════════════════════════════════════
  [1/3] Loading content tree...
  [2/3] Verifying tree structure...
  ─────────────────────────────────────────────────────────────
  Tree Root        0xabcdef...7890
  Leaf Count       3
  Tree Depth       2
  ✓ Tree structure is valid
```

Verify with leaf inclusion:

```bash
csv content verify --tree content-tree.json --leaf "This is a test" --leaf-index 1
```

Output:

```
═══════════════════════════════════════════════════════════════
Verify Content Tree
═══════════════════════════════════════════════════════════════
  [1/3] Loading content tree...
  [2/3] Verifying tree structure...
  [3/3] Verifying leaf inclusion...
  ─────────────────────────────────────────────────────────────
  Tree Root        0xabcdef...7890
  Leaf Count       3
  Tree Depth       2
  Leaf Index       1
  Inclusion Verified  Yes
  ✓ Leaf is included in the tree
```

### Encrypt a Subtree

```bash
csv content encrypt --tree content-tree.json --key-id my-encryption-key --algorithm aes-256-gcm
```

Output:

```
═══════════════════════════════════════════════════════════════
Encrypt Content Subtree
═══════════════════════════════════════════════════════════════
  [1/3] Loading content tree...
  [2/3] Creating encryption descriptor...
  [3/3] Encrypting subtree...
  ─────────────────────────────────────────────────────────────
  Tree Root        0xabcdef...7890
  ✓ Encryption descriptor created
  Algorithm        aes-256-gcm
  Key ID           my-encryption-key

  {
    "ciphertext": [],
    "tag": [],
    "descriptor": {
      "algorithm": "aes-256-gcm",
      "key_id": "my-encryption-key",
      "nonce": "000000000000000000000000",
      "aad": []
    }
  }
```

### Create Selective Disclosure Proof

```bash
csv content disclose --tree content-tree.json --include 0,2
```

Output:

```
═══════════════════════════════════════════════════════════════
Selective Disclosure
═══════════════════════════════════════════════════════════════
  [1/3] Loading content tree...
  [2/3] Generating disclosure proofs...
  [3/3] Disclosure proofs generated
  ─────────────────────────────────────────────────────────────
  Tree Root        0xabcdef...7890
  Leaves to Disclose 2
  ✓ 2 disclosure proof(s) generated

  {
    "subtree_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "inclusion_proof": {
      "leaf_index": 0,
      "leaf_hash": "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
      "siblings": [...],
      "root_hash": "0xabcdef..."
    }
  }
```

### Add Attachment Reference

```bash
csv content attach add --tree content-tree.json --file document.pdf --media-type pdf
```

Output:

```
═══════════════════════════════════════════════════════════════
Add Attachment Reference
═══════════════════════════════════════════════════════════════
  File             document.pdf
  Media Type       pdf
  Size             123456
  Content Hash     0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7
  ✓ Attachment reference created
```

### Add Participant

```bash
csv content participants add --tree content-tree.json --key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678 --role creator
```

Output:

```
═══════════════════════════════════════════════════════════════
Add Participant
═══════════════════════════════════════════════════════════════
  Participant ID   0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  Role             creator
  Public Key       0x1234...5678
  ✓ Participant created
```

### Create Content Claim

```bash
csv content claims create --tree content-tree.json --predicate authentic --description "This content was created by Alice and verified on 2024-01-15"
```

Output:

```
═══════════════════════════════════════════════════════════════
Create Content Claim
═══════════════════════════════════════════════════════════════
  Predicate        authentic
  Description      This content was created by Alice and verified on 2024-01-15

  {
    "predicate": "authentic",
    "description": "This content was created by Alice and verified on 2024-01-15"
  }

  ✓ Claim created
```

---

## Trust Management

### Check Trust Package Status

```bash
csv trust status
```

Output:

```
═══════════════════════════════════════════════════════════════
Trust Package Status
═══════════════════════════════════════════════════════════════
  Version          1
  Genesis Hash     0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  Trusted Checkpoint Height  1000000
  Trusted Checkpoint Hash    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  Validator Epoch  5
  Validator Count  21
  Created          30 days
  Expires          335 days
  Signature        0xabcdef12...3456
  Signers          5 multi-sig
  ─────────────────────────────────────────────────────────────
  ✓ Trust package is valid
```

### Export Trust Package

```bash
csv trust export -o my-trust-package.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Export Trust Package
═══════════════════════════════════════════════════════════════
  ✓ Trust package exported to my-trust-package.json
  Genesis          0xabcdef...7890
  Checkpoint       1000000 (0x1234...5678)
```

### Import Trust Package

```bash
csv trust import my-trust-package.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Import Trust Package
═══════════════════════════════════════════════════════════════
  [1/3] Verifying signature...
  [2/3] Checking signer identities...
  [3/3] Validating against known authority set...
  ✓ Signature verified
  ✓ Trust package imported successfully
  Genesis          0xabcdef...7890
  Checkpoint       1000000 (0x1234...5678)
  Validators       21 (epoch 5)
  Valid For        335 hours
```

### Verify Trust Package

```bash
csv trust verify my-trust-package.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Verify Trust Package
═══════════════════════════════════════════════════════════════
  [1/4] Parsing trust package...
  [2/4] Checking validity...
  [3/4] Checking structure...
  [4/4] Verifying signature...
  ─────────────────────────────────────────────────────────────
  Version          1
  Genesis          0xabcdef...7890
  ✓ Package is not expired
  ✓ Structure is valid
  ✓ Signature present
  ✓ Trust package is valid
```

### Rotate Trust Checkpoint

```bash
csv trust rotate 1000100 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

Output:

```
═══════════════════════════════════════════════════════════════
Rotate Trust Checkpoint
═══════════════════════════════════════════════════════════════
  [1/3] Validating new checkpoint...
  [2/3] Updating trust package...
  [3/3] Saving new trust package...
  ─────────────────────────────────────────────────────────────
  ✓ Trust checkpoint rotated successfully
  Old Checkpoint   1000000 (0x1234...5678)
  New Checkpoint   1000100 (0xabcdef...1234)
```

---

## Runtime Monitoring

### Check Runtime Status

```bash
csv runtime status
```

Output:

```
═══════════════════════════════════════════════════════════════
Runtime Status
═══════════════════════════════════════════════════════════════
  Health           Healthy
  Mode             Normal
  Circuit Breaker  Closed (normal)
  ─────────────────────────────────────────────────────────────
  ✓ Runtime is operating normally
```

### Check Component Health

```bash
csv runtime health
```

Output:

```
═══════════════════════════════════════════════════════════════
Component Health Checks
═══════════════════════════════════════════════════════════════
  Component        Status                    Error
  ────────────────────────────────────────────────────────────────────────
  RPC Providers    Healthy
  Quorum           Healthy
  Replay Registry  Healthy
  Event Persistence  Healthy
  Clock Drift      Healthy
  Trust Packages   Healthy
  ────────────────────────────────────────────────────────────────
  ✓ All components healthy
```

### Check Admission Control

```bash
csv runtime admission
```

Output:

```
═══════════════════════════════════════════════════════════════
Admission Control
═══════════════════════════════════════════════════════════════
  Max In-Flight Transfers  128
  Max In-Flight Per Chain  32
  Current In-Flight        5

  In-Flight by Chain:
    bitcoin:              2
    ethereum:             2
    sui:                  1

  Capacity Utilization   3.9%
  ────────────────────────────────────────────────────────────────
  ✓ Admission capacity healthy
```

### List Runtime Events

```bash
csv runtime events --count 10
```

Output:

```
═══════════════════════════════════════════════════════════════
Runtime Events
═══════════════════════════════════════════════════════════════
  Runtime event streaming requires a running runtime instance
  Events are published to the EventBus and can be queried via the runtime API

  Event Types:
    TransferPhaseEntered — A transfer entered a new phase
    TransferPhaseCompleted — A transfer phase completed
    TransferPhaseFailed — A transfer phase failed
    LeaseAcquired — A transfer lease was acquired
    LeaseReleased — A transfer lease was released
    CircuitBreakerOpen — A circuit breaker opened
    CircuitBreakerClosed — A circuit breaker closed
    AdmissionRejected — A transfer was rejected by admission control
```

---

## Validation & Inspection

### Validate a Consignment

```bash
csv validate consignment consignment.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Validating Consignment
═══════════════════════════════════════════════════════════════
  [1/4] Checking consignment structure...
  [2/4] Verifying commitment chain...
  [3/4] Checking seal consumption...
  [4/4] Validating state transitions...
  ────────────────────────────────────────────────────────────────
  ✓ Consignment is valid
```

### Validate a Proof

```bash
csv validate proof proof.json --chain ethereum
```

### Validate Seal Consumption

```bash
csv validate seal 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

Output:

```
═══════════════════════════════════════════════════════════════
Validating Seal Consumption
═══════════════════════════════════════════════════════════════
  Seal             0x1234...5678
  Status           Unconsumed
  ────────────────────────────────────────────────────────────────
  ✓ Seal is available for consumption
```

### Offline Proof Verification

```bash
csv validate offline --file proof.json
```

Output:

```
═══════════════════════════════════════════════════════════════
Offline Proof Verification
═══════════════════════════════════════════════════════════════
  [1/5] Parsing proof bundle...
  [2/5] Verifying proof structure...
  [3/5] Performing cryptographic verification...
  [4/5] Generating explorer links...
  [5/5] Verification complete
  ────────────────────────────────────────────────────────────────
  Seal Ref         0x1234...5678
  Source Chain     ethereum
  Destination Chain  sui
  Verification Level  high
  Explorer Links:
    Seal ID          https://sepolia.etherscan.io/tx/0x1234...5678
    Anchor Block     https://sepolia.etherscan.io/block/4567890
    Destination      https://suiscan.xyz/testnet
  ✓ Proof bundle is cryptographically valid
  ✓ Offline verification successful
```

### Inspect Replay Registry

```bash
csv inspect replay --id 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

### Inspect Merkle Root

```bash
csv inspect merkle --root 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

---

## Schema Tooling

### Validate a Schema

```bash
csv schema validate --file schema.json
```

### Compile a Schema

```bash
csv schema compile --file schema.json --out compiled-schema.cbor
```

### Diff Two Schemas

```bash
csv schema diff --left schema-v1.json --right schema-v2.json
```

---

## End-to-End Testing

### Run Tests for a Specific Chain Pair

```bash
csv test run --chain-pair bitcoin:sui
```

Output:

```
═══════════════════════════════════════════════════════════════
Running Test: bitcoin -> sui
═══════════════════════════════════════════════════════════════
  [1/6] Initializing test environment...
  [2/6] Creating source Sanad on Bitcoin...
  [3/6] Generating proof bundle...
  [4/6] Verifying on Sui...
  [5/6] Minting destination Sanad...
  [6/6] Verifying final state...
  ────────────────────────────────────────────────────────────────
  ✓ Test passed: bitcoin -> sui
```

### Run All Tests

```bash
csv test run-all
```

Output:

```
═══════════════════════════════════════════════════════════════
Running All Tests (9 chain pairs)
═══════════════════════════════════════════════════════════════
  Test                   Status    Duration
  ────────────────────────────────────────────────────────────────
  bitcoin -> sui         ✓ Pass    45s
  bitcoin -> ethereum    ✓ Pass    60s
  bitcoin -> aptos       ✓ Pass    55s
  sui -> ethereum        ✓ Pass    30s
  sui -> aptos           ✓ Pass    25s
  ethereum -> sui        ✓ Pass    35s
  ethereum -> aptos      ✓ Pass    40s
  aptos -> sui           ✓ Pass    20s
  aptos -> ethereum      ✓ Pass    30s
  ────────────────────────────────────────────────────────────────
  ✓ All 9 tests passed (6:15 total)
```

### Run a Specific Scenario

```bash
csv test scenario double_spend
```

### View Test Results

```bash
csv test results
```

---

## Complete Workflow Example

Here's a complete end-to-end workflow demonstrating the full CSV Protocol CLI capabilities on testnet:

### Step 1: Initialize Your Wallet

```bash
# Generate a new wallet with 12-word mnemonic
csv wallet init --network test --words 12
```

Save your mnemonic phrase securely! This is the only way to recover your wallet.

### Step 2: Fund Your Wallets

Get testnet tokens from faucets:

- **Bitcoin Signet**: <https://bitcoin-signet.com/faucet-to-url>
- **Ethereum Sepolia**: <https://sepoliafaucet.com>
- **Sui Testnet**: <https://docs.sui.io/build/testnet>
- **Aptos Testnet**: <https://aptos.dev/networks/testnet>
- **Solana Devnet**: <https://faucet.solana.com>

### Step 3: Check Your Balances

```bash
csv wallet list
csv wallet balance --chain ethereum
csv wallet balance --chain bitcoin
```

### Step 4: Create a Sanad

```bash
# Create a Sanad on Ethereum (representing 1 ETH)
csv sanad create --chain ethereum --value 1000000000000000000
```

Note the Sanad ID from the output.

### Step 5: Generate a Proof

```bash
# Generate an inclusion proof for your Sanad
csv proof generate --chain ethereum <SANAD_ID> -o proof.json
```

### Step 6: Create a Content Tree

```bash
# Create a content tree with metadata about your Sanad
echo -e "Sanad ID: <SANAD_ID>\nValue: 1 ETH\nChain: Ethereum" > sanad-metadata.txt
csv content create --input sanad-metadata.txt --output sanad-content.json
```

### Step 7: Generate a Content Proof

```bash
# Generate a Merkle proof for the Sanad ID leaf
csv content prove --tree sanad-content.json --index 0
```

### Step 8: Set Up Trust

```bash
# Check your trust package status
csv trust status

# If you have a trust package from a trusted source, import it
csv trust import trusted-trust-package.json
```

### Step 9: Initiate a Cross-Chain Transfer

```bash
# Transfer your Sanad from Ethereum to Sui
csv cross-chain transfer \
  --from ethereum \
  --to sui \
  --sanad-id <SANAD_ID> \
  --dest-owner 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678
```

### Step 10: Monitor the Transfer

```bash
# Check transfer status
csv cross-chain status <TRANSFER_ID>

# Check runtime health
csv runtime status
csv runtime health
```

### Step 11: Verify the Cross-Chain Proof

```bash
# Verify the proof on the destination chain
csv proof verify-cross-chain --source ethereum --dest sui proof.json
```

### Step 12: Validate Everything

```bash
# Validate the proof
csv validate proof proof.json --chain sui

# Validate seal consumption
csv validate seal <SEAL_REF>

# Offline verification
csv validate offline --file proof.json
```

### Step 13: Check Final Status

```bash
# List all your Sanads
csv sanad list

# List all your transfers
csv cross-chain list

# Check runtime admission
csv runtime admission
```

---

## Troubleshooting

### Common Issues

**RPC Connection Failed**

```bash
# Check chain status
csv chain status --chain ethereum

# Set a different RPC URL
csv chain set-rpc --chain ethereum https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
```

**Transfer Stuck**

```bash
# Check runtime health
csv runtime health

# Check admission control
csv runtime admission

# Retry the transfer
csv cross-chain retry <TRANSFER_ID>
```

**Trust Package Expired**

```bash
# Check trust status
csv trust status

# Import a new trust package
csv trust import new-trust-package.json
```

**Proof Verification Failed**

```bash
# Verify offline
csv validate offline --file proof.json

# Check seal consumption
csv validate seal <SEAL_REF>
```

---

## Next Steps

- Explore the code examples in `csv-examples/`
- Run the full test suite: `csv test run-all`
- Read the protocol documentation in `csv-docs/`
- Contribute to the project: <https://github.com/Diewan/csv-protocol>
