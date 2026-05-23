# Canonical Event Schema

This document defines the canonical event schema that all chain implementations MUST follow. Events are the primary interface between on-chain contracts and off-chain verification.

## Canonical Event Types

### 1. SanadCreated

Emitted when a new Sanad is created on a chain.

**Canonical Fields:**
- `sanad_id: [u8; 32]` - Unique identifier for the Sanad
- `commitment: [u8; 32]` - Commitment hash
- `owner: Address` - Owner address (chain-specific encoding)
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event SanadCreated(bytes32 sanad_id, bytes32 commitment, address indexed owner, uint256 timestamp)`
- **Solana**: Account data + CPI log
- **Bitcoin**: OP_RETURN with encoded data
- **Sui**: Event in Move
- **Aptos**: Event in Move

### 2. SanadConsumed

Emitted when a Sanad is consumed (locked for cross-chain transfer).

**Canonical Fields:**
- `sanad_id: [u8; 32]` - Sanad identifier
- `nullifier: [u8; 32]` - Nullifier for replay protection
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event SanadConsumed(bytes32 sanad_id, bytes32 nullifier, uint256 timestamp)`
- **Solana**: Account data update + CPI log
- **Bitcoin**: OP_RETURN with nullifier
- **Sui**: Event in Move
- **Aptos**: Event in Move

### 3. CrossChainLock

Emitted when a Sanad is locked for cross-chain transfer.

**Canonical Fields:**
- `sanad_id: [u8; 32]` - Sanad identifier
- `source_chain: String` - Source chain ID
- `destination_chain: String` - Destination chain ID
- `commitment: [u8; 32]` - Commitment hash
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event CrossChainLock(bytes32 sanad_id, string source_chain, string destination_chain, bytes32 commitment, uint256 timestamp)`
- **Solana**: CPI log with encoded data
- **Bitcoin**: OP_RETURN with encoded lock
- **Sui**: Event in Move
- **Aptos**: Event in Move

### 4. CrossChainMint

Emitted when a Sanad is minted on the destination chain after proof verification.

**Canonical Fields:**
- `sanad_id: [u8; 32]` - Sanad identifier
- `commitment: [u8; 32]` - Commitment hash
- `owner: Address` - Owner address
- `source_chain: String` - Source chain ID
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event CrossChainMint(bytes32 sanad_id, bytes32 commitment, address indexed owner, string source_chain, uint256 timestamp)`
- **Solana**: Token mint + CPI log
- **Bitcoin**: Not applicable (no minting)
- **Sui**: Object creation + Event
- **Aptos**: Resource mint + Event

### 5. CrossChainRefund

Emitted when a cross-chain transfer is refunded (proof verification failed or timeout).

**Canonical Fields:**
- `sanad_id: [u8; 32]` - Sanad identifier
- `commitment: [u8; 32]` - Commitment hash
- `reason: String` - Refund reason
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event CrossChainRefund(bytes32 sanad_id, bytes32 commitment, string reason, uint256 timestamp)`
- **Solana**: Token burn + CPI log
- **Bitcoin**: Not applicable (no refunds)
- **Sui**: Object deletion + Event
- **Aptos**: Resource burn + Event

### 6. NullifierRegistered

Emitted when a nullifier is registered for replay protection.

**Canonical Fields:**
- `nullifier: [u8; 32]` - Nullifier hash
- `sanad_id: [u8; 32]` - Associated Sanad ID
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event NullifierRegistered(bytes32 nullifier, bytes32 sanad_id, uint256 timestamp)`
- **Solana**: Account data update
- **Bitcoin**: OP_RETURN with nullifier
- **Sui**: Event in Move
- **Aptos**: Event in Move

### 7. ProofAccepted

Emitted when a proof is successfully verified.

**Canonical Fields:**
- `proof_root: [u8; 32]` - Proof bundle root hash
- `protocol_version: String` - Protocol version
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event ProofAccepted(bytes32 proof_root, string protocol_version, uint256 timestamp)`
- **Solana**: CPI log
- **Bitcoin**: Not applicable (no on-chain verification)
- **Sui**: Event in Move
- **Aptos**: Event in Move

### 8. ProofRejected

Emitted when a proof is rejected.

**Canonical Fields:**
- `proof_root: [u8; 32]` - Proof bundle root hash
- `reason: String` - Rejection reason
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event ProofRejected(bytes32 proof_root, string reason, uint256 timestamp)`
- **Solana**: CPI log
- **Bitcoin**: Not applicable
- **Sui**: Event in Move
- **Aptos**: Event in Move

### 9. ReplayDetected

Emitted when a replay attack is detected.

**Canonical Fields:**
- `replay_id: [u8; 32]` - Replay identifier
- `sanad_id: [u8; 32]` - Associated Sanad ID
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event ReplayDetected(bytes32 replay_id, bytes32 sanad_id, uint256 timestamp)`
- **Solana**: CPI log
- **Bitcoin**: Not applicable
- **Sui**: Event in Move
- **Aptos**: Event in Move

## Encoding Rules

### Address Encoding

Each chain uses its native address encoding:
- **Ethereum**: 20-byte address (0x-prefixed hex)
- **Solana**: 32-byte public key (base58)
- **Bitcoin**: 20-byte hash (base58check)
- **Sui**: 32-byte address (bech32)
- **Aptos**: 32-byte address (hex)

### Hash Encoding

All hashes are 32 bytes, represented as:
- **Solidity**: `bytes32`
- **Move**: `vector<u8>` of length 32
- **Bitcoin**: 32-byte hex

### Timestamp Encoding

Timestamps are Unix epoch seconds:
- **Solidity**: `uint256`
- **Move**: `u64`
- **Bitcoin**: 4-byte little-endian

### String Encoding

Strings are UTF-8 encoded:
- **Solidity**: `string`
- **Move**: `string`
- **Bitcoin**: Not applicable (use numeric IDs)

## Event Indexing

For chains that support indexed event parameters:
- **Ethereum**: Index `sanad_id`, `owner`, `nullifier` for efficient querying
- **Solana**: Use CPI logs with indexed data
- **Sui**: Use event indexing
- **Aptos**: Use event indexing

## Backward Compatibility

Event schema changes require:
1. Protocol version bump
2. RFC approval
3. Migration path for existing deployments
4. Dual-event emission during transition period

## Implementation Checklist

For each chain implementation:
- [ ] All 9 canonical events implemented
- [ ] Field types match canonical schema
- [ ] Event indexing configured
- [ ] Event emission tested
- [ ] Cross-chain equivalence verified
