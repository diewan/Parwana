# Canonical Event Schema

This document defines the canonical event schema that all chain implementations MUST follow. Events are the primary interface between on-chain contracts and off-chain verification.

> Aligned with **[RFC-0012: Thin Registry Cross-Chain Mint](../rfcs/RFC-0012-thin-registry-cross-chain-mint.md)**. Destination materialization emits `SanadMinted` (thin-registry mint, verifier-attested — §9); escrow release emits a **distinct** `SettlementReleased` (§10). Field names follow the canonical field dictionary in [ABI_CONSTITUTION.md](ABI_CONSTITUTION.md). The former `CrossChainMint` is renamed to `SanadMinted`; the proof-root events `ProofAccepted` / `ProofRejected` are **deprecated** (proof adjudication is off-chain under RFC-0012 and not signalled on-chain).

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

### 4. SanadMinted

Emitted when a Sanad is materialized on the destination chain by the thin registry, after the verifier-signed mint attestation (RFC-0012 §9) is verified natively. This is NOT a proof-root verification event — the destination contract records an off-chain-verified result; it does not re-adjudicate the proof.

**Canonical Fields** (canonical field dictionary — carries the full `destinationOwner` bytes so off-chain consumers can reconstruct settlement/replay evidence):
- `sanadId: bytes32` - Sanad identifier (duplicate-mint key)
- `commitment: bytes32` - Commitment hash
- `sourceChain: bytes32` - `keccak256("csv.chain.<name>")`
- `destinationOwner: bytes` - Full recipient bytes (on-chain storage keeps `keccak256(destinationOwner)`; the event carries full bytes)
- `lockEventId: bytes32` - Source lock event identity (duplicate-source-lock key)
- `nullifier: bytes32` - Replay nullifier (replay-protection key)
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event SanadMinted(bytes32 indexed sanadId, bytes32 commitment, bytes32 sourceChain, bytes destinationOwner, bytes32 indexed lockEventId, bytes32 nullifier, uint256 timestamp)`
- **Solana**: Registry account write + CPI log
- **Bitcoin**: Not applicable (interactive/off-chain destination only)
- **Sui**: Object creation + Event
- **Aptos**: Resource mint + Event

### 4b. SettlementReleased

Emitted by the **source-chain** escrow when it releases the operator's fee after verifying a verifier-signed `SettlementReceipt` (RFC-0012 §10). **Distinct from `SanadMinted`** and never conflated with it — mint happens on the destination chain; settlement happens on the source chain. Authorized by the verifier receipt, never by the operator's own claim.

**Canonical Fields:**
- `lockEventId: bytes32` - Settlement replay key (exactly one release per `lockEventId`)
- `sanadId: bytes32` - Sanad identifier
- `operatorPayoutAddress: Address` - Escrow payout beneficiary (chain-native encoding)
- `destinationMintTxRef: bytes32` - Canonical reference to the confirmed destination mint
- `timestamp: u64` - Block timestamp

**Chain-Specific Mappings:**
- **Ethereum**: `event SettlementReleased(bytes32 indexed lockEventId, bytes32 indexed sanadId, address operatorPayoutAddress, bytes32 destinationMintTxRef, uint256 timestamp)`
- **Solana / Sui / Aptos**: native escrow-release event with the same fields
- **Bitcoin**: source escrow release per the chain's script model

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

### 7. ProofAccepted — DEPRECATED (RFC-0012)

**Deprecated.** Belonged to the proof-root verification model. Under RFC-0012 the destination contract does not adjudicate proofs on-chain, so there is no on-chain "proof accepted" signal; mint authenticity is the verifier attestation carried in the `SanadMinted` calldata. Retained here only as historical context; new contracts MUST NOT emit it.

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

### 8. ProofRejected — DEPRECATED (RFC-0012)

**Deprecated.** Same rationale as `ProofAccepted`: proof rejection is an off-chain verification outcome under RFC-0012, not an on-chain event. Retained as historical context only; new contracts MUST NOT emit it.

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
- [ ] Active canonical events implemented (`SanadCreated`, `SanadConsumed`, `CrossChainLock`, `SanadMinted`, `SettlementReleased`, `CrossChainRefund`, `NullifierRegistered`, `ReplayDetected`)
- [ ] `ProofAccepted` / `ProofRejected` NOT emitted (deprecated by RFC-0012)
- [ ] `SanadMinted` field set matches the canonical field dictionary and carries full `destinationOwner` bytes
- [ ] `SettlementReleased` emitted only by source escrow, distinct from `SanadMinted`
- [ ] Field types match canonical schema
- [ ] Event indexing configured
- [ ] Event emission tested
- [ ] Cross-chain equivalence verified
