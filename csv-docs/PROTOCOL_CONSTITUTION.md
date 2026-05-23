# CSV Protocol Constitution

**Version:** 1.0.0
**Status:** Constitutional Hardening Phase
**Last Updated:** 2026-05-20

---

## 1. Preamble

This document defines the immutable and mutable rules of the CSV (Cross-Chain Verification) Protocol. It serves as the single source of truth for serialization, hashing, proof encoding, seal semantics, replay protection, and upgrade governance. All implementations — Rust, TypeScript, and third-party — MUST conform to this constitution.

Deviations from this constitution constitute a protocol fork and require a formal upgrade process (Section 14).

---

## 2. Serialization

### 2.1 Canonical CBOR

All protocol data that participates in cryptographic operations (hashing, signing, proof verification) MUST use canonical CBOR serialization via `ciborium`.

**Rule:** Raw `serde_json` serialization is FORBIDDEN in any hashing path, proof encoding, or cryptographic context.

**Approved functions:**
- `to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError>` — Serialize to canonical CBOR
- `from_canonical_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError>` — Deserialize from canonical CBOR
- `canonical_hash<T: Serialize>(domain: &str, value: &T) -> Result<Hash, ProtocolError>` — Hash via canonical CBOR + tagged SHA-256

**Rationale:** Canonical serialization ensures that identical logical values produce identical byte sequences across implementations and platforms. JSON serialization is order-dependent and platform-sensitive, making it unsuitable for cryptographic contexts.

### 2.2 CBOR Tags

The protocol reserves the following CBOR tag numbers for semantic identification:

| Tag | Type | Description |
|-----|------|-------------|
| 0x1C0 (448) | `ProofBundle` | Canonical proof bundle |
| 0x1C1 (449) | `SanadEnvelope` | Merkleized sanad envelope |
| 0x1C2 (450) | `Commitment` | Transfer commitment |
| 0x1C3 (451) | `Seal` | Cross-chain seal |
| 0x1C4 (452) | `Consignment` | Signed consignment for transfer |

Third-party implementations MUST use tags in the 0x1C0–0x1FF range. Tags outside this range are reserved for future protocol use.

### 2.3 Encoding Order

All `struct` fields MUST be serialized in declaration order as defined in the Rust source. Field renaming, reordering, or omission is prohibited without a protocol version bump.

---

## 3. Hashing

### 3.1 Tagged Hashing

All protocol hashing MUST use BIP-340 style tagged SHA-256 via `csv_tagged_hash`.

**Rule:** Direct calls to `sha2::Sha256`, `sha3::Sha3`, `blake3`, `keccak256`, or any other hash function are FORBIDDEN in protocol code. All hashing MUST go through `csv_tagged_hash`.

**Function signature:**
```rust
pub fn csv_tagged_hash(name: &str, data: &[u8]) -> [u8; 32]
```

**Implementation:**
```
csv_tagged_hash(name, data) = SHA256( SHA256("csv." + name) || SHA256("csv." + name) || data )
```

### 3.2 Domain Tags

The protocol reserves the following domain tags:

| Domain Tag | Purpose |
|------------|---------|
| `csv.sanad-id` | Sanad identity hash |
| `csv-nullifier` | Sanad nullifier (prevents double-spend) |
| `csv.replay-id.v1` | Transfer replay identifier |
| `csv.stealth.addr.v1` | Stealth address derivation |
| `csv.stealth.nonce.v1` | Stealth nonce derivation |
| `csv.ephemeral.point.v1` | Ephemeral point derivation |
| `csv.commitment.version` | Commitment version field |
| `csv.commitment.protocol-id` | Commitment protocol ID field |
| `csv.commitment.mpc-root` | Commitment MPC root field |
| `csv.commitment.contract-id` | Commitment contract ID field |
| `csv.commitment.prev` | Commitment previous commitment field |
| `csv.commitment.payload` | Commitment transition payload hash field |
| `csv.commitment.seal` | Commitment seal ID field |
| `csv.commitment.domain` | Commitment domain separator field |
| `csv.verification.proof.v1` | Proof verification identifier |

New domain tags MUST follow the naming convention: `csv.<context>.<version>` where version is `v1`, `v2`, etc.

### 3.3 Hash Output

All hash outputs are 32-byte arrays (`[u8; 32]`). The `Hash` type is a newtype wrapper:

```rust
pub struct Hash([u8; 32]);
```

Hashes are never serialized as hex strings in protocol messages. They are always raw bytes in CBOR-encoded structures.

---

## 4. Proof Encoding

### 4.1 Proof Bundle Structure

A `ProofBundle` is the canonical container for off-chain verification data:

```rust
pub struct ProofBundle {
    pub version: u32,
    pub protocol_id: Hash,
    pub source_chain: String,
    pub source_txid: Hash,
    pub source_output_index: u32,
    pub seal: Seal,
    pub transition_payload: Vec<u8>,
    pub transition_payload_hash: Hash,
    pub finality_proof: FinalityProof,
    pub inclusion_proof: InclusionProof,
    pub phase: ProofPhase,
}
```

### 4.2 Proof Lifecycle

A proof advances through the following phases. Transitions are unidirectional:

| Phase | Value | Requirement |
|-------|-------|-------------|
| `Constructed` | 0 | Initial state after bundle creation |
| `StructuralValidated` | 1 | All fields present, types correct, hashes match |
| `CryptographicallyValidated` | 2 | Seal signatures verified, MPC proofs valid |
| `FinalityValidated` | 3 | Source chain finality confirmed |
| `ReplayChecked` | 4 | Replay registry confirms novelty |
| `ConsensusBound` | 5 | Cross-chain consensus thresholds met |

**Rule:** A transfer may only mint on the destination chain when the proof reaches `ConsensusBound`.

### 4.3 Proof Verification Levels

The `VerificationLevel` enum classifies proof verification depth:

| Level | Meaning |
|-------|---------|
| `StructuralOnly` | Schema valid, no cryptographic checks |
| `Cryptographic` | Seal signatures and MPC proofs verified |
| `FinalityConfirmed` | Source chain finality confirmed |
| `ReplayProtected` | Replay registry confirms novelty |
| `ConsensusVerified` | Cross-chain consensus thresholds met |

Agent-facing tools MUST return `VerificationLevel` alongside `is_valid`.

### 4.4 Golden Proof Corpus

Canonical proof fixtures live at `csv-core/tests/golden/`:

```
csv-core/tests/golden/
├── valid_proof_bundle_v1.cbor
├── valid_sanad_envelope_v1.cbor
├── replay_attempt_v1.cbor
├── malformed_proof_missing_finality.cbor
├── malformed_proof_wrong_domain.cbor
└── README.md
```

These fixtures are:
- Generated from a known-good runtime build
- Signed with a release key
- Validated in CI via `csv-core/tests/golden/mod.rs`
- Immutable once published (new versions use `_v2`, `_v3`, etc.)

---

## 5. Seal Semantics

### 5.1 Seal Structure

A `Seal` is a cryptographic commitment to a source-chain state transition:

```rust
pub struct Seal {
    pub seal_id: Hash,
    pub source_chain: String,
    pub source_txid: Hash,
    pub source_output_index: u32,
    pub anchor: CommitAnchor,
    pub signature: Vec<u8>,
    pub mpc_proofs: Vec<MpcProof>,
}
```

### 5.2 Seal Types

| Type | Description |
|------|-------------|
| `BitcoinSeal` | Bitcoin UTXO anchor with Merkle proof |
| `EthereumSeal` | Ethereum log anchor with proof |
| `SolanaSeal` | Solana instruction anchor with proof |
| `SuiSeal` | Sui event anchor with proof |
| `AptosSeal` | Aptos event anchor with proof |

### 5.3 Seal Anchors

A `CommitAnchor` binds a seal to on-chain state:

```rust
pub struct CommitAnchor {
    pub contract_id: Hash,
    pub block_number: u64,
    pub block_hash: Hash,
    pub merkle_root: Hash,
    pub index_in_block: u32,
}
```

**Rule:** Every seal MUST include a `CommitAnchor` with a verifiable Merkle proof linking the seal to a finalized block.

### 5.4 Stealth Addresses

Stealth addresses provide recipient privacy:

```
P' = csv_tagged_hash("csv.stealth.addr.v1", R || scan_pk)
```

Where:
- `R` = sender's ephemeral public point
- `scan_pk` = recipient's scan public key
- `P'` = derived stealth address

Only the recipient (with `scan_sk`) can detect payments to their stealth addresses.

---

## 6. Replay Protection

### 6.1 ReplayId

Every transfer MUST derive a unique `ReplayId`:

```rust
pub struct ReplayId([u8; 32]);

impl ReplayId {
    pub fn derive(
        source_chain: &str,
        source_txid: &[u8],
        source_output_index: u32,
        seal_id: &[u8],
        transition_id: &[u8],
        destination_chain: &str,
    ) -> Self
}
```

The `ReplayId` is computed as:
```
ReplayId = csv_tagged_hash("csv.replay-id.v1", canonical_cbor(ReplayIdInputs))
```

Where `ReplayIdInputs` is a struct containing all six fields above.

### 6.2 Replay Registry

The `ReplayRegistry` is an append-only database of seen `ReplayId`s:

- **Insert:** `registry.insert(replay_id) -> Result<(), ProtocolError>`
- **Check:** `registry.contains(replay_id) -> bool`
- **Persistence:** Registry state is persisted across process restarts

**Rule:** A transfer with a `ReplayId` already present in the registry MUST be rejected as a replay attack.

### 6.3 Nullifiers

Sanads include a nullifier to prevent double-spend at the application level:

```
nullifier = Hash::new(csv_tagged_hash("csv-nullifier", &data))
```

The nullifier is published on the destination chain and checked before any mint operation.

---

## 7. Versioning and Upgrades

### 7.1 Protocol Version

The protocol uses semantic versioning with a `ProtocolVersion` struct:

```rust
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub hash: Hash,
}
```

The `hash` field is the `csv_tagged_hash("csv.protocol-version", cbor(version_fields))`.

### 7.2 Version Compatibility

- **Major version bumps** indicate breaking changes (incompatible serialization, hashing, or proof structure)
- **Minor version bumps** indicate additive changes (new fields, new seal types)
- **Patch version bumps** indicate non-breaking fixes

**Rule:** Implementations MUST reject proofs with a `version.major` higher than their supported version.

### 7.3 Upgrade Process

Protocol upgrades follow this process:

1. **Proposal:** A `ProtocolVersion` bump is proposed with migration notes
2. **Review:** All adapter implementations are updated to support the new version
3. **Testing:** Golden corpus is regenerated and validated
4. **Deployment:** New version is activated on a specified block height
5. **Sunset:** Old version is deprecated after a grace period (minimum 30 days)

**Rule:** No implementation may silently accept proofs from a deprecated version.

---

## 8. Domain Separation

### 8.1 Domain Marker Trait

All cryptographic contexts implement the `Domain` trait:

```rust
pub trait Domain {
    const DOMAIN: &'static [u8];
}
```

### 8.2 Reserved Domains

| Domain Constant | Context |
|-----------------|---------|
| `b"csv.bitcoin.seal.v1"` | Bitcoin seal verification |
| `b"csv.ethereum.seal.v1"` | Ethereum seal verification |
| `b"csv.solana.seal.v1"` | Solana seal verification |
| `b"csv.sui.seal.v1"` | Sui seal verification |
| `b"csv.aptos.seal.v1"` | Aptos seal verification |
| `b"csv.stark.seal.v1"` | StarkNet seal verification |
| `b"csv.celestia.seal.v1"` | Celestia data availability seal |
| `b"csv.transfer.commitment.v1"` | Transfer commitment verification |

**Rule:** Domain constants MUST be unique across all contexts. Duplicate domain tags constitute a protocol violation.

### 8.3 Domain-Separated Hashing

The `DomainSeparatedHash<D>` type provides type-safe domain separation:

```rust
pub struct DomainSeparatedHash<D: Domain>(PhantomData<D>);

impl<D: Domain> DomainSeparatedHash<D> {
    pub fn hash(payload: &[u8]) -> Hash;
    pub fn hash_multiple<I>(payloads: I) -> Hash where I: IntoIterator<Item = &[u8]>;
}
```

Both methods use `csv_tagged_hash` internally with the domain tag as the hash tag.

---

## 9. Error Handling

### 9.1 ProtocolError Enum

All protocol errors are captured in a single enum:

```rust
pub enum ProtocolError {
    SerializationError(String),
    ValidationError(String),
    CryptographicError(String),
    ReplayDetected(ReplayId),
    FinalityTimeout(String),
    ConsensusNotReached(String),
    VersionMismatch { expected: ProtocolVersion, got: ProtocolVersion },
    AdapterError { chain: String, message: String },
    InternalError(String),
}
```

### 9.2 Error Propagation

- Protocol functions MUST return `Result<T, ProtocolError>`
- Adapter errors MUST be wrapped in `ProtocolError::AdapterError` with chain context
- Serialization errors MUST include the expected type name
- Replay errors MUST include the offending `ReplayId`

### 9.3 Error Suggestions

Errors MAY include actionable suggestions via `ErrorSuggestion`:

```rust
pub struct ErrorSuggestion {
    pub message: String,
    pub fix_actions: Vec<FixAction>,
}
```

Agent-facing tools MUST include `ErrorSuggestion` in their response when available.

---

## 10. Consignment and Transfer

### 10.1 Consignment Structure

A `Consignment` is a signed package for cross-chain transfer:

```rust
pub struct Consignment {
    pub version: u32,
    pub sender: Address,
    pub recipient: Address,
    pub amount: u128,
    pub source_chain: String,
    pub destination_chain: String,
    pub proof_bundle: ProofBundle,
    pub signature: Vec<u8>,
    pub lease_id: Option<Hash>,
}
```

### 10.2 Transfer Flow

1. **Lock:** Sender locks assets on source chain, receives `Seal`
2. **Construct:** Sender constructs `ProofBundle` from seal and chain data
3. **Sign:** Sender signs `Consignment` with private key
4. **Transfer:** Consignment is delivered to destination chain (via MCP, RPC, or relay)
5. **Verify:** Destination chain verifies proof bundle, checks replay registry
6. **Mint:** If verification passes and consensus thresholds are met, assets are minted

### 10.3 Lease Management

Transfers MAY use leases to coordinate multi-party operations:

- `acquire_lease(timeout_secs) -> LeaseId` — Acquire a lease with TTL
- `is_lease_valid(lease_id) -> bool` — Check lease status
- Leases are scoped to a session and expire after the timeout

---

## 11. MPC Proofs

### 11.1 MPC Proof Structure

Multi-Party Computation proofs attest to the correctness of seal signatures:

```rust
pub struct MpcProof {
    pub protocol_id: Hash,
    pub participant_count: u32,
    pub threshold: u32,
    pub proof_data: Vec<u8>,
    pub verification_hash: Hash,
}
```

### 11.2 Verification

MPC proofs are verified by:
1. Checking `participant_count >= threshold`
2. Verifying `verification_hash = csv_tagged_hash("csv.mpc.proof", proof_data)`
3. Checking the proof against the known MPC protocol specification

---

## 12. Finality and Inclusion Proofs

### 12.1 FinalityProof

A `FinalityProof` attests that a transaction has reached finality on the source chain:

```rust
pub struct FinalityProof {
    pub chain: String,
    pub block_hash: Hash,
    pub block_number: u64,
    pub finality_threshold: u32,
    pub proof_data: Vec<u8>,
}
```

### 12.2 InclusionProof

An `InclusionProof` attests that a seal is included in a specific block:

```rust
pub struct InclusionProof {
    pub merkle_path: Vec<Hash>,
    pub merkle_root: Hash,
    pub leaf_hash: Hash,
    pub leaf_index: u64,
}
```

**Rule:** Every `ProofBundle` MUST include both `FinalityProof` and `InclusionProof`.

---

## 13. Sanads

### 13.1 Sanad Structure

A `Sanad` is a verifiable credential for cross-chain transfers:

```rust
pub struct Sanad {
    pub id: SanadId,
    pub version: u32,
    pub transfer_id: Hash,
    pub sender: Address,
    pub recipient: Address,
    pub amount: u128,
    pub source_chain: String,
    pub destination_chain: String,
    pub nullifier: Hash,
    pub metadata: Vec<u8>,
    pub signature: Vec<u8>,
}
```

### 13.2 Sanad Identity

```
SanadId = Hash::new(csv_tagged_hash("sanad-id", &data))
```

Where `data` contains all sanad fields serialized in declaration order.

### 13.3 Merkleized Payloads (Future)

Future versions will introduce `SanadEnvelope` with merkleized payloads:

```rust
pub struct SanadEnvelope {
    pub header: SanadHeader,
    pub payload_hash: Hash,
    pub merkle_proof: Vec<Hash>,
}
```

This is tracked as a Priority 1 gap in the audit remediation plan.

---

## 14. Governance and Amendments

### 14.1 Immutable Rules

The following rules are IMMUTABLE and cannot be changed without creating a new protocol:

1. Canonical CBOR serialization for all cryptographic contexts
2. Tagged SHA-256 hashing via `csv_tagged_hash`
3. Unidirectional proof phase progression
4. Replay registry as append-only
5. Domain separation for all cryptographic contexts
6. `VerificationLevel` must be returned by all agent-facing tools

### 14.2 Mutable Rules

The following rules MAY be amended via the upgrade process (Section 7.3):

1. New seal types
2. New domain tags (within reserved ranges)
3. CBOR tag assignments (within reserved ranges)
4. Error message formats
5. Performance optimizations (non-breaking)

### 14.3 Amendment Process

1. Draft an amendment with clear motivation and impact analysis
2. Submit to the protocol governance channel
3. Allow 14-day comment period
4. Require 2/3 majority approval from protocol maintainers
5. Implement and test against golden corpus
6. Deploy with version bump

---

## 15. Compliance Checklist

All implementations MUST pass the following checks:

- [ ] Uses `canonical_hash()` or `csv_tagged_hash()` for all protocol hashing
- [ ] Uses `to_canonical_cbor()` / `from_canonical_cbor()` for all cryptographic serialization
- [ ] Never uses `serde_json` in hashing paths
- [ ] Returns `VerificationLevel` alongside `is_valid` in all proof verification responses
- [ ] Includes `ErrorSuggestion` in error responses when actionable
- [ ] Validates all inputs via Zod schemas (TypeScript) or type system (Rust)
- [ ] Emits audit logs for all state-changing operations
- [ ] Uses temp files for proof bundles/consignments (never passes via shell args)
- [ ] Checks replay registry before any transfer
- [ ] Includes `lease_id` in consignment when using lease management

---

## 16. References

- [Audit Report](./audit/audit.md) — Full security audit findings
- [Implementation Plan](./audit/implementation.md) — Remediation roadmap
- [Canonical Serialization](../csv-core/src/canonical.rs) — Rust implementation
- [Tagged Hashing](../csv-core/src/tagged_hash.rs) — Rust implementation
- [Proof Pipeline](../csv-core/src/proof_pipeline.rs) — Verification flow
- [MCP Server](../csv-mcp-server/src/index.ts) — Agent-facing interface

---

*This constitution is a living document. As the CSV Protocol evolves, this document MUST be updated to reflect the current state of the protocol. All changes require governance approval per Section 14.3.*
