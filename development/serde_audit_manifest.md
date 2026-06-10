# Serde Audit Manifest

**Generated:** 2026-06-09
**Scope:** csv-protocol, csv-hash, csv-codec, csv-proof, csv-verifier, csv-content, csv-storage, csv-contract-bindings, csv-adapters (solana, ethereum, aptos, bitcoin, sui)
**Total types found:** 128

---

## Layer Definitions

| Layer | Description | Serde Policy |
|-------|-------------|--------------|
| **L0** | Hash types, SanadId, SealPoint, CommitAnchor | **MUST NOT** use serde — hashing paths require canonical_cbor |
| **L1** | Proof types, InclusionProof, FinalityProof | **SHOULD NOT** use serde — verification must use canonical_cbor |
| **L2** | Schema, Content types | **MAY** use serde — serialization is the primary use case |
| **L3** | Storage types (replay, state, lease, genesis) | **MAY** use serde — persistence layer |
| **L4** | Runtime/Coordinator types (failure domains, capabilities, config) | **MAY** use serde — operational serialization |

---

## L0 — Hash Types (MUST STRIP serde)

These types are used in cryptographic hashing paths. Serde serialization is non-canonical and can introduce hash divergence. They already have `to_canonical_bytes()` / `from_canonical_bytes()` using `csv_codec::canonical::to_canonical_cbor`.

### csv-hash/src/hash_registry.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `Hash` | 14-17 | `[u8; 32]` | **STRIP** — Core hash type. Already has `to_hex()`/`from_hex()`. Use `canonical_cbor` for any serialization. |
| `SealHash` | 326 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `CommitmentHash` | 351 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `SanadIdHash` | 369 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `NullifierHash` | 387 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `ReplayIdHash` | 405 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `VerificationHash` | 423 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `MerkleHash` | 441 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |

### csv-hash/src/registry.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `TypedHashDomain` | 21 | enum | **STRIP** — Domain enum. Use `Display`/`FromStr` for serialization. |
| `ContentHash` | 76 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `ProofHash` | 103 | `Hash` | **STRIP** — Typed wrapper. Use `canonical_cbor`. |
| `SealHash` | 130 | `Hash` | **STRIP** — Duplicate name from hash_registry. Use `canonical_cbor`. |

### csv-hash/src/sanad.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SanadId` | 9 | `Hash` | **STRIP** — Core identity type. Already has `from_bytes()`/`as_bytes()`. Use `canonical_cbor`. |

### csv-hash/src/seal.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SealPoint` | 29 | `id: Vec<u8>`, `nonce`, `version` | **STRIP** — Already has `to_canonical_bytes()`/`from_canonical_bytes()`. The `to_vec()` method is already `#[deprecated]`. Remove serde entirely. |
| `CommitAnchor` | 215 | `anchor_id`, `block_height`, `metadata` | **STRIP** — Already has `to_canonical_bytes()`/`from_canonical_bytes()`. The `to_vec()` method is already `#[deprecated]`. Remove serde entirely. |

### csv-hash/src/commitment.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `Commitment` | 52 | 8 fields including 6 `Hash` fields | **STRIP** — Core protocol type. Already has `to_canonical_bytes()`. The `commitment_hash()` method uses `to_canonical_bytes()` internally. Remove serde. |

### csv-hash/src/dag.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `DAGNode` | 10 | `node_id`, `bytecode`, `signatures`, `witnesses`, `parents` | **STRIP** — Already has `hash()` using `to_canonical_cbor`. Tests already verify canonical roundtrip. Remove serde. |
| `DAGSegment` | 58 | `nodes: Vec<DAGNode>`, `root_commitment` | **STRIP** — Already has `validate_structure()`. Tests verify canonical roundtrip. Remove serde. |

### csv-hash/src/nullifier.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SealConsumption` | 60 | `chain`, `seal_ref`, `sanad_id`, `block_height`, `tx_hash`, `recorded_at` | **STRIP** — Used in double-spend detection. Uses `to_canonical_bytes()` for seal key derivation. Remove serde. |

---

## L1 — Proof Types (SHOULD STRIP serde)

These types are used in proof verification. They should use `canonical_cbor` for deterministic serialization. Some may keep serde for debug/inspection purposes only.

### csv-proof/src/commitments_ext.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `CommitmentScheme` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `CommitmentMetadata` | (struct) | — | **STRIP** — Use `canonical_cbor`. |
| `CommitmentExt` | (struct) | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityProofType` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `InclusionProofType` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |

### csv-proof/src/proof_dags.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ProofDAG` | (struct) | — | **STRIP** — Use `canonical_cbor`. |
| `ProofNodeId` | (struct) | — | **STRIP** — Use `canonical_cbor`. |
| `ProofNode` | (struct) | — | **STRIP** — Use `canonical_cbor`. |
| `ProofNodeMetadata` | (struct) | — | **STRIP** — Use `canonical_cbor`. |

### csv-proof/src/provenance.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ProofProvenance` | — | — | **STRIP** — Use `canonical_cbor`. |

### csv-proof/src/zk_proof.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ChainWitness` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ProofEnvelope` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ZkPublicInputs` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ZkProofSystem` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ZkVerificationKey` | — | — | **STRIP** — Use `canonical_cbor`. |

### csv-protocol/src/canonical_proof.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `CanonicalProof` | — | — | **STRIP** — By definition should use canonical serialization. Remove serde. |

### csv-protocol/src/proof_types.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ProofBundle` | — | — | **STRIP** — Core proof type. Use `canonical_cbor`. |
| `ProofCategory` | — | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ProofType` | — | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `FinalityProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `InclusionProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ExecutionProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `OwnershipProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ReplayProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `TransitionProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ZkProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `CompositionRule` | — | — | **STRIP** — Enum. Use `Display`/`FromStr`. |

### csv-protocol/src/cross_chain.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `BitcoinInclusionProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `EthereumInclusionProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `SolanaSlotProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `SuiCheckpointProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `AptosLedgerProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `InclusionProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `ZkSealProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `PublicInputs` | — | — | **STRIP** — Use `canonical_cbor`. |
| `VerifierKey` | — | — | **STRIP** — Use `canonical_cbor`. |
| `CompleteProofBundle` | — | — | **STRIP** — Use `canonical_cbor`. |
| `CrossChainSealEntry` | — | — | **STRIP** — Use `canonical_cbor`. |
| `SourceHashEvent` | — | — | **STRIP** — Use `canonical_cbor`. |
| `HashAlgorithm` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |

### csv-protocol/src/verified.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `VerificationResult` | — | — | **STRIP** — Use `canonical_cbor`. |
| `VerificationStrength` | — | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `VerificationError` | — | — | **STRIP** — Error type. Use `thiserror`. |

### csv-protocol/src/finality/abstraction.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `FinalityPolicy` | — | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityEvidence` | — | — | **STRIP** — Use `canonical_cbor`. |

### csv-protocol/src/finality/capabilities.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `FinalityType` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ProofModel` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `StateModel` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ReorgRisk` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ReplayProtectionModel` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ChainCapability` | — | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityModel` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `CapabilityRequirements` | — | — | **STRIP** — Use `canonical_cbor`. |
| `CapabilityCheckResult` | — | — | **STRIP** — Use `canonical_cbor`. |
| `IndividualCapability` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `LegacyChainCapability` | — | — | **STRIP** — Use `canonical_cbor`. |

### csv-protocol/src/finality/chain_specific.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `FinalityLevel` | — | — | **STRIP** — Use `canonical_cbor`. |

### csv-protocol/src/finality/mod.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `FinalityProof` | — | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityType` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `ProofSystem` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `FinalityConfig` | — | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityPolicy` | — | — | **STRIP** — Use `canonical_cbor`. |
| `FinalityConstraint` | — | — | **STRIP** — Use `canonical_cbor`. |

### csv-protocol/src/finality/state.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `FinalityStatus` | (enum) | — | **STRIP** — Enum. Use `Display`/`FromStr`. |
| `FinalityState` | — | — | **STRIP** — Use `canonical_cbor`. |

---

## L2 — Content Types (MAY KEEP serde)

These types are primarily used for serialization/deserialization of content trees, attachments, claims, and encryption metadata. Serde is appropriate here.

### csv-content/src/attachments.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `AttachmentRef` | — | — | **KEEP** — Serialization target. |
| `AttachmentBudget` | — | — | **KEEP** — Configuration for serialization. |
| `MimeType` | — | — | **KEEP** — Enum. Serde is appropriate. |

### csv-content/src/claims.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `Claim` | — | — | **KEEP** — Serialization target. |
| `ClaimType` | — | — | **KEEP** — Enum. Serde is appropriate. |
| `RightsTransfer` | — | — | **KEEP** — Serialization target. |
| `Rights` | — | — | **KEEP** — Serialization target. |

### csv-content/src/content_tree.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ContentType` | — | — | **KEEP** — Enum. Serde is appropriate. |
| `ContentNode` | — | — | **KEEP** — Serialization target. |
| `ContentTree` | — | — | **KEEP** — Serialization target. |
| `ContentProof` | — | — | **KEEP** — Serialization target. |
| `SelectiveDisclosure` | — | — | **KEEP** — Serialization target. |
| `SubtreeProof` | — | — | **KEEP** — Serialization target. |
| `AccessControl` | — | — | **KEEP** — Serialization target. |
| `ContentMetadata` | — | — | **KEEP** — Serialization target. |

### csv-content/src/encryption.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `EncryptionScheme` | — | — | **KEEP** — Enum. Serde is appropriate. |
| `EncryptionPolicy` | — | — | **KEEP** — Serialization target. |
| `EncryptedContent` | — | — | **KEEP** — Serialization target. |

### csv-content/src/participants.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ParticipantId` | — | — | **KEEP** — Serialization target. |
| `ParticipantRole` | — | — | **KEEP** — Enum. Serde is appropriate. |
| `Participant` | — | — | **KEEP** — Serialization target. |
| `ParticipantSet` | — | — | **KEEP** — Serialization target. |

### csv-content/src/resource_accounting.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ResourceCost` | — | — | **KEEP** — Serialization target. |
| `ResourceAccountingError` | — | — | **KEEP** — Error type. Serde ok for reporting. |
| `ResourceLimits` | — | — | **KEEP** — Configuration. Serde is appropriate. |

---

## L3 — Storage Types (MAY KEEP serde)

These types are used for persistence, replay protection, leases, state management, and genesis. Serde is appropriate for storage serialization.

### csv-protocol/src/replay/registry.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ReplayKey` | — | — | **KEEP** — Storage key type. Serde ok. |
| `ReplayEntry` | — | — | **KEEP** — Storage entry. Serde ok. |
| `ReplayRegistry` | — | — | **KEEP** — Storage container. Serde ok. |
| `ReplayStats` | — | — | **KEEP** — Storage stats. Serde ok. |

### csv-protocol/src/state.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `State` | — | — | **KEEP** — Storage type. Serde ok. |
| `GlobalState` | — | — | **KEEP** — Storage type. Serde ok. |
| `OwnedState` | — | — | **KEEP** — Storage type. Serde ok. |
| `StateOutput` | — | — | **KEEP** — Storage type. Serde ok. |
| `StateInput` | — | — | **KEEP** — Storage type. Serde ok. |

### csv-protocol/src/genesis.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `Genesis` | — | — | **KEEP** — Genesis serialization. Serde ok. |

### csv-protocol/src/lease.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `LeaseId` | — | — | **KEEP** — Storage key. Serde ok. |
| `Lease` | — | — | **KEEP** — Storage entry. Serde ok. |

### csv-protocol/src/transfer_state/mod.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `TransferState` | — | — | **KEEP** — Storage type. Serde ok. |

### csv-protocol/src/transition.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `Transition` | — | — | **KEEP** — Storage type. Serde ok. |

### csv-protocol/src/events.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `EventType` | — | — | **KEEP** — Enum. Serde ok. |
| `EventData` | — | — | **KEEP** — Storage type. Serde ok. |
| `CanonicalEvent` | — | — | **KEEP** — Storage type. Serde ok. |

### csv-protocol/src/version.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ProtocolVersion` | — | — | **KEEP** — Serialization target. Serde ok. |
| `SyncStatus` | — | — | **KEEP** — Serialization target. Serde ok. |

### csv-protocol/src/backend.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ContractStatus` | — | — | **KEEP** — Serialization target. Serde ok. |
| `TxStatus` | — | — | **KEEP** — Serialization target. Serde ok. |
| `SanadOpType` | — | — | **KEEP** — Enum. Serde ok. |
| `SanadOpResult` | — | — | **KEEP** — Serialization target. Serde ok. |
| `SealOpResult` | — | — | **KEEP** — Serialization target. Serde ok. |
| `Balance` | — | — | **KEEP** — Serialization target. Serde ok. |
| `TokenBalance` | — | — | **KEEP** — Serialization target. Serde ok. |
| `ContractInfo` | — | — | **KEEP** — Serialization target. Serde ok. |
| `TxInfo` | — | — | **KEEP** — Serialization target. Serde ok. |
| `CanonicalSanadState` | — | — | **KEEP** — Serialization target. Serde ok. |
| `CanonicalSealState` | — | — | **KEEP** — Serialization target. Serde ok. |
| `CanonicalEvent` | — | — | **KEEP** — Serialization target. Serde ok. |

### csv-protocol/src/chain_config.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `ChainConfig` | — | — | **KEEP** — Config serialization. Serde ok. |

### csv-protocol/src/deterministic_recovery.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `RuntimeCheckpoint` | — | — | **KEEP** — Checkpoint serialization. Serde ok. |
| `LeaseCheckpoint` | — | — | **KEEP** — Checkpoint serialization. Serde ok. |
| `TransferCheckpoint` | — | — | **KEEP** — Checkpoint serialization. Serde ok. |
| `RegistryCheckpoint` | — | — | **KEEP** — Checkpoint serialization. Serde ok. |
| `Checkpoint` | — | — | **KEEP** — Checkpoint serialization. Serde ok. |
| `RecoveryState` | — | — | **KEEP** — Serialization target. Serde ok. |

### csv-protocol/src/invariants.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `TimeoutConfig` | — | — | **KEEP** — Config serialization. Serde ok. |

### csv-protocol/src/signature.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SignatureScheme` | — | — | **KEEP** — Enum. Serde ok. |

### csv-protocol/src/envelope.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `EnvelopeType` | — | — | **KEEP** — Enum. Serde ok. |
| `Envelope` | — | — | **KEEP** — Wire format. Serde ok. |
| `EnvelopeCommitment` | — | — | **KEEP** — Wire format. Serde ok. |
| `CanonicalEncoding` | — | — | **KEEP** — Enum. Serde ok. |

---

## L4 — Runtime/Coordinator Types (MAY KEEP serde)

These types are used for runtime monitoring, failure domain classification, capability negotiation, and operational configuration. Serde is appropriate.

### csv-protocol/src/failure_domains.rs

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `FailureDomain` | — | — | **KEEP** — Runtime classification. Serde ok. |
| `ErrorClassification` | — | — | **KEEP** — Runtime classification. Serde ok. |
| `Component` | — | — | **KEEP** — Enum. Serde ok. |
| `ErrorContext` | — | — | **KEEP** — Runtime metadata. Serde ok. |
| `RetryStrategy` | — | — | **KEEP** — Config. Serde ok. |
| `ErrorStats` | — | — | **KEEP** — Metrics. Serde ok. |

### csv-adapters/csv-solana/src/

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SolanaConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `SolanaNetworkConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `SolanaProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SolanaSealProtocol` | — | — | **KEEP** — Adapter seal. Serde ok. |
| `SolanaSeal` | — | — | **KEEP** — Adapter seal. Serde ok. |
| `SolanaAccountProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SolanaAccountStateChange` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SolanaAccountState` | — | — | **KEEP** — Adapter state. Serde ok. |
| `SolanaConfirmationStatus` | — | — | **KEEP** — Adapter status. Serde ok. |
| `SolanaInstructionType` | — | — | **KEEP** — Adapter enum. Serde ok. |
| `SolanaSealStatus` | — | — | **KEEP** — Adapter status. Serde ok. |
| `SolanaFinalityProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SolanaInclusionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SolanaSanadAccount` | — | — | **KEEP** — Adapter state. Serde ok. |
| `SolanaAnchorRef` | — | — | **KEEP** — Adapter type. Serde ok. |
| `SolanaSealRef` | — | — | **KEEP** — Adapter type. Serde ok. |
| `SolanaTransactionStatus` | — | — | **KEEP** — Adapter status. Serde ok. |

### csv-adapters/csv-ethereum/src/

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `EthRpcBlock` | — | — | **KEEP** — RPC type. Serde ok. |
| `EthAnchorRef` | — | — | **KEEP** — Adapter type. Serde ok. |
| `EthFinalityProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `EthInclusionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `EthSealRef` | — | — | **KEEP** — Adapter type. Serde ok. |

### csv-adapters/csv-aptos/src/

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `AptosCheckpoint` | — | — | **KEEP** — Adapter type. Serde ok. |
| `AptosCheckpointConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `AptosSealContractConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `AptosNetworkConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `AptosTransactionConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `AptosEventProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `AptosStateProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `AptosTransactionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `AptosSeal` | — | — | **KEEP** — Adapter seal. Serde ok. |
| `AptosAnchorRef` | — | — | **KEEP** — Adapter type. Serde ok. |
| `AptosFinalityProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `AptosInclusionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `AptosSealRef` | — | — | **KEEP** — Adapter type. Serde ok. |

### csv-adapters/csv-bitcoin/src/

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `BitcoinAnchorRef` | — | — | **KEEP** — Adapter type. Serde ok. |
| `BitcoinFinalityProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `BitcoinInclusionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `BitcoinSealRef` | — | — | **KEEP** — Adapter type. Serde ok. |

### csv-adapters/csv-sui/src/

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SuiCheckpoint` | — | — | **KEEP** — Adapter type. Serde ok. |
| `SuiCheckpointConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `SuiSealContractConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `SuiAnchorContractConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `SuiTransactionConfig` | — | — | **KEEP** — Adapter config. Serde ok. |
| `SuiNetworkType` | — | — | **KEEP** — Adapter enum. Serde ok. |
| `SuiEventProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SuiStateProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SuiTransactionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SuiSeal` | — | — | **KEEP** — Adapter seal. Serde ok. |
| `SuiAnchorRef` | — | — | **KEEP** — Adapter type. Serde ok. |
| `SuiFinalityProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SuiInclusionProof` | — | — | **KEEP** — Adapter proof. Serde ok. |
| `SuiSealRef` | — | — | **KEEP** — Adapter type. Serde ok. |

### csv-contract-bindings/src/

| Type | Line | Fields | Action |
|------|------|--------|--------|
| `SanadState` | — | — | **KEEP** — ABI enum. Serde ok. |
| `SealState` | — | — | **KEEP** — ABI enum. Serde ok. |
| `AbiConstitution` | — | — | **KEEP** — ABI config. Serde ok. |
| `AbiFunction` | — | — | **KEEP** — ABI type. Serde ok. |
| `AbiEvent` | — | — | **KEEP** — ABI type. Serde ok. |
| `AbiError` | — | — | **KEEP** — ABI type. Serde ok. |
| `AbiParam` | — | — | **KEEP** — ABI type. Serde ok. |
| `AbiConst` | — | — | **KEEP** — ABI type. Serde ok. |
| `ContractAbi` | — | — | **KEEP** — ABI container. Serde ok. |
| `ContractAddress` | — | — | **KEEP** — Common type. Serde ok. |
| `ContractEvent` | — | — | **KEEP** — Common type. Serde ok. |
| `ContractFunctionSelector` | — | — | **KEEP** — Common type. Serde ok. |
| `ContractMethod` | — | — | **KEEP** — Common type. Serde ok. |
| `ContractVersion` | — | — | **KEEP** — Common type. Serde ok. |
| `EventInputParam` | — | — | **KEEP** — ABI type. Serde ok. |
| `MethodInputParam` | — | — | **KEEP** — ABI type. Serde ok. |
| `MethodOutputParam` | — | — | **KEEP** — ABI type. Serde ok. |
| `ContractBytecode` | — | — | **KEEP** — Deployment type. Serde ok. |
| `DeploymentConfig` | — | — | **KEEP** — Deployment type. Serde ok. |
| `DeploymentManifest` | — | — | **KEEP** — Deployment type. Serde ok. |
| `DeploymentRegistry` | — | — | **KEEP** — Deployment type. Serde ok. |
| `DeploymentResult` | — | — | **KEEP** — Deployment type. Serde ok. |
| `MintedEvent` | — | — | **KEEP** — Contract event. Serde ok. |
| `MintRollbackEvent` | — | — | **KEEP** — Contract event. Serde ok. |
| `SanadCreatedEvent` | — | — | **KEEP** — Contract event. Serde ok. |
| `SanadDetails` | — | — | **KEEP** — Contract type. Serde ok. |
| `SanadTransferredEvent` | — | — | **KEEP** — Contract event. Serde ok. |
| `SealCreatedEvent` | — | — | **KEEP** — Contract event. Serde ok. |
| `SealConsumedEvent` | — | — | **KEEP** — Contract event. Serde ok. |

---

## Summary

### Types to STRIP (L0 + L1)

| Layer | Count | Crates |
|-------|-------|--------|
| L0 | 18 | csv-hash (8 files) |
| L1 | 47 | csv-proof (4 files), csv-protocol (8 files) |
| **Total** | **65** | |

### Types to KEEP (L2 + L3 + L4)

| Layer | Count | Crates |
|-------|-------|--------|
| L2 | 22 | csv-content (6 files) |
| L3 | 33 | csv-protocol (12 files) |
| L4 | 53 | csv-protocol (6 files), csv-adapters (5 crates), csv-contract-bindings (3 files) |
| **Total** | **108** | |

---

## Recommended Actions

### Priority 1 — L0 Types (Critical Security)

1. **Remove `serde::{Serialize, Deserialize}` from all csv-hash types**
   - These types already have `to_canonical_bytes()` / `from_canonical_bytes()` using `csv_codec::canonical`
   - The `Hash` type already has `to_hex()`/`from_hex()` for string serialization
   - `SealPoint` and `CommitAnchor` already have `#[deprecated]` `to_vec()` methods — remove serde to eliminate the escape hatch
   - `Commitment` uses `to_canonical_bytes()` internally in `commitment_hash()` — serde is redundant

2. **Add compile-time enforcement**
   - Consider adding a `#[cfg(not(test))]` guard or a build script check that verifies no serde is used in hash paths
   - Add a test that asserts `Hash::serialize()` does not exist (compile failure if serde is re-added)

3. **Migration path**
   - All existing serde usage of L0 types must be replaced with `to_canonical_bytes()` + `from_canonical_bytes()`
   - For debug/logging, use `Display`/`Debug` implementations (already present on most types)
   - For wire format, use `csv-wire` which owns all serialization

### Priority 2 — L1 Types (High Importance)

1. **Remove serde from proof types in csv-proof and csv-protocol**
   - Proof types should use `canonical_cbor` for deterministic serialization
   - This ensures proof verification is reproducible across implementations
   - Some enum types (FinalityType, ProofSystem, etc.) can use `Display`/`FromStr` instead

2. **Wire format migration**
   - All proof serialization should go through `csv-wire`
   - The `csv-wire` crate should own the canonical encoding for proof types

### Priority 3 — L2-L4 Types (No Action Required)

1. **Content types (L2)** — Serde is appropriate. These are serialization targets.
2. **Storage types (L3)** — Serde is appropriate. These are persisted to storage backends.
3. **Runtime/Coordinator types (L4)** — Serde is appropriate. These are operational/runtime types.
4. **Adapter types** — Serde is appropriate. These are chain-specific serialization formats.
5. **Contract bindings** — Serde is appropriate. These are ABI-level types.

### Additional Recommendations

1. **Add a serde audit CI check** — Run the same grep command from this manifest as a CI step to detect new serde derives on L0/L1 types.

2. **Document the policy** — Add a comment in `csv-hash/Cargo.toml` and `csv-proof/Cargo.toml` explaining why serde is excluded.

3. **Consider `no_std` compatibility** — L0/L1 types should ideally be `no_std` compatible. Serde adds a `std` dependency that may not be available in WASM contexts.

4. **Test canonical roundtrips** — Ensure all L0/L1 types have tests verifying `to_canonical_bytes()` -> `from_canonical_bytes()` roundtrip produces identical values.

5. **Remove test-only serde** — The `golden_vectors.rs` test file has a test struct with serde. This is acceptable for tests only but should not leak into production code.
