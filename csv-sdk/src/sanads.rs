//! Sanads management runtime.
//!
//! The [`SanadsManager`] provides a high-level API for creating, querying,
//! and managing Sanads across all supported chains.
//!
//! # What is a Sanad?
//!
//! A **Sanad** is a verifiable, single-use digital claim that can be
//! transferred cross-chain. It exists in client state (not on any chain)
//! and is anchored to a single-use seal on a specific chain.
//!
//! To transfer a Sanad, the seal is consumed on-chain and the new owner
//! verifies the consumption proof locally — no bridges, no minting,
//! no cross-chain messaging.
//!
//! # Wallet Integration
//!
//! Creating a Sanad requires:
//! 1. A [`SanadPayloadDescriptor`] binding content metadata to the Sanad ID
//! 2. A signed [`OwnershipProof`] from the wallet
//!
//! Use [`SanadsManager::create`] which accepts both the descriptor and owner proof.
//!
//! ## Example: Creating a Sanad with Real Wallet
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//! use csv_protocol::{SanadPayloadDescriptor, OwnershipProof};
//! use csv_keys::memory::SecretKey;
//!
//! // 1. Create a payload descriptor
//! let descriptor = SanadPayloadDescriptor::new(
//!     "csv.sanad.content.v1",
//!     schema_hash,
//!     1, // CBOR codec
//!     payload_hash,
//!     None, // no content root
//!     disclosure_policy_hash,
//!     proof_policy_hash,
//! );
//!
//! // 2. Sign the descriptor hash with the wallet
//! let owner_proof = wallet.sign_descriptor(&descriptor)?;
//!
//! // 3. Create the Sanad
//! let sanad = sanads.create(
//!     &descriptor,
//!     commitment,
//!     owner_proof,
//!     salt,
//!     chain,
//! )?;
//! ```

use std::sync::Arc;

use crate::local_store::SanadRecord;
use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;
use csv_protocol::{CommitAnchor, OwnershipProof, Sanad, SanadPayloadDescriptor};

use crate::client::ClientRef;
use crate::error::CsvError;

/// Explicit content-descriptor inputs for a Sanad creation request.
///
/// Every field here maps 1:1 onto a [`SanadPayloadDescriptor`] field. There is
/// **no implicit default**: a hash that the caller did not supply is `None`,
/// never an all-zero [`Hash`]. A zero hash is indistinguishable from the
/// legitimately-computed hash of all-zero content, so it must never be used
/// as a "missing value" sentinel (SANAD-CREATE-001).
///
/// `schema_hash`, `payload_hash`, `disclosure_policy_hash`, and
/// `proof_policy_hash` are required by the protocol descriptor and therefore
/// required here too — [`CreateSanadRequest::validate`] fails closed with
/// [`CsvError::InvalidInput`] if any of them is missing.
#[derive(Debug, Clone, Default)]
pub struct ContentDescriptorInput {
    /// Registered schema identifier (defaults to the canonical descriptor schema id if `None`).
    pub schema_id: Option<String>,
    /// Hash of the schema definition. Required.
    pub schema_hash: Option<Hash>,
    /// Canonical payload serialization codec identifier (defaults to CBOR = 1 if `None`).
    pub payload_codec: Option<u8>,
    /// Hash of the actual payload content. Required.
    pub payload_hash: Option<Hash>,
    /// Optional Merkle root over content subtrees. Explicitly absent when `None`.
    pub content_root: Option<Hash>,
    /// Optional root over attachment hashes. Explicitly absent when `None`.
    pub attachment_root: Option<Hash>,
    /// Hash of the disclosure policy. Required.
    pub disclosure_policy_hash: Option<Hash>,
    /// Hash of the proof policy. Required.
    pub proof_policy_hash: Option<Hash>,
}

/// How the caller wants seal funding selected for a same-chain Sanad creation.
///
/// This replaces ad hoc "pick the first/largest UTXO" logic scattered through
/// callers with an explicit, typed selection policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingSelector {
    /// Let the chain adapter/runtime pick funding automatically (e.g. a
    /// freshly-created seal with an adapter-managed value).
    Automatic,
    /// Use a specific, caller-identified funding reference (e.g. a Bitcoin
    /// `txid:vout`). The runtime/adapter is responsible for validating that
    /// the referenced output is actually spendable before anchoring.
    Explicit {
        /// Chain-specific reference string (e.g. `"<txid>:<vout>"`).
        reference: String,
    },
}

/// Whether a Sanad creation request should actually be anchored on-chain.
///
/// `--skip-publish` (or any equivalent caller option) must map to
/// [`PublishPolicy::DraftOnly`], which can only ever produce a
/// [`SanadDraft`] — an explicitly unpublished, unsigned-for-chain export.
/// It must never be able to produce a [`Sanad`] that looks like a real,
/// actively-anchored Sanad (SANAD-CREATE-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishPolicy {
    /// Publish the commitment under a seal on-chain and return a real,
    /// anchored Sanad.
    Publish,
    /// Do not publish anything on-chain. Produces a local-only draft that
    /// cannot be mistaken for an active Sanad.
    DraftOnly,
}

/// A typed, canonical request to create a Sanad.
///
/// The CLI (or any other caller) builds this request; the SDK/runtime is
/// responsible for executing it. No chain-specific business logic belongs
/// in the request itself — `chain` simply selects which adapter executes
/// the request.
#[derive(Debug, Clone)]
pub struct CreateSanadRequest {
    /// The chain the Sanad's seal will be anchored on.
    pub chain: ChainId,
    /// The owner's address/identifier bytes.
    pub owner: Vec<u8>,
    /// Chain-specific value (e.g. sats for Bitcoin). `None` lets the adapter
    /// pick a default; this is intentionally distinct from "missing
    /// descriptor field" semantics, which always fail closed instead.
    pub value: Option<u64>,
    /// Explicit content descriptor inputs. See [`ContentDescriptorInput`].
    pub content_descriptor: ContentDescriptorInput,
    /// How seal funding should be selected.
    pub funding_selector: FundingSelector,
    /// Whether to actually publish on-chain, or only produce a local draft.
    pub publish_policy: PublishPolicy,
}

/// A local-only, unpublished Sanad creation draft.
///
/// Produced when [`PublishPolicy::DraftOnly`] is requested (e.g.
/// `--skip-publish`). A draft is **not** a real, active Sanad: it has no
/// seal anchor, no on-chain transaction, and no finality status, and it
/// must never be persisted or displayed as if it were one.
#[derive(Debug, Clone)]
pub struct SanadDraft {
    /// The descriptor that would be bound into the Sanad ID once published.
    pub descriptor: SanadPayloadDescriptor,
    /// The commitment hash that would be published.
    pub commitment: Hash,
    /// The ownership proof that would accompany publication.
    pub owner: OwnershipProof,
    /// The salt that would be used for ID derivation.
    pub salt: Vec<u8>,
    /// The chain this draft targets.
    pub chain: ChainId,
}

/// The canonical result of successfully creating and publishing a Sanad.
///
/// Carries everything the acceptance criteria for SANAD-CREATE-001 require:
/// the canonical Sanad ID, seal reference, owner, commitment, anchor
/// transaction, block height, and finality status.
#[derive(Debug, Clone)]
pub struct SanadCreationResult {
    /// The canonical Sanad.
    pub sanad: Sanad,
    /// The seal reference (chain-specific encoded seal bytes) the Sanad is anchored to.
    pub seal_ref: Vec<u8>,
    /// The owner address/identifier bytes.
    pub owner: Vec<u8>,
    /// The commitment hash bound into the Sanad.
    pub commitment: Hash,
    /// The on-chain anchor produced by publishing the seal.
    pub anchor: CommitAnchor,
    /// Whether the anchor has reached the chain's configured finality depth.
    /// `false` means the Sanad is anchored but not yet final; callers must
    /// not treat it as irreversible until this is `true`.
    pub finalized: bool,
}

impl CreateSanadRequest {
    /// Validate that all descriptor fields required by the protocol are
    /// present, and resolve them into a [`SanadPayloadDescriptor`].
    ///
    /// This is the single fail-closed gate for "missing required descriptor
    /// field": there is no fallback to an all-zero hash anywhere in this
    /// path. Callers that omit a required field get a typed
    /// [`CsvError::InvalidInput`], never a fabricated value.
    pub fn build_descriptor(&self) -> Result<SanadPayloadDescriptor, CsvError> {
        let d = &self.content_descriptor;

        let schema_hash = d.schema_hash.ok_or_else(|| {
            CsvError::InvalidInput(
                "content_descriptor.schema_hash is required and was not provided".to_string(),
            )
        })?;
        let payload_hash = d.payload_hash.ok_or_else(|| {
            CsvError::InvalidInput(
                "content_descriptor.payload_hash is required and was not provided".to_string(),
            )
        })?;
        let disclosure_policy_hash = d.disclosure_policy_hash.ok_or_else(|| {
            CsvError::InvalidInput(
                "content_descriptor.disclosure_policy_hash is required and was not provided"
                    .to_string(),
            )
        })?;
        let proof_policy_hash = d.proof_policy_hash.ok_or_else(|| {
            CsvError::InvalidInput(
                "content_descriptor.proof_policy_hash is required and was not provided"
                    .to_string(),
            )
        })?;

        let schema_id = d
            .schema_id
            .clone()
            .unwrap_or_else(|| SanadPayloadDescriptor::SCHEMA_ID.to_string());
        let payload_codec = d.payload_codec.unwrap_or(1); // 1 = canonical CBOR

        let mut descriptor = SanadPayloadDescriptor::new(
            schema_id,
            schema_hash,
            payload_codec,
            payload_hash,
            d.content_root,
            disclosure_policy_hash,
            proof_policy_hash,
        );

        if let Some(attachment_root) = d.attachment_root {
            descriptor = descriptor.with_attachment_root(attachment_root);
        }

        Ok(descriptor)
    }
}

/// Filter options for listing Sanads.
#[derive(Debug, Clone, Default)]
pub struct SanadFilters {
    /// Filter by chain (the chain where the seal is anchored).
    pub chain: Option<ChainId>,
    /// Filter by owner address.
    pub owner: Option<String>,
    /// Filter by consumed status.
    pub consumed: Option<bool>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

/// Manager for Sanad operations.
///
/// Obtain a [`SanadsManager`] via [`CsvClient::sanads()`](crate::client::CsvClient::sanads).
///
/// # Example
///
/// ```ignore
/// use csv_sdk::prelude::*;
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let client = CsvClient::builder()
/// #     .with_chain(ChainId::new("bitcoin"))
/// #     .with_store_backend(StoreBackend::InMemory)
/// #     .build()?;
/// let sanads = client.sanads();
///
/// // List all Sanads
/// let all_sanads = sanads.list(SanadFilters::default())?;
/// # Ok(())
/// # }
/// ```
pub struct SanadsManager {
    client: Arc<ClientRef>,
}

impl SanadsManager {
    pub(crate) fn new(client: Arc<ClientRef>) -> Self {
        Self { client }
    }

    /// Create a new Sanad anchored to the specified chain.
    ///
    /// This is the **only** method for creating Sanads. It requires:
    /// 1. A [`SanadPayloadDescriptor`] binding content metadata to the Sanad ID
    /// 2. A signed [`OwnershipProof`] from the wallet
    /// 3. A commitment hash binding the Sanad's state
    /// 4. Salt bytes for uniqueness in ID derivation
    ///
    /// ## Workflow
    ///
    /// 1. Create a [`SanadPayloadDescriptor`] with schema, payload hash, and content roots
    /// 2. Sign the descriptor hash with the wallet's secret key
    /// 3. Create the seal on the target chain (via chain adapter)
    /// 4. Construct the Sanad with the descriptor, commitment, and ownership proof
    /// 5. Persist to local store and emit event
    ///
    /// # Arguments
    ///
    /// * `descriptor` — The payload descriptor binding content metadata to the Sanad
    /// * `commitment` — The commitment hash binding the Sanad's state
    /// * `owner` — The ownership proof (wallet signature over descriptor hash)
    /// * `salt` — Salt bytes for uniqueness in ID derivation
    /// * `chain` — The chain where the seal will be anchored
    ///
    /// # Returns
    ///
    /// The newly created [`Sanad`] with a unique [`SanadId`] that binds:
    /// - The descriptor hash (content metadata)
    /// - The commitment hash (state binding)
    /// - The salt (uniqueness)
    ///
    /// # Errors
    ///
    /// - [`CsvError::ChainNotSupported`] if the chain is not enabled.
    /// - [`CsvError::InvalidInput`] if the ownership proof is malformed.
    /// - [`CsvError::SerializationError`] if the Sanad cannot be serialized.
    pub fn create(
        &self,
        descriptor: &csv_protocol::SanadPayloadDescriptor,
        commitment: Hash,
        owner: csv_protocol::OwnershipProof,
        salt: &[u8],
        chain: ChainId,
    ) -> Result<Sanad, CsvError> {
        if !self.client.is_chain_enabled(chain.clone()) {
            return Err(CsvError::ChainNotSupported(chain.clone()));
        }

        // Validate ownership proof structure
        if owner.owner.is_empty() {
            return Err(CsvError::InvalidInput(
                "Ownership proof owner field is empty".to_string(),
            ));
        }
        if owner.proof.is_empty() {
            return Err(CsvError::InvalidInput(
                "Ownership proof signature bytes are empty".to_string(),
            ));
        }

        let sanad = Sanad::new(descriptor, commitment, owner, salt);

        // Persist the Sanad to the store
        let sanad_id_hex = sanad.id.bytes.clone();
        let record = SanadRecord {
            sanad_id: sanad_id_hex.clone(),
            chain: chain.to_string(),
            owner: sanad.owner.owner.clone(),
            sanad_data: sanad.to_canonical_bytes().map_err(|e| {
                CsvError::SerializationError(format!("Failed to serialize Sanad: {:?}", e))
            })?,
            consumed: false,
            recorded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            consumed_at: None,
        };

        // Lock the store and save the sanad
        let mut store = self
            .client
            .store
            .lock()
            .map_err(|_| CsvError::StoreError("Failed to acquire store lock".to_string()))?;
        store.save_sanad(&record)?;
        drop(store); // Release lock before emitting event

        let sanad_id = csv_hash::sanad::SanadId::from_bytes(
            &hex::decode(&sanad_id_hex).unwrap_or_default()
        );
        self.client.emit_event(crate::events::Event::SanadCreated {
            sanad_id,
            chain,
        });

        Ok(sanad)
    }

    /// Build a local-only, unpublished draft from a [`CreateSanadRequest`].
    ///
    /// This is the **only** outcome [`PublishPolicy::DraftOnly`] (e.g.
    /// `--skip-publish`) can ever produce. It performs no chain I/O, persists
    /// nothing, and emits no events — the returned [`SanadDraft`] has no
    /// seal anchor, no transaction, and no finality status, so it can never
    /// be mistaken for a real, active Sanad (SANAD-CREATE-001).
    ///
    /// Required descriptor fields are validated and fail closed via
    /// [`CreateSanadRequest::build_descriptor`]; missing fields produce
    /// [`CsvError::InvalidInput`], never an all-zero hash default.
    ///
    /// # Errors
    ///
    /// - [`CsvError::InvalidInput`] if `request.publish_policy` is not
    ///   [`PublishPolicy::DraftOnly`], if `request.owner` is empty, or if a
    ///   required content descriptor field is missing.
    pub fn create_draft(
        &self,
        request: &CreateSanadRequest,
        commitment: Hash,
        owner_proof: OwnershipProof,
        salt: &[u8],
    ) -> Result<SanadDraft, CsvError> {
        if request.publish_policy != PublishPolicy::DraftOnly {
            return Err(CsvError::InvalidInput(
                "create_draft requires PublishPolicy::DraftOnly; use finalize_published() for PublishPolicy::Publish".to_string(),
            ));
        }
        if request.owner.is_empty() {
            return Err(CsvError::InvalidInput(
                "CreateSanadRequest.owner must not be empty".to_string(),
            ));
        }
        if owner_proof.owner.is_empty() || owner_proof.proof.is_empty() {
            return Err(CsvError::InvalidInput(
                "Ownership proof must have non-empty owner and signature bytes".to_string(),
            ));
        }

        let descriptor = request.build_descriptor()?;

        Ok(SanadDraft {
            descriptor,
            commitment,
            owner: owner_proof,
            salt: salt.to_vec(),
            chain: request.chain.clone(),
        })
    }

    /// Finalize a [`CreateSanadRequest`] with [`PublishPolicy::Publish`] into
    /// a canonical, persisted [`SanadCreationResult`].
    ///
    /// The caller (typically the CLI) is responsible for performing the
    /// actual on-chain publish via [`crate::runtime::ChainRuntime`] — that is
    /// chain-specific execution, not SDK-level business logic. This method
    /// is the single place that turns a successful publish into the
    /// canonical record: it validates the request, builds and binds the
    /// descriptor, derives the Sanad, persists it, and emits the creation
    /// event.
    ///
    /// # Arguments
    ///
    /// * `request` — The original typed creation request (must use
    ///   [`PublishPolicy::Publish`]).
    /// * `commitment` — The commitment hash that was actually published.
    /// * `owner_proof` — The ownership proof accompanying the publish.
    /// * `salt` — Salt bytes used for Sanad ID derivation.
    /// * `seal_ref` — Chain-specific encoded seal bytes the commitment was published under.
    /// * `anchor` — The [`CommitAnchor`] returned by the chain adapter/runtime publish call.
    /// * `finalized` — Whether the anchor has reached the chain's configured finality depth.
    ///
    /// # Errors
    ///
    /// - [`CsvError::InvalidInput`] if `request.publish_policy` is not
    ///   [`PublishPolicy::Publish`], or required fields are missing/empty.
    /// - [`CsvError::ChainNotSupported`] if the chain is not enabled.
    /// - [`CsvError::SerializationError`] if the Sanad cannot be serialized.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_published(
        &self,
        request: &CreateSanadRequest,
        commitment: Hash,
        owner_proof: OwnershipProof,
        salt: &[u8],
        seal_ref: Vec<u8>,
        anchor: CommitAnchor,
        finalized: bool,
    ) -> Result<SanadCreationResult, CsvError> {
        if request.publish_policy != PublishPolicy::Publish {
            return Err(CsvError::InvalidInput(
                "finalize_published requires PublishPolicy::Publish; use create_draft() for PublishPolicy::DraftOnly".to_string(),
            ));
        }

        let descriptor = request.build_descriptor()?;
        let sanad = self.create(&descriptor, commitment, owner_proof, salt, request.chain.clone())?;

        Ok(SanadCreationResult {
            sanad,
            seal_ref,
            owner: request.owner.clone(),
            commitment,
            anchor,
            finalized,
        })
    }

    /// Get a Sanad by its ID.
    ///
    /// # Note
    ///
    /// Sanads exist in client state, not on-chain. This method queries
    /// the local store for previously created or received Sanads.
    pub fn get(&self, sanad_id: &SanadId) -> Result<Option<Sanad>, CsvError> {
        // Query the local store for the Sanad by ID
        let store = self
            .client
            .store
            .lock()
            .map_err(|_| CsvError::StoreError("Failed to acquire store lock".to_string()))?;

        let sanad_id_hex = hex::encode(sanad_id.as_bytes());
        match store.get_sanad(&sanad_id_hex)? {
            Some(record) => {
                // Deserialize the Sanad from stored data
                let sanad = Sanad::from_canonical_bytes(&record.sanad_data).map_err(|e| {
                    CsvError::SerializationError(format!("Failed to deserialize Sanad: {:?}", e))
                })?;
                Ok(Some(sanad))
            }
            None => Ok(None),
        }
    }

    /// List Sanads matching the given filters.
    ///
    /// # Note
    ///
    /// This method queries the local store and filters results in memory.
    /// This is acceptable for client-side local stores. For large-scale deployments
    /// with persistent backends, consider implementing store-side filtering.
    pub fn list(&self, filters: SanadFilters) -> Result<Vec<Sanad>, CsvError> {
        let store = self
            .client
            .store
            .lock()
            .map_err(|_| CsvError::StoreError("Failed to acquire store lock".to_string()))?;

        // Query local store for all active sanads
        let records = store.list_active_sanads()?;

        // Apply filters and deserialize
        let mut sanads = Vec::new();
        for record in records {
            // Deserialize the Sanad
            let sanad = match Sanad::from_canonical_bytes(&record.sanad_data) {
                Ok(r) => r,
                Err(e) => {
                    // Log warning but skip invalid records
                    eprintln!("Warning: Failed to deserialize Sanad record: {:?}", e);
                    continue;
                }
            };

            // Apply filters
            if let Some(ref chain) = filters.chain
                && record.chain != chain.to_string()
            {
                continue;
            }

            if let Some(ref owner) = filters.owner
                && record.owner != owner.as_bytes()
            {
                continue;
            }

            if let Some(consumed) = filters.consumed
                && record.consumed != consumed
            {
                continue;
            }

            sanads.push(sanad);
        }

        // Apply limit if specified
        if let Some(limit) = filters.limit {
            sanads.truncate(limit);
        }

        Ok(sanads)
    }

    /// Transfer a Sanad to a new owner on a different chain.
    ///
    /// # Deprecated
    ///
    /// Cross-chain transfers should be performed through [`TransferManager`],
    /// which provides runtime-backed execution with replay protection,
    /// durable recovery, and canonical verification.
    ///
    /// Use `CsvClient::transfers().cross_chain(sanad_id, to_chain)` instead.
    ///
    /// # Errors
    ///
    /// Always returns [`CsvError::ChainNotEnabled`] directing users to TransferManager.
    #[deprecated(since = "0.5.0", note = "Use CsvClient::transfers().cross_chain() instead")]
    pub fn transfer(
        &self,
        sanad_id: &SanadId,
        to_chain: ChainId,
        to_address: String,
    ) -> Result<String, CsvError> {
        if !self.client.is_chain_enabled(to_chain.clone()) {
            return Err(CsvError::ChainNotSupported(to_chain));
        }

        // Cross-chain transfers require runtime coordination through TransferCoordinator.
        // This method is deprecated - use TransferManager for production-grade transfers.
        Err(CsvError::ChainNotEnabled(format!(
            "Cross-chain transfer requires runtime coordination. \
             Use CsvClient::transfers().cross_chain({:?}, {:?}).to_address(\"{}\") instead. \
             Sanad: {:?}, To: {} on {:?}",
            sanad_id, to_chain, to_address, sanad_id, to_address, to_chain
        )))
    }

    /// Burn (permanently consume) a Sanad.
    ///
    /// This is an irreversible operation that destroys the Sanad by
    /// consuming its seal without creating a new one.
    ///
    /// # Note
    ///
    /// Burn operations require chain adapter integration with RPC connectivity.
    /// This method requires the client to be built with chain configuration
    /// and adapters initialized via `init_adapters()`.
    ///
    /// # Arguments
    ///
    /// * `sanad_id` — The Sanad to burn.
    ///
    /// # Errors
    ///
    /// - [`CsvError::ChainNotEnabled`] if chain adapter is not configured.
    /// - [`CsvError::SanadNotFound`] if the Sanad does not exist.
    pub fn burn(&self, sanad_id: &SanadId) -> Result<(), CsvError> {
        // Burn operations require chain adapter with RPC connectivity.
        // SanadsManager only has access to local store (not chain adapters).
        // Burn operations should be performed through CsvClient::chain_runtime()
        // when the client has chain adapters configured.
        //
        // This is a fail-closed API: it explicitly requires runtime configuration
        // rather than returning placeholder values or silently failing.
        Err(CsvError::ChainNotEnabled(format!(
            "Burn operation requires configured chain adapter with RPC endpoint. \
             Use CsvClient::chain_runtime() when client is built with chain configuration. \
             Sanad ID: {:?}",
            sanad_id
        )))
    }
}

#[cfg(test)]
mod create_request_tests {
    use super::*;

    fn base_request() -> CreateSanadRequest {
        CreateSanadRequest {
            chain: ChainId::new("ethereum"),
            owner: vec![1, 2, 3, 4],
            value: Some(100),
            content_descriptor: ContentDescriptorInput::default(),
            funding_selector: FundingSelector::Automatic,
            publish_policy: PublishPolicy::DraftOnly,
        }
    }

    fn full_descriptor() -> ContentDescriptorInput {
        ContentDescriptorInput {
            schema_id: None,
            schema_hash: Some(Hash::sha256(b"schema")),
            payload_codec: None,
            payload_hash: Some(Hash::sha256(b"payload")),
            content_root: None,
            attachment_root: None,
            disclosure_policy_hash: Some(Hash::sha256(b"disclosure")),
            proof_policy_hash: Some(Hash::sha256(b"proof")),
        }
    }

    /// SANAD-CREATE-001: a missing required descriptor field must fail closed
    /// with a typed error, never fall back to an all-zero hash.
    #[test]
    fn missing_payload_hash_fails_closed() {
        let mut request = base_request();
        request.content_descriptor = ContentDescriptorInput {
            payload_hash: None,
            ..full_descriptor()
        };

        let err = request.build_descriptor().unwrap_err();
        match err {
            CsvError::InvalidInput(msg) => assert!(msg.contains("payload_hash")),
            other => panic!("expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn missing_schema_hash_fails_closed() {
        let mut request = base_request();
        request.content_descriptor = ContentDescriptorInput {
            schema_hash: None,
            ..full_descriptor()
        };
        assert!(matches!(
            request.build_descriptor(),
            Err(CsvError::InvalidInput(_))
        ));
    }

    #[test]
    fn missing_disclosure_policy_hash_fails_closed() {
        let mut request = base_request();
        request.content_descriptor = ContentDescriptorInput {
            disclosure_policy_hash: None,
            ..full_descriptor()
        };
        assert!(matches!(
            request.build_descriptor(),
            Err(CsvError::InvalidInput(_))
        ));
    }

    #[test]
    fn missing_proof_policy_hash_fails_closed() {
        let mut request = base_request();
        request.content_descriptor = ContentDescriptorInput {
            proof_policy_hash: None,
            ..full_descriptor()
        };
        assert!(matches!(
            request.build_descriptor(),
            Err(CsvError::InvalidInput(_))
        ));
    }

    /// A fully-populated descriptor must never silently substitute a zero
    /// hash for any required field.
    #[test]
    fn complete_descriptor_builds_without_zero_hash_substitution() {
        let mut request = base_request();
        request.content_descriptor = full_descriptor();

        let descriptor = request.build_descriptor().expect("should build");
        let zero_hex = hex::encode([0u8; 32]);
        assert_ne!(descriptor.schema_hash.bytes, zero_hex);
        assert_eq!(
            descriptor.payload_hash.bytes,
            hex::encode(request.content_descriptor.payload_hash.unwrap().as_bytes())
        );
    }

    /// `--skip-publish` (PublishPolicy::DraftOnly) must only ever be able to
    /// produce a SanadDraft, never something that looks like a published
    /// anchor/result.
    #[test]
    fn draft_only_policy_produces_draft_with_no_anchor() {
        let client = Arc::new(ClientRef::new());
        let manager = SanadsManager::new(client);

        let mut request = base_request();
        request.content_descriptor = full_descriptor();
        request.publish_policy = PublishPolicy::DraftOnly;

        let owner_proof = OwnershipProof {
            owner: vec![9, 9, 9],
            proof: vec![1, 1, 1],
            scheme: None,
        };
        let commitment = Hash::sha256(b"commitment");
        let salt = [7u8; 16];

        let draft = manager
            .create_draft(&request, commitment, owner_proof, &salt)
            .expect("draft should build");

        // SanadDraft has no anchor/seal_ref/finality fields at all -- the
        // type itself makes "draft pretending to be published" impossible.
        assert_eq!(draft.commitment.as_bytes(), commitment.as_bytes());
        assert_eq!(draft.chain, request.chain);
    }

    /// Calling create_draft with PublishPolicy::Publish must fail closed
    /// rather than silently treating a publish request as a draft.
    #[test]
    fn create_draft_rejects_publish_policy() {
        let client = Arc::new(ClientRef::new());
        let manager = SanadsManager::new(client);

        let mut request = base_request();
        request.content_descriptor = full_descriptor();
        request.publish_policy = PublishPolicy::Publish;

        let owner_proof = OwnershipProof {
            owner: vec![9, 9, 9],
            proof: vec![1, 1, 1],
            scheme: None,
        };

        let result = manager.create_draft(
            &request,
            Hash::sha256(b"commitment"),
            owner_proof,
            &[7u8; 16],
        );
        assert!(matches!(result, Err(CsvError::InvalidInput(_))));
    }

    /// Calling finalize_published with PublishPolicy::DraftOnly must fail
    /// closed: a skip-publish request must never be finalized as if it were
    /// a real, anchored Sanad.
    #[test]
    fn finalize_published_rejects_draft_only_policy() {
        let client = Arc::new(ClientRef::new());
        let manager = SanadsManager::new(client);

        let mut request = base_request();
        request.content_descriptor = full_descriptor();
        request.publish_policy = PublishPolicy::DraftOnly;

        let owner_proof = OwnershipProof {
            owner: vec![9, 9, 9],
            proof: vec![1, 1, 1],
            scheme: None,
        };
        let anchor = CommitAnchor {
            anchor_id: vec![1, 2, 3],
            block_height: 10,
            metadata: vec![],
        };

        let result = manager.finalize_published(
            &request,
            Hash::sha256(b"commitment"),
            owner_proof,
            &[7u8; 16],
            vec![0xAA],
            anchor,
            false,
        );
        assert!(matches!(result, Err(CsvError::InvalidInput(_))));
    }
}
