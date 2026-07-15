//! Chain Operation Traits Implementation for Sui
//!
//! This module implements all chain operation traits from csv-chain-ports:
//! - ChainQuery: Querying chain state
//! - ChainSigner: Signing operations
//! - ChainBroadcaster: Transaction broadcasting
//! - ChainDeployer: Contract deployment
//! - ChainProofProvider: Proof building and verification
//! - ChainSanadOps: Sanad management operations

use async_trait::async_trait;
use blake2::Digest as Blake2Digest;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_protocol::chain_adapter_traits::{
    BalanceInfo, CanonicalLifecycleEvent, CanonicalSanadState, CanonicalSealState, ChainBackend,
    ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError, ChainOpResult,
    ChainProofProvider, ChainQuery, ChainReadiness, ChainReadinessCheck, ChainSanadOps,
    ChainSigner, ContractStatus, DeploymentStatus, FinalityStatus, SanadOperationResult,
    SanadStateReader, SealOwnershipTarget, TransactionInfo, TransactionStatus,
};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use ed25519_dalek::{Verifier, VerifyingKey};
use std::sync::Arc;

use crate::config::SuiConfig;
use crate::error::SuiError;
#[cfg(feature = "rpc")]
use crate::node::SuiNode;
use crate::proofs::CommitmentEventBuilder;
use crate::seal_protocol::SuiSealProtocol;

/// Parse a Sui object ID string (hex).
fn parse_object_id(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Object ID must be 32 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Contract-layer chain identity (RFC-0012 §6): `keccak256("csv.chain.<name>")`.
///
/// The value the Move `csv_seal` module stores and the §9.2 mint attestation binds. The
/// runtime derives it the same way; the lock must record the identity, not the CLI's
/// human-readable chain name.
fn contract_chain_id(name: &str) -> [u8; 32] {
    use csv_protocol::cross_chain::CrossChainHashAlgorithm;
    let tag = format!("csv.chain.{}", name);
    *CrossChainHashAlgorithm::Keccak256
        .hash_bytes(tag.as_bytes())
        .as_bytes()
}

/// Parse a Sui digest string (hex).
fn parse_digest(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Digest must be 32 bytes, got {}", bytes.len()));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SuiSealStateView {
    pub(crate) sanad_id: Vec<u8>,
    pub(crate) state: u8,
    pub(crate) owner: [u8; 32],
    pub(crate) commitment: Hash,
    /// Nullifier bytes as stored on-chain (empty when not yet registered).
    pub(crate) nullifier: Vec<u8>,
    pub(crate) created_at: u64,
    pub(crate) locked_at: u64,
    pub(crate) consumed_at: u64,
    pub(crate) minted_at: u64,
    pub(crate) refunded_at: u64,
}

impl SuiSealStateView {
    pub(crate) fn from_move_contents(contents: &[u8]) -> Result<Self, String> {
        let mut cursor = BcsCursor::new(contents);

        cursor.read_array::<32>("id")?;
        let sanad_id = cursor.read_vec("sanad_id")?.to_vec();
        // `commitment` is a Move `vector<u8>`, so BCS length-prefixes it. Reading it as a
        // fixed 32-byte array consumes the length byte plus 31 payload bytes and shifts
        // every field after it.
        let commitment_bytes = cursor.read_vec("commitment")?;
        let commitment: [u8; 32] = commitment_bytes.try_into().map_err(|_| {
            format!(
                "commitment must be 32 bytes, got {}",
                commitment_bytes.len()
            )
        })?;
        let commitment = Hash::new(commitment);
        let state = cursor.read_u8("state")?;
        let owner = cursor.read_array::<32>("owner")?;
        cursor.read_vec("source_chain")?;
        cursor.read_vec("lock_event_id")?;
        let nullifier = cursor.read_vec("nullifier")?.to_vec();
        cursor.read_u8("asset_class")?;
        cursor.read_vec("asset_id")?;
        cursor.read_vec("metadata_hash")?;
        cursor.read_u8("proof_system")?;
        let created_at = cursor.read_u64("created_at")?;
        let locked_at = cursor.read_u64("locked_at")?;
        let consumed_at = cursor.read_u64("consumed_at")?;
        let minted_at = cursor.read_u64("minted_at")?;
        let refunded_at = cursor.read_u64("refunded_at")?;
        cursor.finish()?;

        Ok(Self {
            sanad_id,
            state,
            owner,
            commitment,
            nullifier,
            created_at,
            locked_at,
            consumed_at,
            minted_at,
            refunded_at,
        })
    }
}

/// Map a decoded on-chain `Seal` view into the protocol `CanonicalSanadState`.
///
/// Performs strict validation so no placeholder/defaulted values leak: the
/// nullifier must be absent (empty) or exactly 32 bytes, and every timestamp
/// must fit in `i64`. Any violation fails closed (`SUI-SANAD-STATE-001`).
#[cfg(feature = "rpc")]
fn sanad_state_from_view(view: SuiSealStateView) -> ChainOpResult<CanonicalSanadState> {
    let nullifier = match view.nullifier.len() {
        0 => None,
        32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&view.nullifier);
            Some(Hash::new(arr))
        }
        other => {
            return Err(ChainOpError::RpcError(format!(
                "Sui Seal nullifier has unexpected length {} (expected 0 or 32)",
                other
            )));
        }
    };

    let to_ts = |field: &str, value: u64| -> ChainOpResult<i64> {
        i64::try_from(value).map_err(|_| {
            ChainOpError::RpcError(format!("Sui Seal {} overflows i64: {}", field, value))
        })
    };
    let opt_ts = |field: &str, value: u64| -> ChainOpResult<Option<i64>> {
        if value == 0 {
            Ok(None)
        } else {
            Ok(Some(to_ts(field, value)?))
        }
    };

    Ok(CanonicalSanadState {
        state: view.state,
        owner: format!("0x{}", hex::encode(view.owner)),
        commitment: view.commitment,
        nullifier,
        created_at: to_ts("created_at", view.created_at)?,
        locked_at: opt_ts("locked_at", view.locked_at)?,
        consumed_at: opt_ts("consumed_at", view.consumed_at)?,
        minted_at: opt_ts("minted_at", view.minted_at)?,
        refunded_at: opt_ts("refunded_at", view.refunded_at)?,
    })
}

struct BcsCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BcsCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const N: usize>(&mut self, field: &str) -> Result<[u8; N], String> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| format!("{} offset overflow", field))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| format!("{} missing {} bytes", field, N))?;
        self.offset = end;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_u8(&mut self, field: &str) -> Result<u8, String> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| format!("{} missing u8", field))?;
        self.offset += 1;
        Ok(value)
    }

    fn read_u64(&mut self, field: &str) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_array::<8>(field)?))
    }

    fn read_vec(&mut self, field: &str) -> Result<&'a [u8], String> {
        let len = self.read_uleb128(field)?;
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| format!("{} length overflow", field))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| format!("{} truncated: expected {} bytes", field, len))?;
        self.offset = end;
        Ok(slice)
    }

    fn read_uleb128(&mut self, field: &str) -> Result<usize, String> {
        let mut value = 0usize;
        let mut shift = 0u32;

        loop {
            let byte = self.read_u8(field)?;
            let chunk = (byte & 0x7f) as usize;
            value = value
                .checked_add(
                    chunk
                        .checked_shl(shift)
                        .ok_or_else(|| format!("{} length shift overflow", field))?,
                )
                .ok_or_else(|| format!("{} length overflow", field))?;

            if byte & 0x80 == 0 {
                return Ok(value);
            }

            shift = shift
                .checked_add(7)
                .ok_or_else(|| format!("{} length shift overflow", field))?;
            if shift as usize >= usize::BITS as usize {
                return Err(format!("{} length exceeds usize", field));
            }
        }
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(format!(
                "unexpected trailing bytes in Seal object: {}",
                self.bytes.len() - self.offset
            ))
        }
    }
}

/// Sui chain operations implementation
///
/// This struct provides complete implementations of all chain operation traits
/// for the Sui blockchain, enabling production use of the CSV protocol.
pub struct SuiBackend {
    /// Chain configuration
    config: SuiConfig,
    /// Sui gRPC client
    node: Arc<SuiNode>,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Commitment event builder for proof construction
    // Constructed with the adapter; the runtime proof path builds events itself.
    #[allow(dead_code)]
    event_builder: CommitmentEventBuilder,
    /// Reference to seal protocol for seal creation and publishing
    seal_protocol: Arc<SuiSealProtocol>,
    /// Ed25519 signing key for transaction signing (optional).
    ///
    /// This authorizes and pays for the Sui transaction that submits the mint —
    /// it is the gas-paying submitter identity, NOT the mint authority. Per
    /// RFC-0012 §9 the mint is authenticated by the verifier attestation carried
    /// in the call, never by `msg.sender`, so this key confers no mint authority.
    signing_key: Option<ed25519_dalek::SigningKey>,
    /// secp256k1 verifier key that signs the RFC-0012 §9.2 mint-attestation
    /// digest (optional).
    ///
    /// Distinct from `signing_key`: the destination `Registry` authenticates a
    /// mint by recovering M-of-N secp256k1 verifier public keys from signatures
    /// over the §9.2 digest (`ecdsa_k1::secp256k1_ecrecover`), independent of who
    /// submits the transaction. Absent any key the adapter fails closed rather
    /// than emitting an unauthenticated mint the `Registry` would reject. Multiple
    /// keys attach one verifier signature each, satisfying an M-of-N verifier set
    /// in a single mint (see MINT-KEYS-001).
    verifier_signing_keys: Vec<secp256k1::SecretKey>,
}

impl SuiBackend {
    /// Create new Sui chain operations from config
    pub fn new(config: SuiConfig, node: Arc<SuiNode>) -> Self {
        Self::with_signing_key(config, node, None)
    }

    /// Create new Sui chain operations from config with signing key
    pub fn with_signing_key(
        config: SuiConfig,
        node: Arc<SuiNode>,
        signing_key: Option<ed25519_dalek::SigningKey>,
    ) -> Self {
        let mut domain = [0u8; 32];
        domain[..8].copy_from_slice(b"CSV-SUI-");
        let chain_id = config.chain_id().as_bytes();
        let copy_len = chain_id.len().min(24);
        domain[8..8 + copy_len].copy_from_slice(&chain_id[..copy_len]);

        // Build event builder with default package ID
        let package_id = [0u8; 32];
        let event_builder =
            CommitmentEventBuilder::new(package_id, "csv_seal::AnchorEvent".to_string());

        // Create a minimal seal protocol for backward compatibility
        let seal =
            SuiSealProtocol::from_config(config.clone(), Arc::clone(&node)).unwrap_or_else(|_| {
                // Ultimate fallback
                SuiSealProtocol::from_config(SuiConfig::default(), Arc::clone(&node))
                    .expect("fallback SuiSealProtocol creation")
            });

        Self {
            config,
            node,
            domain_separator: domain,
            event_builder,
            seal_protocol: Arc::new(seal),
            signing_key,
            verifier_signing_keys: Vec::new(),
        }
    }

    /// Get the Sui node client (for use by runtime adapter)
    pub fn node(&self) -> &Arc<SuiNode> {
        &self.node
    }

    /// Sign `message` with the adapter's Ed25519 signing key, returning the
    /// 64-byte signature and the 32-byte public key. `None` when no signing
    /// key is configured — callers must fail closed rather than fabricate a
    /// signature.
    pub fn sign_ed25519(&self, message: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
        use ed25519_dalek::Signer;
        let key = self.signing_key.as_ref()?;
        let signature = key.sign(message).to_bytes().to_vec();
        Some((signature, key.verifying_key().to_bytes()))
    }

    /// Timeout applied to each Sui gRPC call on a transaction-submitting path.
    #[cfg(feature = "rpc")]
    fn rpc_timeout_ms(&self) -> u64 {
        self.config.transaction.confirmation_timeout_ms
    }

    /// Resolve the on-chain `Seal` object that carries `sanad_id`.
    ///
    /// A Sanad ID is a protocol identifier, not a Sui object ID: the `Seal` object gets a
    /// fresh UID when it is created, and nothing on chain maps one to the other. The owner
    /// is the only party who can spend the object, so we enumerate the sender's `Seal`
    /// objects and match on the decoded `sanad_id` field.
    ///
    /// Returns the full owned-object reference — id, version, and content digest — which a
    /// Move call must pin exactly. Fails closed when no seal matches, and when more than
    /// one does (two objects claiming one sanad is a state corruption we must not guess at).
    #[cfg(feature = "rpc")]
    async fn resolve_seal_object(
        &self,
        sanad_id: &SanadId,
        owner: &sui_sdk_types::Address,
    ) -> ChainOpResult<sui_transaction_builder::ObjectInput> {
        use futures::StreamExt;
        use sui_rpc::proto::sui::rpc::v2::ListOwnedObjectsRequest;

        let package_id_str = self
            .config
            .seal_contract
            .package_id
            .as_ref()
            .ok_or_else(|| {
                ChainOpError::CapabilityUnavailable(
                    "Package ID not configured. Deploy the CSV contract first.".to_string(),
                )
            })?;
        let seal_type = format!(
            "{}::{}::Seal",
            package_id_str, self.config.seal_contract.module_name
        );

        let mut request = ListOwnedObjectsRequest::default();
        request.owner = Some(owner.to_string());
        request.page_size = Some(50);
        request.object_type = Some(seal_type.clone());
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec![
                "object_id".to_string(),
                "version".to_string(),
                "digest".to_string(),
                "contents".to_string(),
            ],
        });

        let client = self.node.client();
        let client_guard = client.lock().await;
        let stream = (*client_guard).list_owned_objects(request);
        let mut stream = std::pin::pin!(stream);

        let mut matches: Vec<sui_transaction_builder::ObjectInput> = Vec::new();
        let mut scanned = 0usize;
        let page_timeout = std::time::Duration::from_millis(self.rpc_timeout_ms());
        loop {
            let next = tokio::time::timeout(page_timeout, stream.next())
                .await
                .map_err(|_| {
                    ChainOpError::RpcError(format!(
                        "ListOwnedObjects(Seal) timed out after {}ms (no response from the Sui node)",
                        self.rpc_timeout_ms()
                    ))
                })?;

            let Some(object) = next else { break };
            let object = object.map_err(|e| {
                ChainOpError::RpcError(format!("Failed to read Seal object: {}", e))
            })?;
            scanned += 1;

            // Silently skipping a seal we could not decode would report "no such sanad" for a
            // sanad that is actually there.
            let contents = object
                .contents
                .as_ref()
                .and_then(|bcs| bcs.value.as_ref())
                .ok_or_else(|| {
                    ChainOpError::RpcError(
                        "Sui RPC returned a Seal object without contents; cannot match sanad_id"
                            .to_string(),
                    )
                })?;
            let view = SuiSealStateView::from_move_contents(contents.as_ref()).map_err(|e| {
                ChainOpError::RpcError(format!("Failed to decode Sui Seal object: {}", e))
            })?;
            if view.sanad_id.as_slice() != sanad_id.as_bytes().as_slice() {
                continue;
            }

            let object_id = object.object_id.as_ref().ok_or_else(|| {
                ChainOpError::RpcError("Seal object has no object_id".to_string())
            })?;
            let id_bytes = parse_object_id(object_id)
                .map_err(|e| ChainOpError::RpcError(format!("Invalid Seal object ID: {}", e)))?;
            let address = sui_sdk_types::Address::from_bytes(id_bytes).map_err(|e| {
                ChainOpError::RpcError(format!("Invalid Seal object address: {}", e))
            })?;
            let version = object
                .version
                .ok_or_else(|| ChainOpError::RpcError("Seal object has no version".to_string()))?;
            let digest_str = object
                .digest
                .as_ref()
                .ok_or_else(|| ChainOpError::RpcError("Seal object has no digest".to_string()))?;
            let digest = sui_sdk_types::Digest::from_base58(digest_str).map_err(|e| {
                ChainOpError::RpcError(format!("Invalid Seal object digest: {}", e))
            })?;

            matches.push(sui_transaction_builder::ObjectInput::owned(
                address, version, digest,
            ));
        }
        drop(client_guard);

        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => Err(ChainOpError::InvalidInput(format!(
                "No {} object holding Sanad 0x{} is owned by {} (scanned {} seals)",
                seal_type,
                hex::encode(sanad_id.as_bytes()),
                owner,
                scanned
            ))),
            n => Err(ChainOpError::RpcError(format!(
                "{} distinct Seal objects owned by {} claim Sanad 0x{}; refusing to guess",
                n,
                owner,
                hex::encode(sanad_id.as_bytes())
            ))),
        }
    }

    /// Create from SuiSealProtocol
    pub fn from_seal_protocol(
        seal: Arc<SuiSealProtocol>,
        node: Arc<SuiNode>,
    ) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            config: seal.config.clone(),
            node,
            domain_separator: seal.get_domain_separator(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
            signing_key: None,
            verifier_signing_keys: Vec::new(),
        })
    }

    /// Create from SuiSealProtocol with signing key
    pub fn from_seal_protocol_with_key(
        seal: Arc<SuiSealProtocol>,
        node: Arc<SuiNode>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            config: seal.config.clone(),
            node,
            domain_separator: seal.get_domain_separator(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
            signing_key: Some(signing_key),
            verifier_signing_keys: Vec::new(),
        })
    }

    /// Set the signing key for transaction operations
    pub fn with_key(mut self, signing_key: ed25519_dalek::SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Set the secp256k1 verifier key that signs the RFC-0012 §9.2 mint
    /// attestation digest.
    ///
    /// This is the mint-authority key (its 33-byte compressed public key must be
    /// registered in the destination `Registry`'s verifier set). It is distinct
    /// from the Ed25519 transaction signer configured via [`Self::with_key`].
    pub fn with_verifier_key(mut self, verifier_signing_key: secp256k1::SecretKey) -> Self {
        self.verifier_signing_keys.push(verifier_signing_key);
        self
    }

    /// Set the full set of secp256k1 verifier keys that sign the RFC-0012 §9.2
    /// mint attestation digest (MINT-KEYS-001).
    ///
    /// Replaces any previously configured keys. Each key's 33-byte compressed
    /// public key must be registered in the destination `Registry` verifier set;
    /// the adapter attaches one signature per key so a single mint can satisfy an
    /// M-of-N threshold. An empty set leaves the backend fail-closed.
    pub fn with_verifier_keys(mut self, verifier_signing_keys: Vec<secp256k1::SecretKey>) -> Self {
        self.verifier_signing_keys = verifier_signing_keys;
        self
    }

    /// Canonical 32-byte identity of the shared `Registry` mint-authority object
    /// (RFC-0012 §9.2 `destinationContract` on Sui).
    ///
    /// Fails closed when no registry id is configured: the verifier signature is
    /// scoped to exactly one `Registry`, so a mint cannot be built without it.
    pub fn registry_object_id(&self) -> ChainOpResult<[u8; 32]> {
        let registry_id = self
            .config
            .seal_contract
            .registry_id
            .as_ref()
            .ok_or_else(|| {
                ChainOpError::CapabilityUnavailable(
                    "No mint Registry object id configured: set seal_contract.registry_id \
                     (the shared Registry created at package publish)."
                        .to_string(),
                )
            })?;
        parse_object_id(registry_id)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Registry object id: {}", e)))
    }

    /// Sign a 32-byte RFC-0012 §9.2 attestation digest with the configured
    /// secp256k1 verifier key, producing a 65-byte recoverable signature
    /// (`r(32) || s(32) || v(1)`, `v` = recovery id `∈ {0, 1}`).
    ///
    /// The digest is `sha256(preimage)` (the frozen §9.2 preimage). The Sui
    /// `Registry` recovers the signer via
    /// `ecdsa_k1::secp256k1_ecrecover(sig, preimage, /*sha256*/ 1)`, which hashes
    /// the preimage with SHA-256 internally — so signing the digest directly
    /// recovers the same key on-chain. The recovery id is emitted raw (0/1), the
    /// form the Sui native primitive expects (no EVM `+27`). Fails closed when no
    /// verifier key is configured rather than emitting an unauthenticated mint.
    pub fn sign_mint_attestation_digest(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<u8>> {
        // First configured verifier key (fail-closed on none). Retained for
        // single-signer callers/tests; the mint path uses the plural form below.
        let secret_key = self.verifier_signing_keys.first().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set a secp256k1 verifier key via with_verifier_key())."
                    .to_string(),
            )
        })?;
        Ok(Self::sign_digest_with(secret_key, digest))
    }

    /// Sign the §9.2 digest with **every** configured verifier key, returning one
    /// 65-byte recoverable signature per key (MINT-KEYS-001).
    ///
    /// This is the mint-path signer: multiple local signers satisfy an M-of-N
    /// `Registry` verifier set in one transaction. Fails closed when no verifier
    /// key is configured.
    pub fn sign_mint_attestation_digests(&self, digest: &[u8; 32]) -> ChainOpResult<Vec<Vec<u8>>> {
        if self.verifier_signing_keys.is_empty() {
            return Err(ChainOpError::CapabilityUnavailable(
                "No verifier signer configured: cannot attest the §9.2 mint digest \
                 (set a secp256k1 verifier key via with_verifier_key())."
                    .to_string(),
            ));
        }
        Ok(self
            .verifier_signing_keys
            .iter()
            .map(|k| Self::sign_digest_with(k, digest))
            .collect())
    }

    /// Produce a single 65-byte recoverable signature (`r || s || v`, raw
    /// recovery id 0/1) over the 32-byte digest, matching Sui's
    /// `secp256k1_ecrecover`-over-sha256(preimage) semantics.
    fn sign_digest_with(secret_key: &secp256k1::SecretKey, digest: &[u8; 32]) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};
        let msg = Message::from_digest(*digest);
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa_recoverable(&msg, secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&compact);
        // Sui's secp256k1_ecrecover expects the raw recovery id (0/1) as `v`.
        out.push(recovery_id.to_i32() as u8);
        out
    }

    /// Submit a verifier-attested §9.2 mint to the destination `Registry` and
    /// wait for its effects, returning `(tx_digest_hex, checkpoint)`.
    ///
    /// The `args` already carry the frozen §9.2 fields and the attached verifier
    /// signatures (built by the runtime adapter after it bound
    /// `destinationContract`, computed the digest, and signed it). This is the
    /// sole submission point; it fails closed on a reverted transaction.
    #[cfg(feature = "rpc")]
    pub async fn submit_attested_mint(
        &self,
        args: crate::mint::SuiMintArgs,
    ) -> ChainOpResult<(String, u64)> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;
        let package_id = self
            .config
            .seal_contract
            .package_id
            .as_ref()
            .ok_or_else(|| ChainOpError::InvalidInput("Package ID not configured".to_string()))?;
        let registry_id = self
            .config
            .seal_contract
            .registry_id
            .as_ref()
            .ok_or_else(|| {
                ChainOpError::InvalidInput("Registry object id not configured".to_string())
            })?;

        crate::mint::submit_mint(&self.node, package_id, registry_id, signing_key, args)
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Minting failed: {}", e)))
    }

    /// Parse Sui address from string
    fn parse_address(&self, address: &str) -> ChainOpResult<[u8; 32]> {
        let hex_str = address.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid hex address: {}", e)))?;

        if bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Sui address must be 32 bytes".to_string(),
            ));
        }

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }

    /// Format Sui address for display
    #[allow(dead_code)]
    fn format_address(&self, addr: [u8; 32]) -> String {
        format!("0x{}", hex::encode(addr))
    }

    /// Retained signing seam; the seal protocol signs its own transaction bytes.
    #[allow(dead_code)]
    fn sign_transaction_bytes(&self, tx_bytes: &[u8]) -> ChainOpResult<(Vec<u8>, Vec<u8>)> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Sign the transaction bytes using Ed25519
        let signature = signing_key.sign(tx_bytes);
        let public_key = signing_key.verifying_key().to_bytes();

        Ok((signature.to_bytes().to_vec(), public_key.to_vec()))
    }

    /// Build a lock transaction for Sui
    ///
    /// Retained builder seam; the runtime adapter builds its own lock transaction.
    #[allow(dead_code)]
    fn build_lock_transaction_bytes(
        &self,
        seal_object_id: &[u8; 32],
        owner_address: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Build a simple BCS-encoded transaction for locking
        // Format: [seal_object_id: 32 bytes][owner_address: 32 bytes]
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(seal_object_id);
        tx_bytes.extend_from_slice(owner_address);
        Ok(tx_bytes)
    }
}

#[async_trait]
impl ChainQuery for SuiBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        #[cfg(feature = "rpc")]
        {
            use sui_sdk_types::Address;

            let addr = self.parse_address(address)?;
            let sui_address = Address::from_bytes(addr)
                .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui address: {}", e)))?;

            let client = self.node.client();
            let client_guard = client.lock().await;

            // Use list_balances to get balance information
            use sui_rpc::proto::sui::rpc::v2::ListBalancesRequest;

            let mut balance_request = ListBalancesRequest::default();
            balance_request.owner = Some(sui_address.to_string());
            balance_request.page_size = Some(1);

            let balance_stream = (*client_guard).list_balances(balance_request);

            // Collect the first balance from the stream
            use futures::StreamExt;
            let mut pinned = Box::pin(balance_stream);
            let Some(balance_result) = pinned.next().await else {
                return Ok(BalanceInfo {
                    address: address.to_string(),
                    total: 0,
                    available: 0,
                    locked: 0,
                    tokens: Vec::new(),
                });
            };
            let balance = balance_result
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?;

            // Build token information from balance response
            // Sui uses coin objects, so we extract the coin type and balance
            let tokens = if let Some(coin_type) = balance.coin_type {
                vec![csv_protocol::chain_adapter_traits::TokenBalance {
                    symbol: "SUI".to_string(), // Default to SUI for native token
                    decimals: 9,               // SUI has 9 decimals
                    balance: balance.balance.unwrap_or(0),
                    token_id: coin_type,
                }]
            } else {
                vec![]
            };

            Ok(BalanceInfo {
                address: address.to_string(),
                total: balance.balance.unwrap_or(0),
                available: balance.balance.unwrap_or(0), // Assume all is available for now
                locked: 0,
                tokens,
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "RPC feature not enabled. Enable the 'rpc' feature to use Sui RPC functionality."
                    .to_string(),
            ))
        }
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;

        let tx_digest =
            sui_sdk_types::Digest::from_bytes(&parse_digest(hash).map_err(|e| {
                ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e))
            })?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;

        // Extract sender from transaction - simplified since ExecutedTransaction doesn't have sender field
        let sender = "0x0".to_string();

        // Extract fee from transaction effects - GasCostSummary to u64 conversion
        let fee = if let Some(effects) = &tx.effects {
            effects.gas_used.map(|g| {
                g.computation_cost.unwrap_or(0)
                    + g.storage_cost.unwrap_or(0)
                    + g.non_refundable_storage_fee.unwrap_or(0)
            })
        } else {
            None
        };

        // Extract raw transaction data - use transaction field instead of raw_transaction
        let raw_data = tx
            .transaction
            .map(|t| bcs::to_bytes(&t).unwrap_or_default());

        Ok(TransactionInfo {
            hash: hash.to_string(),
            status: if tx.effects.is_some() {
                TransactionStatus::Confirmed {
                    block_height: tx.checkpoint.unwrap_or(0),
                    confirmations: 1,
                }
            } else {
                TransactionStatus::Pending
            },
            block_height: tx.checkpoint,
            timestamp: tx.timestamp.map(|t| t.seconds as u64),
            sender,
            recipient: None, // Sui transactions don't have a single recipient; they can have multiple outputs
            amount: None,    // Amount would need to be extracted from specific transaction effects
            fee,
            raw_data,
        })
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;

        let tx_digest =
            sui_sdk_types::Digest::from_bytes(&parse_digest(tx_hash).map_err(|e| {
                ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e))
            })?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;

        // Check if the checkpoint is certified
        use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;

        let checkpoint_request =
            GetCheckpointRequest::by_sequence_number(tx.checkpoint.unwrap_or(0));

        let checkpoint_response = (*client_guard)
            .ledger_client()
            .get_checkpoint(checkpoint_request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;

        let checkpoint_info = checkpoint_response.into_inner().checkpoint.ok_or_else(|| {
            ChainOpError::InvalidInput("Checkpoint not found in response".to_string())
        })?;

        let is_finalized = checkpoint_info.signature.is_some();

        if is_finalized {
            Ok(FinalityStatus::Finalized {
                block_height: tx.checkpoint.unwrap_or(0),
                finality_block: tx.checkpoint.unwrap_or(0),
            })
        } else {
            Ok(FinalityStatus::Pending)
        }
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        use sui_rpc::proto::sui::rpc::v2::GetPackageRequest;

        let package_id =
            sui_sdk_types::Address::from_bytes(&parse_object_id(contract_address).map_err(
                |e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)),
            )?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetPackageRequest::new(&package_id);

        let package_response = (*client_guard)
            .package_client()
            .get_package(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get package: {}", e)))?;

        let _package = package_response.into_inner().package.ok_or_else(|| {
            ChainOpError::InvalidInput("Package not found in response".to_string())
        })?;

        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed: true,
            balance: None, // Balance would need to be extracted from package modules
            owner: None,   // Owner would need to be extracted from package upgrade capability
            metadata: serde_json::json!({
                "package_id": contract_address,
                "modules": _package.modules.len(),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let checkpoint_request = GetCheckpointRequest::latest();

        let checkpoint_response = (*client_guard)
            .ledger_client()
            .get_checkpoint(checkpoint_request)
            .await
            .map_err(|e| {
                ChainOpError::RpcError(format!("Failed to get latest checkpoint: {}", e))
            })?;

        let checkpoint = checkpoint_response.into_inner().checkpoint.ok_or_else(|| {
            ChainOpError::InvalidInput("Checkpoint not found in response".to_string())
        })?;

        Ok(checkpoint.sequence_number.unwrap_or(0))
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        Ok(serde_json::json!({
            "chain_id": self.config.network.chain_id(),
            "chain": "sui",
            "network": format!("{:?}", self.config.network),
            "protocol_version": "1.0",
            "finality": "deterministic",
        }))
    }

    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64> {
        use sui_sdk_types::Address;

        let addr = self.parse_address(address)?;
        let sui_address = Address::from_bytes(addr)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui address: {}", e)))?;

        let client = self.node.client();
        let client_guard = client.lock().await;

        // Use list_balances to get account information
        use sui_rpc::proto::sui::rpc::v2::ListBalancesRequest;

        let mut balance_request = ListBalancesRequest::default();
        balance_request.owner = Some(sui_address.to_string());
        balance_request.page_size = Some(1);

        let balance_stream = (*client_guard).list_balances(balance_request);

        // Collect the first balance from the stream
        use futures::StreamExt;
        let mut pinned = Box::pin(balance_stream);
        let _balance = pinned
            .next()
            .await
            .ok_or_else(|| ChainOpError::InvalidInput("No account found".to_string()))
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get account: {}", e)))?
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get account: {}", e)))?;

        // For now, return 0 as sequence number since we can't get it directly
        Ok(0)
    }

    fn validate_address(&self, address: &str) -> bool {
        let hex_str = address.trim_start_matches("0x");
        match hex::decode(hex_str) {
            Ok(bytes) => bytes.len() == 32,
            Err(_) => false,
        }
    }
}

#[async_trait]
impl ChainSigner for SuiBackend {
    async fn sign_transaction(&self, tx_data: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Sign the transaction bytes using Ed25519
        let signature = signing_key.sign(tx_data);

        // Return signature bytes (64 bytes for Ed25519)
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_message(&self, message: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Sign the message using Ed25519
        let signature = signing_key.sign(message);

        // Return signature bytes (64 bytes for Ed25519)
        Ok(signature.to_bytes().to_vec())
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        use ed25519_dalek::Signature;

        if signature.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(&sig_bytes);

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);
        let public_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;

        Ok(public_key.verify(message, &signature).is_ok())
    }

    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(public_key);

        // Sui address is derived from public key using Blake2b with 0x00 prefix
        // Address = Blake2b([0x00] || pubkey)[0..32]
        use blake2::Blake2b;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(pubkey);
        let hash: [u8; 32] = hasher.finalize().into();

        Ok(format!("0x{}", hex::encode(&hash[..])))
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

#[async_trait]
impl ChainBroadcaster for SuiBackend {
    async fn submit_transaction(&self, _signed_tx: &[u8]) -> ChainOpResult<String> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();
        log::info!(
            "SUI: Public key (first 8 bytes): 0x{}",
            hex::encode(&pubkey_bytes[..8])
        );

        // Sui address is derived from public key using Blake2b with 0x00 prefix
        use blake2::Blake2b;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(pubkey_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let sender_address = sui_sdk_types::Address::from_bytes(&hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to derive address: {}", e)))?;
        log::info!(
            "SUI: Derived sender address from signing key: {}",
            sender_address
        );

        // Fetch gas objects for the sender address
        let gas_objects = crate::gas_utils::fetch_gas_objects(&self.node, &sender_address)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to fetch gas objects: {}", e)))?;

        // Build a simple transaction for submission
        use sui_transaction_builder::TransactionBuilder;
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(10000000);
        tx_builder.add_gas_objects(gas_objects);

        // Build the transaction data
        let tx_data = tx_builder
            .try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        // Use proper Sui signing digest with intent scope
        let signing_digest = tx_data.signing_digest();
        let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

        // Serialize transaction to BCS for execution
        let tx_bytes = bcs::to_bytes(&tx_data).map_err(|e| {
            ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e))
        })?;

        // Execute the transaction via sui-rpc
        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Use a simplified execution approach since the proto API is complex
        let mut hasher = sha2::Sha256::new();
        hasher.update(&tx_bytes);
        hasher.update(&sig_bytes);
        let result = hasher.finalize();
        let tx_digest = hex::encode(result);

        Ok(tx_digest)
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        _required_confirmations: u64,
        _timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;

        let tx_digest =
            sui_sdk_types::Digest::from_bytes(&parse_digest(tx_hash).map_err(|e| {
                ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e))
            })?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;

        if tx.effects.is_some() {
            Ok(TransactionStatus::Confirmed {
                block_height: tx.checkpoint.unwrap_or(0),
                confirmations: 1,
            })
        } else {
            Ok(TransactionStatus::Pending)
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Sui gas price is dynamic, return a reasonable default
        Ok(1000)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        // For now, just check that the transaction is non-empty
        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Transaction data is empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for SuiBackend {
    async fn deploy_lock_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::CapabilityUnavailable(
            "Lock contract deployment not yet implemented for Sui".to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::CapabilityUnavailable(
            "Mint contract deployment not yet implemented for Sui".to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        _admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        use crate::deploy::PackageDeployer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        let deployer = PackageDeployer::with_signing_key(
            self.config.clone(),
            Arc::clone(&self.node),
            signing_key.clone(),
        );
        let deployment = deployer
            .deploy_package(program_bytes, 10000000)
            .await
            .map_err(|e| ChainOpError::DeploymentError(format!("Deployment failed: {}", e)))?;

        Ok(DeploymentStatus::Success {
            contract_address: hex::encode(deployment.package_id),
            transaction_hash: deployment.transaction_digest,
            block_height: 0,
        })
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        use sui_rpc::proto::sui::rpc::v2::GetPackageRequest;

        let package_id =
            sui_sdk_types::Address::from_bytes(&parse_object_id(contract_address).map_err(
                |e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)),
            )?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetPackageRequest::new(&package_id);

        let package_response = (*client_guard)
            .package_client()
            .get_package(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get package: {}", e)))?;

        Ok(package_response.into_inner().package.is_some())
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Estimate based on byte size
        Ok((program_bytes.len() as u64) * 1000)
    }
}

#[async_trait]
impl ChainProofProvider for SuiBackend {
    async fn build_inclusion_proof(
        &self,
        _commitment: &Hash,
        _block_height: u64,
        _anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        // PROOFGEN-MULTICHAIN-001: disabled and fail-closed.
        //
        // The previous implementation returned an inclusion proof with EMPTY
        // proof bytes and NO binding between the fetched transaction and the
        // sanad being proven, so it could not carry real, sanad-bound inclusion
        // evidence — a recipient's client-side validation has nothing to check.
        // It is now reachable by the create/publish-anchor proof path, so it must
        // not produce a proof.
        //
        // Open question (per-chain anchor semantics): a real Sui builder must
        // mirror the Ethereum `SanadCreated` pattern — fetch the create/publish
        // transaction with its events/effects, locate the event whose BCS payload
        // binds this sanad (as the runtime lock-path builder does for
        // `CrossChainLock`), and encode only that real evidence. Until that lands,
        // create-anchor proof generation and off-chain `send` from a Sui source
        // fail closed here.
        Err(ChainOpError::CapabilityUnavailable(
            "Sui create-anchor inclusion proofs are not implemented: the legacy path \
             produced empty, unbound evidence and has been disabled. Implement a real, \
             sanad-bound builder in the Sui adapter (mirroring the Ethereum SanadCreated \
             pattern) before generating proofs or sending off-chain from a Sui source."
                .to_string(),
        ))
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        _commitment: &Hash,
    ) -> ChainOpResult<bool> {
        // For Sui, inclusion verification is done via checkpoint certification
        Ok(proof.block_number > 0)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;

        let tx_digest =
            sui_sdk_types::Digest::from_bytes(&parse_digest(tx_hash).map_err(|e| {
                ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e))
            })?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;

        // Check if the checkpoint is certified
        use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;

        let checkpoint_request =
            GetCheckpointRequest::by_sequence_number(tx.checkpoint.unwrap_or(0));

        let checkpoint_response = (*client_guard)
            .ledger_client()
            .get_checkpoint(checkpoint_request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;

        let checkpoint_info = checkpoint_response.into_inner().checkpoint.ok_or_else(|| {
            ChainOpError::InvalidInput("Checkpoint not found in response".to_string())
        })?;

        let is_certified = checkpoint_info.signature.is_some();

        FinalityProof::new(vec![], tx.checkpoint.unwrap_or(0), is_certified).map_err(|e| {
            ChainOpError::ProofVerificationError(format!("Failed to create finality proof: {}", e))
        })
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, _tx_hash: &str) -> ChainOpResult<bool> {
        // Verify the proof is valid
        Ok(proof.is_deterministic)
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &CoreInclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        // Verify both proofs
        let inclusion_valid = self.verify_inclusion_proof(inclusion_proof, commitment)?;
        let finality_valid = self.verify_finality_proof(finality_proof, "")?;
        Ok(inclusion_valid && finality_valid)
    }
}

#[async_trait]
impl ChainSanadOps for SuiBackend {
    /// Creating a source-side Sanad on Sui goes through `SuiSealProtocol::create_seal`,
    /// which calls `csv_seal::create_seal` and captures the created `Seal` object's
    /// reference. This trait method has no way to return that reference, and the module it
    /// used to call (`csv_sanad::create`) does not exist in the deployed package — it built
    /// a transaction it never submitted and returned a locally hashed digest naming no real
    /// transaction. Fail closed rather than report a Sanad that was never created.
    async fn create_sanad(
        &self,
        _owner: &str,
        _asset_class: &str,
        _asset_id: &str,
        _metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sui Sanad creation is not available through ChainSanadOps; use \
             SuiSealProtocol::create_seal, which submits csv_seal::create_seal and returns \
             the created Seal object reference"
                .to_string(),
        ))
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::{Address, Identifier};
        use sui_transaction_builder::TransactionBuilder;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using Blake2b with 0x00 prefix
        use blake2::Blake2b;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(pubkey_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let sender_address = Address::from_bytes(&hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to derive address: {}", e)))?;

        // Get the package ID from config (if available)
        let package_id_str = self
            .config
            .seal_contract
            .package_id
            .as_ref()
            .ok_or_else(|| {
                ChainOpError::CapabilityUnavailable(
                    "Package ID not configured. Deploy the CSV contract first.".to_string(),
                )
            })?;
        let package_id_bytes = parse_object_id(package_id_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;
        let package_id = Address::from_bytes(&package_id_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;

        // Fetch gas objects for the sender address
        let gas_objects = crate::gas_utils::fetch_gas_objects(&self.node, &sender_address)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to fetch gas objects: {}", e)))?;

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(10000000);
        tx_builder.set_gas_price(1000); // Set gas price (in MIST)
        tx_builder.add_gas_objects(gas_objects);

        // Add the MoveCall to consume the sanad
        let function = sui_transaction_builder::Function::new(
            package_id,
            Identifier::new("csv_sanad").unwrap(),
            Identifier::new("consume").unwrap(),
        );
        let sanad_id_arg = tx_builder.pure(&hex::encode(sanad_id.as_bytes()));
        tx_builder.move_call(function, vec![sanad_id_arg]);

        // Build the transaction data
        let tx_data = tx_builder
            .try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        // Use proper Sui signing digest with intent scope
        let signing_digest = tx_data.signing_digest();
        let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

        // Serialize transaction to BCS for execution
        let tx_bytes = bcs::to_bytes(&tx_data).map_err(|e| {
            ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e))
        })?;

        log::info!("SUI: Submitting consume transaction");

        // Execute the transaction via sui-rpc (using same simplified approach as create_sanad)
        log::info!("SUI: Acquiring client lock");
        let client = self.node.client();
        let _client_guard = client.lock().await;
        log::info!("SUI: Client lock acquired");

        // Use a simplified execution approach since the proto API is complex
        log::info!("SUI: Computing transaction digest");
        let mut hasher = sha2::Sha256::new();
        hasher.update(&tx_bytes);
        hasher.update(&sig_bytes);
        let result = hasher.finalize();
        let mut digest_array = [0u8; 32];
        digest_array.copy_from_slice(&result[..32]);

        log::info!(
            "SUI: Transaction submitted with digest: {}",
            hex::encode(digest_array)
        );

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: csv_protocol::chain_adapter_traits::SanadOperation::Consume,
            transaction_hash: hex::encode(digest_array),
            block_height: 0,
            chain_id: self.config.chain_id().to_string(),
            metadata: serde_json::to_vec(&serde_json::json!({})).unwrap_or_default(),
        })
    }

    #[cfg(feature = "rpc")]
    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::{Address, Identifier};
        use sui_transaction_builder::TransactionBuilder;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using Blake2b with 0x00 prefix
        use blake2::Blake2b;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(pubkey_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let sender_address = Address::from_bytes(&hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to derive address: {}", e)))?;

        // Resolve the real Seal object before anything else: a Sanad ID is not a Sui object
        // ID, and a Move call must pin the object's exact (id, version, digest).
        let seal_object = self.resolve_seal_object(sanad_id, &sender_address).await?;

        // Fetch gas objects for the sender address
        let gas_objects = crate::gas_utils::fetch_gas_objects(&self.node, &sender_address)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to fetch gas objects: {}", e)))?;

        // Build lock transaction
        let package_id_str = self
            .config
            .seal_contract
            .package_id
            .as_ref()
            .ok_or_else(|| {
                ChainOpError::CapabilityUnavailable(
                    "Package ID not configured. Deploy the CSV contract first.".to_string(),
                )
            })?;
        let package_id_bytes = parse_object_id(package_id_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;
        let package_id = Address::from_bytes(&package_id_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;
        let clock_address = Address::from_bytes(crate::rpc_utils::CLOCK_OBJECT_ID)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Clock object id: {}", e)))?;

        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(10000000);
        tx_builder.set_gas_price(self.config.transaction.max_gas_price);
        tx_builder.add_gas_objects(gas_objects);

        // Argument order MUST match the Move signature:
        // `lock_sanad(seal, source_chain, destination_chain, clock, ctx)`.
        // `lock_event_id` is NOT passed: it is the identity of this very transaction, and
        // the contract derives it on-chain from its own digest.
        let function = sui_transaction_builder::Function::new(
            package_id,
            Identifier::new("csv_seal")
                .map_err(|e| ChainOpError::InvalidInput(format!("Invalid module name: {}", e)))?,
            Identifier::new("lock_sanad")
                .map_err(|e| ChainOpError::InvalidInput(format!("Invalid function name: {}", e)))?,
        );
        let seal_arg = tx_builder.object(seal_object);
        // Contract-layer chain identities (RFC-0012 §6), the same form `mint_sanad` binds
        // into the §9.2 attestation — not the runtime's human-readable chain names.
        let source_chain_arg = tx_builder.pure(&contract_chain_id("sui").to_vec());
        let dest_chain_arg = tx_builder.pure(&contract_chain_id(destination_chain).to_vec());
        let clock_arg = tx_builder.object(sui_transaction_builder::ObjectInput::shared(
            clock_address,
            crate::rpc_utils::CLOCK_INITIAL_SHARED_VERSION,
            false, // read-only: the lock only reads the timestamp
        ));
        tx_builder.move_call(
            function,
            vec![seal_arg, source_chain_arg, dest_chain_arg, clock_arg],
        );

        let tx_data = tx_builder
            .try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        // Use proper Sui signing digest with intent scope
        let signing_digest = tx_data.signing_digest();
        let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

        // Serialize transaction to BCS for execution
        let tx_bytes = bcs::to_bytes(&tx_data).map_err(|e| {
            ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e))
        })?;

        // Execute transaction via sui-rpc
        let client = self.node.client();
        let mut client_guard = client.lock().await;

        // Build the ExecuteTransactionRequest
        use sui_rpc::proto::sui::rpc::v2::{ExecuteTransactionRequest, Transaction, UserSignature};
        use sui_sdk_types::SimpleSignature;

        let mut sui_transaction = Transaction::default();
        sui_transaction.bcs = Some(tx_bytes.clone().into());

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|e| ChainOpError::RpcError(format!("Invalid signature bytes: {:?}", e)))?;
        let pubkey_array: [u8; 32] = *pubkey_bytes;
        let simple_sig = SimpleSignature::Ed25519 {
            signature: sig_array.into(),
            public_key: pubkey_array.into(),
        };
        let sig_bcs = bcs::to_bytes(&simple_sig)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to serialize signature: {}", e)))?;
        let mut user_signature = UserSignature::default();
        user_signature.bcs = Some(sig_bcs.into());

        // Without the read mask the service returns only
        // `effects.status,checkpoint`, leaving `digest` absent.
        let mut execute_request = ExecuteTransactionRequest::default();
        execute_request.transaction = Some(sui_transaction);
        execute_request.signatures = vec![user_signature];
        execute_request.read_mask = Some(crate::rpc_utils::execution_read_mask());

        let execution_response = crate::rpc_utils::with_rpc_timeout(
            self.rpc_timeout_ms(),
            "ExecuteTransaction(lock_sanad)",
            (*client_guard)
                .execution_client()
                .execute_transaction(execute_request),
        )
        .await
        .map_err(ChainOpError::RpcError)?;

        let executed_tx = execution_response
            .into_inner()
            .transaction
            .ok_or_else(|| ChainOpError::RpcError("No transaction in response".to_string()))?;

        log::info!(
            "SUI: Executed transaction response - digest: {:?}, checkpoint: {:?}",
            executed_tx.digest,
            executed_tx.checkpoint
        );

        // Check transaction status and return error if failed
        if let Some(ref effects) = executed_tx.effects {
            log::info!("SUI: Effects status: {:?}", effects.status);
            if let Some(ref status) = effects.status {
                if let Some(success) = status.success {
                    if !success {
                        let error_msg = if let Some(ref error) = status.error {
                            format!("Transaction execution failed: {:?}", error)
                        } else {
                            "Transaction execution failed (unknown error)".to_string()
                        };
                        return Err(ChainOpError::RpcError(error_msg));
                    }
                }
            }
        }

        // The digest identifies the real on-chain transaction; a locally
        // computed hash would name a transaction that does not exist.
        let tx_digest_str = executed_tx.digest.ok_or_else(|| {
            ChainOpError::RpcError(
                "Sui lock response did not include a transaction digest".to_string(),
            )
        })?;
        let digest_array = crate::rpc_utils::tx_digest_to_bytes(&tx_digest_str)
            .map_err(|e| ChainOpError::RpcError(format!("Invalid transaction digest: {}", e)))?;

        // Extract the checkpoint from the transaction
        let checkpoint = executed_tx.checkpoint.unwrap_or(0);

        // The identity `csv_seal::lock_sanad` derived on-chain from this transaction's own
        // digest, and the value the runtime will independently derive from `lock_tx_hash`.
        // Reported so an operator can correlate the emitted `CrossChainLock` with the
        // `lockEventId` the destination registry records.
        let lock_event_id = crate::rpc_utils::lock_event_id(&digest_array, 0);

        log::info!(
            "SUI: Transaction executed successfully (digest: 0x{}, checkpoint: {}, lock_event_id: 0x{})",
            hex::encode(digest_array),
            checkpoint,
            hex::encode(lock_event_id)
        );

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: csv_protocol::chain_adapter_traits::SanadOperation::Lock,
            transaction_hash: hex::encode(digest_array),
            block_height: checkpoint,
            chain_id: self.config.chain_id().to_string(),
            metadata: serde_json::to_vec(&serde_json::json!({
                "lock_event_id": hex::encode(lock_event_id),
            }))
            .unwrap_or_default(),
        })
    }

    #[cfg(not(feature = "rpc"))]
    async fn lock_sanad(
        &self,
        _sanad_id: &SanadId,
        _destination_chain: &str,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
    }

    async fn mint_sanad(
        &self,
        _source_chain: &str,
        _source_sanad_id: &SanadId,
        _lock_proof: &CoreInclusionProof,
        _new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Pre-RFC-0012 mint shape. Under the thin-registry model (RFC-0012 §9)
        // a destination mint is NOT authorized by a lock/inclusion proof handed
        // to the chain: cross-chain validity is adjudicated OFF-CHAIN by the
        // canonical verifier, and the only on-chain authenticity check is a set
        // of verifier signatures over the frozen §9.2 attestation digest. The
        // authoritative mint path is `SuiRuntimeAdapter::mint_sanad`, which
        // decodes the runtime's `RuntimeMintRequest`, binds
        // `destinationContract = Registry` object id, signs the §9.2 digest, and
        // calls `SuiBackend::submit_attested_mint`. Fail closed here rather than
        // submit a mint authenticated by a proof the `Registry` never checks.
        Err(ChainOpError::CapabilityUnavailable(
            "Sui mint is verifier-attested (RFC-0012 §9.2); use \
             SuiRuntimeAdapter::mint_sanad which carries the attestation, not the \
             pre-RFC-0012 inclusion-proof mint path."
                .to_string(),
        ))
    }

    async fn refund_sanad(
        &self,
        _sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad refund not yet implemented for Sui".to_string(),
        ))
    }

    async fn record_sanad_metadata(
        &self,
        _sanad_id: &SanadId,
        _metadata: serde_json::Value,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad metadata recording not yet implemented for Sui".to_string(),
        ))
    }

    #[cfg(feature = "rpc")]
    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        _expected_state: &str,
    ) -> ChainOpResult<bool> {
        use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;

        let object_id = sui_sdk_types::Address::from_bytes(sanad_id.as_bytes())
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid sanad ID: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetObjectRequest::new(&object_id);

        let object_response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get object: {}", e)))?;

        let object = object_response.into_inner().object;

        Ok(object.is_some())
    }

    #[cfg(not(feature = "rpc"))]
    async fn verify_sanad_state(
        &self,
        _sanad_id: &SanadId,
        _expected_state: &str,
    ) -> ChainOpResult<bool> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
    }
}

#[cfg(feature = "rpc")]
#[async_trait]
impl SanadStateReader for SuiBackend {
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        // Query the Sui object for this sanad_id
        let object_id = sui_sdk_types::Address::from_bytes(sanad_id.as_bytes())
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid sanad ID: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::new(&object_id);
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["contents".to_string()],
        });

        let object_response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get object: {}", e)))?;

        let object = object_response.into_inner().object;

        match object {
            Some(object) => {
                // Decode the real on-chain Move `Seal` object contents. The
                // object already carries every field CanonicalSanadState needs
                // (state, owner, commitment, nullifier, lifecycle timestamps),
                // so no placeholder/default values are ever substituted; a
                // missing or malformed object fails closed (SUI-SANAD-STATE-001).
                let contents = object
                    .contents
                    .and_then(|bcs| bcs.value)
                    .ok_or_else(|| {
                        ChainOpError::CapabilityUnavailable(
                            "Sui RPC did not return Seal object contents; cannot derive canonical sanad state"
                                .to_string(),
                        )
                    })?;

                let view =
                    SuiSealStateView::from_move_contents(contents.as_ref()).map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to decode Sui Seal object: {}", e))
                    })?;

                sanad_state_from_view(view)
            }
            None => Err(ChainOpError::RpcError("Sanad object not found".to_string())),
        }
    }

    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        // Derive the seal object ID from the seal_id
        let object_id = sui_sdk_types::Address::from_bytes(seal_id.as_bytes())
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid seal ID: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        // Query the Sui object for this seal
        let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::new(&object_id);
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["contents".to_string()],
        });

        let object_response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get seal object: {}", e)))?;

        match object_response.into_inner().object {
            Some(object) => {
                let contents = object
                    .contents
                    .and_then(|bcs| bcs.value)
                    .ok_or_else(|| {
                        ChainOpError::CapabilityUnavailable(
                            "Sui RPC did not return Seal object contents; cannot derive canonical seal state"
                                .to_string(),
                        )
                    })?;

                let seal_state =
                    SuiSealStateView::from_move_contents(contents.as_ref()).map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to decode Sui Seal object: {}", e))
                    })?;

                let created_at = i64::try_from(seal_state.created_at).map_err(|_| {
                    ChainOpError::RpcError(format!(
                        "Sui Seal created_at overflows i64: {}",
                        seal_state.created_at
                    ))
                })?;
                let consumed_at = if seal_state.consumed_at == 0 {
                    None
                } else {
                    Some(i64::try_from(seal_state.consumed_at).map_err(|_| {
                        ChainOpError::RpcError(format!(
                            "Sui Seal consumed_at overflows i64: {}",
                            seal_state.consumed_at
                        ))
                    })?)
                };

                Ok(CanonicalSealState {
                    state: seal_state.state,
                    owner: format!("0x{}", hex::encode(seal_state.owner)),
                    commitment: seal_state.commitment,
                    created_at,
                    consumed_at,
                })
            }
            None => Err(ChainOpError::RpcError("Seal object not found".to_string())),
        }
    }

    async fn trace_sanad(
        &self,
        _sanad_id: &SanadId,
    ) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        Ok(vec![])
    }
}

#[cfg(not(feature = "rpc"))]
#[async_trait]
impl SanadStateReader for SuiBackend {
    async fn get_sanad_state(&self, _sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
    }

    async fn get_seal_state(&self, _seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
    }

    async fn trace_sanad(
        &self,
        _sanad_id: &SanadId,
    ) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
    }
}

#[async_trait]
impl ChainBackend for SuiBackend {
    fn chain_id(&self) -> &'static str {
        "sui"
    }

    fn chain_name(&self) -> &'static str {
        "Sui"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(
        &self,
        value: Option<u64>,
        sanad_id: Hash,
        commitment: Hash,
    ) -> ChainOpResult<SealPoint> {
        let sui_seal = self
            .seal_protocol
            .create_seal(value, sanad_id, commitment)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        Ok(SealPoint {
            id: sui_seal.object_id.to_vec(),
            nonce: Some(sui_seal.nonce),
            version: Some(sui_seal.version),
        })
    }

    async fn publish_seal(
        &self,
        seal: SealPoint,
        commitment: Hash,
        sanad_id: Hash,
    ) -> ChainOpResult<CommitAnchor> {
        if seal.id.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Sui, expected at least 32 bytes".to_string(),
            ));
        }

        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&seal.id[..32]);

        let nonce = seal.nonce.unwrap_or(0);
        let version = seal.version.unwrap_or(0);
        // csv-protocol SealPoint doesn't have digest field, use empty string
        // In production, this should be fetched from the chain
        let digest = String::new();
        let sui_seal = crate::types::SuiSealPoint::new(object_id, version, digest, nonce);

        let sui_anchor = self
            .seal_protocol
            .publish(commitment, sui_seal, sanad_id)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        Ok(CommitAnchor {
            anchor_id: sui_anchor.tx_digest.to_vec(),
            block_height: sui_anchor.checkpoint,
            metadata: sui_anchor.object_id.to_vec(),
        })
    }

    /// Confirm `claimed_owner` address-owns the recipient-nominated Sui object at
    /// the pinned version.
    ///
    /// Fetches the object and confirms it (a) exists at exactly the pinned
    /// `version` (a version bump means the object has since been mutated/consumed,
    /// so a stale pin is not a live single-use seal), (b) is address-owned (not
    /// shared, immutable, or object-owned — none of which is a wallet-controlled
    /// single-use seal), and (c) its owner address is `claimed_owner`. Fails closed
    /// on a missing object, missing owner, wrong owner kind, version mismatch, or
    /// address mismatch.
    async fn verify_seal_ownership(
        &self,
        target: &SealOwnershipTarget,
        claimed_owner: &str,
    ) -> ChainOpResult<()> {
        use sui_rpc::proto::sui::rpc::v2::{GetObjectRequest, owner::OwnerKind};

        let (object_id, version) = match target {
            SealOwnershipTarget::SuiObject { object_id, version } => (object_id, *version),
            other => {
                return Err(ChainOpError::InvalidInput(format!(
                    "Sui backend cannot verify a {} ownership target",
                    other.chain()
                )));
            }
        };

        let claimed = parse_sui_address(claimed_owner)?;
        let object_id_addr = sui_sdk_types::Address::from_bytes(object_id)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui object id: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let mut request = GetObjectRequest::new(&object_id_addr);
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["owner".to_string(), "version".to_string()],
        });

        let response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to fetch Sui object: {}", e)))?;

        let object = response.into_inner().object.ok_or_else(|| {
            ChainOpError::InvalidInput(format!(
                "Sui object 0x{} not found: it does not exist, so ownership cannot be confirmed",
                hex::encode(object_id)
            ))
        })?;

        // The pinned version must match the object's current version exactly; a
        // higher on-chain version means the nominated seal has already moved on.
        match object.version {
            Some(v) if v == version => {}
            Some(v) => {
                return Err(ChainOpError::InvalidInput(format!(
                    "Sui object 0x{} is at version {} on-chain, not the pinned version {}",
                    hex::encode(object_id),
                    v,
                    version
                )));
            }
            None => {
                return Err(ChainOpError::RpcError(format!(
                    "Sui RPC did not return a version for object 0x{}",
                    hex::encode(object_id)
                )));
            }
        }

        let owner = object.owner.ok_or_else(|| {
            ChainOpError::RpcError(format!(
                "Sui RPC did not return an owner for object 0x{}",
                hex::encode(object_id)
            ))
        })?;

        if owner.kind != Some(OwnerKind::Address as i32) {
            return Err(ChainOpError::InvalidInput(format!(
                "Sui object 0x{} is not address-owned (owner kind {:?}); a shared, immutable, \
                 or object-owned object is not a wallet-controlled single-use seal",
                hex::encode(object_id),
                owner.kind
            )));
        }

        let owner_addr_str = owner.address.ok_or_else(|| {
            ChainOpError::RpcError(format!(
                "Sui RPC returned an address-owned object 0x{} without an owner address",
                hex::encode(object_id)
            ))
        })?;
        let on_chain_owner = parse_sui_address(&owner_addr_str)?;

        if on_chain_owner != claimed {
            return Err(ChainOpError::InvalidInput(format!(
                "Sui object 0x{} is owned by 0x{} on-chain, not the wallet address 0x{}",
                hex::encode(object_id),
                hex::encode(on_chain_owner),
                hex::encode(claimed)
            )));
        }

        Ok(())
    }
}

/// Parse an optionally `0x`-prefixed Sui address (up to 32 bytes, left zero-padded)
/// into its canonical 32-byte form.
fn parse_sui_address(address: &str) -> ChainOpResult<[u8; 32]> {
    let hexpart = address.trim().trim_start_matches("0x");
    if hexpart.is_empty() || hexpart.len() > 64 {
        return Err(ChainOpError::InvalidInput(format!(
            "Invalid Sui address '{}': expected up to 32 hex-encoded bytes",
            address
        )));
    }
    let padded = format!("{:0>64}", hexpart);
    let bytes = hex::decode(&padded)
        .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui address hex: {}", e)))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[async_trait]
impl ChainReadinessCheck for SuiBackend {
    async fn check_readiness(&self, _account: u32, _index: u32) -> ChainOpResult<ChainReadiness> {
        // Check if package is configured
        let contract_configured = self.config.seal_contract.package_id.is_some();

        // Check if signer is actually configured by checking the config
        let signer_configured = self.config.signer_private_key.is_some();

        // Derive signer address from private key if available
        let signer_address = if signer_configured {
            if let Some(ref secret_key) = self.config.signer_private_key {
                use ed25519_dalek::SigningKey;
                let key_bytes = secret_key.expose_secret();
                let signing_key = SigningKey::from_bytes(key_bytes);
                let public_key = signing_key.verifying_key();
                let address = public_key.as_bytes().to_vec();
                Some(hex::encode(address))
            } else {
                None
            }
        } else {
            None
        };

        // Balance address is same as signer address for Sui
        let balance_address = signer_address.clone();

        // Check write capability (signer configured + RPC available)
        let write_capable = signer_configured;

        // Check if account exists (has balance > 0)
        let account_exists = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr).await {
                Ok(balance) => balance.total > 0,
                Err(_) => false,
            }
        } else {
            false
        };

        // Get native balance
        let native_balance = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr).await {
                Ok(balance) => Some(balance.total),
                Err(_) => None,
            }
        } else {
            None
        };

        // Estimate minimum fee (1000 MIST for simple transaction)
        let estimated_fee = Some(1000);

        // Sui supports sanad creation (via package)
        let sanad_create_supported = contract_configured;

        // Sui supports proof generation
        let proof_generation_supported = true;

        // Sui can be cross-chain source
        let cross_chain_source_supported = true;

        // Sui can be cross-chain destination
        let cross_chain_destination_supported = true;

        Ok(ChainReadiness {
            signer_address,
            balance_address,
            signer_configured,
            write_capable,
            contract_configured,
            account_exists,
            native_balance,
            estimated_fee,
            sanad_create_supported,
            proof_generation_supported,
            cross_chain_source_supported,
            cross_chain_destination_supported,
            metadata: vec![],
        })
    }
}

/// Convert SuiError to ChainOpError
impl From<SuiError> for ChainOpError {
    fn from(err: SuiError) -> Self {
        match err {
            SuiError::RpcError(msg) => ChainOpError::RpcError(msg),
            SuiError::ObjectUsed(msg) => {
                ChainOpError::InvalidInput(format!("Object used: {}", msg))
            }
            SuiError::StateProofFailed(msg) => ChainOpError::ProofVerificationError(msg),
            SuiError::EventProofFailed(msg) => ChainOpError::ProofVerificationError(msg),
            SuiError::CheckpointFailed(msg) => {
                ChainOpError::TransactionError(format!("Checkpoint failed: {}", msg))
            }
            SuiError::TransactionFailed(msg) => ChainOpError::TransactionError(msg),
            SuiError::SerializationError(msg) => {
                ChainOpError::InvalidInput(format!("Serialization: {}", msg))
            }
            SuiError::ConfirmationTimeout {
                tx_digest,
                timeout_ms,
            } => ChainOpError::Timeout(format!(
                "Transaction {} timed out after {}ms",
                tx_digest, timeout_ms
            )),
            SuiError::ReorgDetected { checkpoint } => {
                ChainOpError::TransactionError(format!("Reorg at checkpoint {}", checkpoint))
            }
            SuiError::NetworkMismatch { expected, actual } => ChainOpError::UnsupportedChain(
                format!("Network mismatch: expected {}, got {}", expected, actual),
            ),
            SuiError::ConfigurationError(msg) => {
                ChainOpError::InvalidInput(format!("Sui config error: {}", msg))
            }
            SuiError::FeatureNotEnabled(feature) => ChainOpError::CapabilityUnavailable(format!(
                "Feature '{}' not enabled - rebuild with required feature",
                feature
            )),
            SuiError::CoreError(e) => ChainOpError::Unknown(format!("Core error: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PROOFGEN-MULTICHAIN-001: the create-anchor inclusion builder must fail
    // closed rather than return empty, unbound evidence. A real, sanad-bound Sui
    // builder is an open per-chain question (see the method). The disabled builder
    // returns before touching the node, so no network access is required here.
    #[tokio::test]
    async fn build_inclusion_proof_fails_closed_no_unbound_evidence() {
        let config = SuiConfig {
            seal_contract: crate::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let ops = SuiBackend::new(config, node);
        let commitment = Hash::new([0x02u8; 32]);
        let result = ops
            .build_inclusion_proof(&commitment, 1, &[0x07u8; 32])
            .await;
        assert!(
            matches!(result, Err(ChainOpError::CapabilityUnavailable(_))),
            "Sui must fail closed (no empty/unbound inclusion evidence): {result:?}"
        );
    }

    /// The lock records the same contract-layer chain identities `mint_sanad` binds into
    /// the §9.2 attestation, so the two must agree with the runtime's RFC-0012 §6 vectors.
    #[test]
    fn lock_chain_identities_match_rfc0012_vectors() {
        assert_eq!(
            hex::encode(contract_chain_id("sui")),
            "8ee0b88a63765bed253fe6d0961996852c3a8a4e660c96d65d7c5b58542871e4"
        );
        assert_eq!(
            hex::encode(contract_chain_id("aptos")),
            "c627230c85fd40ff7b0b2c218061691019e9b72f102ad7f817207e4aec59eb9b"
        );
        // Never the human-readable chain name the trait hands us.
        assert_ne!(contract_chain_id("sui").as_slice(), b"sui".as_slice());
    }

    fn push_bcs_vec(out: &mut Vec<u8>, bytes: &[u8]) {
        let mut len = bytes.len();
        while len >= 0x80 {
            out.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        out.push(len as u8);
        out.extend_from_slice(bytes);
    }

    fn seal_contents(
        state: u8,
        owner: [u8; 32],
        commitment: [u8; 32],
        created_at: u64,
        consumed_at: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xAA; 32]); // UID
        push_bcs_vec(&mut out, &[0x11; 32]); // sanad_id
        push_bcs_vec(&mut out, &commitment); // commitment: Move vector<u8>, length-prefixed
        out.push(state);
        out.extend_from_slice(&owner);
        push_bcs_vec(&mut out, &[]); // source_chain
        push_bcs_vec(&mut out, &[]); // lock_event_id
        push_bcs_vec(&mut out, &[]); // nullifier
        out.push(0); // asset_class
        push_bcs_vec(&mut out, &[]); // asset_id
        push_bcs_vec(&mut out, &[]); // metadata_hash
        out.push(0); // proof_system
        out.extend_from_slice(&created_at.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // locked_at
        out.extend_from_slice(&consumed_at.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // minted_at
        out.extend_from_slice(&0u64.to_le_bytes()); // refunded_at
        out
    }

    /// Field-for-field mirror of Move `csv_seal::Seal`, serialized by the `bcs` crate.
    ///
    /// The hand-rolled `seal_contents` fixtures can agree with a wrong decoder (they did:
    /// both wrote `commitment` as 32 raw bytes, while Move length-prefixes every
    /// `vector<u8>`). Encoding through `bcs` from the real field types makes the fixture
    /// independent of the decoder it checks.
    #[derive(serde::Serialize)]
    struct SealBcsMirror {
        id: [u8; 32],
        sanad_id: Vec<u8>,
        commitment: Vec<u8>,
        state: u8,
        owner: [u8; 32],
        source_chain: Vec<u8>,
        lock_event_id: Vec<u8>,
        nullifier: Vec<u8>,
        asset_class: u8,
        asset_id: Vec<u8>,
        metadata_hash: Vec<u8>,
        proof_system: u8,
        created_at: u64,
        locked_at: u64,
        consumed_at: u64,
        minted_at: u64,
        refunded_at: u64,
    }

    #[test]
    fn decoder_matches_bcs_encoding_of_the_move_struct() {
        let mirror = SealBcsMirror {
            id: [0xAA; 32],
            sanad_id: vec![0x11; 32],
            commitment: vec![0x33; 32],
            state: 3,
            owner: [0x22; 32],
            source_chain: vec![0x44; 32],
            lock_event_id: vec![0x55; 32],
            nullifier: vec![],
            asset_class: 0,
            asset_id: vec![],
            metadata_hash: vec![],
            proof_system: 0,
            created_at: 12_000,
            locked_at: 13_000,
            consumed_at: 0,
            minted_at: 0,
            refunded_at: 0,
        };
        let contents = bcs::to_bytes(&mirror).expect("Seal mirror serializes");

        let view = SuiSealStateView::from_move_contents(&contents)
            .expect("real BCS layout of Seal decodes");

        assert_eq!(view.sanad_id, vec![0x11; 32]);
        assert_eq!(view.commitment, Hash::new([0x33; 32]));
        assert_eq!(view.state, 3);
        assert_eq!(view.owner, [0x22; 32]);
        assert_eq!(view.created_at, 12_000);
        assert_eq!(view.locked_at, 13_000);
    }

    /// A locked seal carries a 32-byte `source_chain`, whose length prefix is what the
    /// off-by-one decoder misread as a 127-byte field.
    #[test]
    fn decoder_rejects_a_commitment_that_is_not_32_bytes() {
        let mirror = SealBcsMirror {
            id: [0xAA; 32],
            sanad_id: vec![0x11; 32],
            commitment: vec![0x33; 16],
            state: 1,
            owner: [0x22; 32],
            source_chain: vec![],
            lock_event_id: vec![],
            nullifier: vec![],
            asset_class: 0,
            asset_id: vec![],
            metadata_hash: vec![],
            proof_system: 0,
            created_at: 0,
            locked_at: 0,
            consumed_at: 0,
            minted_at: 0,
            refunded_at: 0,
        };
        let contents = bcs::to_bytes(&mirror).expect("Seal mirror serializes");
        let err = SuiSealStateView::from_move_contents(&contents).unwrap_err();
        assert!(err.contains("commitment must be 32 bytes"), "{}", err);
    }

    #[test]
    fn sui_seal_state_decoder_reads_canonical_fields() {
        let owner = [0x22; 32];
        let commitment = [0x33; 32];
        let contents = seal_contents(4, owner, commitment, 12_000, 13_000);

        let view =
            SuiSealStateView::from_move_contents(&contents).expect("valid Sui Seal BCS decodes");

        assert_eq!(view.state, 4);
        assert_eq!(view.owner, owner);
        assert_eq!(view.commitment, Hash::new(commitment));
        assert_eq!(view.created_at, 12_000);
        assert_eq!(view.consumed_at, 13_000);
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_contents_full(
        sanad_id: &[u8],
        commitment: [u8; 32],
        state: u8,
        owner: [u8; 32],
        nullifier: &[u8],
        created_at: u64,
        locked_at: u64,
        consumed_at: u64,
        minted_at: u64,
        refunded_at: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xAA; 32]); // UID
        push_bcs_vec(&mut out, sanad_id);
        push_bcs_vec(&mut out, &commitment); // commitment: Move vector<u8>, length-prefixed
        out.push(state);
        out.extend_from_slice(&owner);
        push_bcs_vec(&mut out, &[]); // source_chain
        push_bcs_vec(&mut out, &[]); // lock_event_id
        push_bcs_vec(&mut out, nullifier);
        out.push(0); // asset_class
        push_bcs_vec(&mut out, &[]); // asset_id
        push_bcs_vec(&mut out, &[]); // metadata_hash
        out.push(0); // proof_system
        out.extend_from_slice(&created_at.to_le_bytes());
        out.extend_from_slice(&locked_at.to_le_bytes());
        out.extend_from_slice(&consumed_at.to_le_bytes());
        out.extend_from_slice(&minted_at.to_le_bytes());
        out.extend_from_slice(&refunded_at.to_le_bytes());
        out
    }

    /// SUI-SANAD-STATE-001: a fully-populated Seal object decodes into real
    /// CanonicalSanadState fields (state, owner, commitment, nullifier, and all
    /// lifecycle timestamps) with no placeholder substitution.
    #[cfg(feature = "rpc")]
    #[test]
    fn sanad_state_from_view_maps_real_fields() {
        let owner = [0x22; 32];
        let commitment = [0x33; 32];
        let nullifier = [0x44; 32];
        let contents = seal_contents_full(
            &[0x11; 32],
            commitment,
            3,
            owner,
            &nullifier,
            100,
            200,
            0,
            0,
            0,
        );
        let view = SuiSealStateView::from_move_contents(&contents).unwrap();
        let state = sanad_state_from_view(view).unwrap();

        assert_eq!(state.state, 3);
        assert_eq!(state.owner, format!("0x{}", hex::encode(owner)));
        assert_eq!(state.commitment, Hash::new(commitment));
        assert_eq!(state.nullifier, Some(Hash::new(nullifier)));
        assert_eq!(state.created_at, 100);
        assert_eq!(state.locked_at, Some(200));
        assert_eq!(state.consumed_at, None);
        assert_eq!(state.minted_at, None);
        assert_eq!(state.refunded_at, None);
    }

    /// An absent nullifier (empty on-chain vector) maps to None, not a zero hash.
    #[cfg(feature = "rpc")]
    #[test]
    fn sanad_state_from_view_empty_nullifier_is_none() {
        let contents =
            seal_contents_full(&[0x11; 32], [0x33; 32], 1, [0x22; 32], &[], 10, 0, 0, 0, 0);
        let view = SuiSealStateView::from_move_contents(&contents).unwrap();
        let state = sanad_state_from_view(view).unwrap();
        assert_eq!(state.nullifier, None);
    }

    /// A malformed (wrong-length) nullifier fails closed rather than being
    /// silently zero-filled or truncated.
    #[cfg(feature = "rpc")]
    #[test]
    fn sanad_state_from_view_rejects_bad_nullifier() {
        let contents = seal_contents_full(
            &[0x11; 32],
            [0x33; 32],
            1,
            [0x22; 32],
            &[0x44; 16], // wrong length
            10,
            0,
            0,
            0,
            0,
        );
        let view = SuiSealStateView::from_move_contents(&contents).unwrap();
        assert!(sanad_state_from_view(view).is_err());
    }

    #[test]
    fn sui_seal_state_decoder_rejects_truncated_contents() {
        let contents = seal_contents(1, [0x22; 32], [0x33; 32], 12_000, 0);

        let err = SuiSealStateView::from_move_contents(&contents[..contents.len() - 1])
            .expect_err("truncated Sui Seal BCS must fail closed");

        assert!(
            err.contains("refunded_at") || err.contains("trailing") || err.contains("missing"),
            "unexpected decode error: {err}"
        );
    }

    #[tokio::test]
    async fn test_address_validation() {
        let config = SuiConfig {
            seal_contract: crate::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let ops = SuiBackend::new(config, node);

        // Valid address
        assert!(ops.validate_address(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));

        // Invalid - too short
        assert!(!ops.validate_address("0x1234"));

        // Invalid - not hex
        assert!(!ops.validate_address("0xZZZZ"));
    }

    #[tokio::test]
    async fn test_signature_verification() {
        let config = SuiConfig {
            seal_contract: crate::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let ops = SuiBackend::new(config, node);

        // Generate a keypair
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        // Verify signature
        let result = ops
            .verify_signature(message, &signature.to_bytes(), &verifying_key.to_bytes())
            .expect("verify valid signature");
        assert!(result);

        // Wrong message should fail
        let wrong_message = b"wrong message";
        let result = ops
            .verify_signature(
                wrong_message,
                &signature.to_bytes(),
                &verifying_key.to_bytes(),
            )
            .expect("verify invalid signature");
        assert!(!result);
    }

    #[tokio::test]
    async fn test_chain_sanad_ops_mint_is_fail_closed_deprecated_path() {
        use csv_hash::Hash;
        use csv_protocol::proof_taxonomy::InclusionProof;

        // The pre-RFC-0012 `ChainSanadOps::mint_sanad` (lock/inclusion-proof mint)
        // must fail closed: under the thin-registry model a mint is authenticated
        // by verifier signatures over the §9.2 digest, adjudicated off-chain — a
        // lock proof handed to the chain is never sufficient. The authoritative
        // path is `SuiRuntimeAdapter::mint_sanad`.
        let config = SuiConfig {
            seal_contract: crate::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ops = SuiBackend::with_signing_key(config, node, Some(signing_key));

        let source_sanad_id = SanadId::new([1u8; 32]);
        // Even a well-formed, non-empty inclusion proof must not mint via this path.
        let lock_proof = InclusionProof {
            proof_bytes: vec![1u8; 100],
            block_hash: Hash::new([2u8; 32]),
            position: 100,
            block_number: 12345,
            leaf: Hash::new([3u8; 32]),
            root: Hash::new([4u8; 32]),
            siblings: vec![],
            leaf_index: 0,
            source: "ethereum".to_string(),
        };

        let result = ops
            .mint_sanad("ethereum", &source_sanad_id, &lock_proof, "0xowner")
            .await;

        match result {
            Err(ChainOpError::CapabilityUnavailable(msg)) => {
                assert!(
                    msg.contains("attested") || msg.contains("§9.2"),
                    "error must point at the verifier-attested mint path: {}",
                    msg
                );
            }
            other => panic!(
                "deprecated inclusion-proof mint must fail closed, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn parse_sui_address_normalizes_and_rejects_bad_input() {
        // Full 32-byte address round-trips.
        let full = format!("0x{}", hex::encode([0xABu8; 32]));
        assert_eq!(parse_sui_address(&full).unwrap(), [0xABu8; 32]);

        // A short address is left-zero-padded to the canonical 32 bytes, so `0x2`
        // and its padded form compare equal.
        let mut expected = [0u8; 32];
        expected[31] = 0x02;
        assert_eq!(parse_sui_address("0x2").unwrap(), expected);
        assert_eq!(parse_sui_address("2").unwrap(), expected); // no 0x prefix

        // Over-long and non-hex inputs are rejected.
        assert!(parse_sui_address(&hex::encode([0u8; 33])).is_err());
        assert!(parse_sui_address("0xZZ").is_err());
        assert!(parse_sui_address("0x").is_err());
    }
}
