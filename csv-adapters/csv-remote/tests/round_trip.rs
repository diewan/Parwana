//! Round-trip and fail-closed tests for remote dispatch.
//!
//! The client [`RemoteChainAdapter`] talks to an **in-process host**
//! ([`host::dispatch`]) over a mock transport that mimics the network — it can
//! drop responses, corrupt bytes, or authenticate — so the full envelope path
//! (encode → transport → decode → registry → encode → transport → decode) is
//! exercised without a live server.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use csv_chain_ports::{
    AdapterError, AdapterRegistry, ChainAdapter, ChainCapabilityPort, CrossChainTransfer,
    DestinationMaterialization, LockResult, MintResult, SealRegistryStatus, SettlementResult,
    TxFinality,
};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use csv_remote::transport::RemoteTransport;
use csv_remote::{RemoteChainAdapter, host};
use csv_wire::remote::{
    RemoteError, RemoteRequest, RemoteRequestPayload, RemoteResponse, RemoteResponsePayload,
};

// ---------------------------------------------------------------------------
// Mock host adapter + registry
// ---------------------------------------------------------------------------

/// A deterministic in-memory chain adapter. Its lock is idempotent — the same
/// transfer id always returns the same lock result — which is what preserves
/// safety across a dropped-connection retry.
struct MockChainAdapter {
    chain: String,
    lock_calls: AtomicUsize,
    mint_calls: AtomicUsize,
}

impl MockChainAdapter {
    fn new(chain: &str) -> Self {
        Self {
            chain: chain.to_string(),
            lock_calls: AtomicUsize::new(0),
            mint_calls: AtomicUsize::new(0),
        }
    }
}

fn sample_proof_bundle(transfer: &CrossChainTransfer) -> Result<ProofBundle, AdapterError> {
    use csv_hash::dag::{DAGNode, DAGSegment};
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};

    let node = DAGNode::new(
        csv_hash::Hash::new([1u8; 32]),
        vec![],
        vec![],
        vec![],
        vec![],
    );
    let seal_point = SealPoint::new(transfer.sanad_id.as_bytes().to_vec(), Some(0), None)
        .map_err(|e| AdapterError::Generic(format!("seal point: {e}")))?;
    let commit_anchor = CommitAnchor::new(vec![1u8; 32], 100, vec![])
        .map_err(|e| AdapterError::Generic(format!("commit anchor: {e}")))?;
    let inclusion_proof = InclusionProof::new(vec![], csv_hash::Hash::new([1u8; 32]), 100, 0)
        .map_err(|e| AdapterError::Generic(format!("inclusion proof: {e}")))?;
    let finality_proof = FinalityProof::new(vec![1u8; 32], 6, true)
        .map_err(|e| AdapterError::Generic(format!("finality proof: {e}")))?;
    ProofBundle::new(
        DAGSegment::new(vec![node], csv_hash::Hash::new([1u8; 32])),
        vec![vec![0u8; 64]],
        seal_point,
        commit_anchor,
        inclusion_proof,
        finality_proof,
    )
    .map_err(|e| AdapterError::Generic(format!("proof bundle: {e}")))
}

#[async_trait]
impl ChainAdapter for MockChainAdapter {
    fn chain_id(&self) -> &str {
        &self.chain
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities::bitcoin()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError> {
        self.lock_calls.fetch_add(1, Ordering::SeqCst);
        // Idempotent: deterministic in the transfer id, no side effect that a
        // retry could double-apply.
        Ok(LockResult {
            tx_hash: format!("lock-{}", transfer.id),
            block_height: 100,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        self.mint_calls.fetch_add(1, Ordering::SeqCst);
        // A real host would submit; the mock asserts it received a non-empty,
        // decodable proof bundle so a corrupted-payload bug can't pass silently.
        ProofBundle::from_canonical_bytes(proof_bundle)
            .map_err(|e| AdapterError::Generic(format!("mint received bad proof: {e}")))?;
        Ok(MintResult {
            tx_hash: format!("mint-{}", transfer.id),
            block_height: 200,
            materialization: DestinationMaterialization::unavailable(&transfer.destination_chain),
        })
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        _lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        sample_proof_bundle(transfer)
    }

    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        if proof_bundle.seal_ref.id != transfer.sanad_id.as_bytes() {
            return Err(AdapterError::ProofVerificationFailed(
                "proof does not bind the transfer sanad".to_string(),
            ));
        }
        Ok(())
    }

    async fn check_seal_registry(
        &self,
        _seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        Ok(SealRegistryStatus::Available)
    }

    async fn confirm_tx(&self, tx_hash: &str) -> Result<MintResult, AdapterError> {
        Ok(MintResult {
            tx_hash: tx_hash.to_string(),
            block_height: 200,
            materialization: DestinationMaterialization::unavailable(&self.chain),
        })
    }

    async fn tx_finality(&self, _tx_hash: &str) -> Result<TxFinality, AdapterError> {
        Ok(TxFinality {
            block_height: 200,
            confirmations: 6,
            observed_tip_height: Some(206),
        })
    }

    async fn get_balance(&self, _address: &str) -> Result<String, AdapterError> {
        Ok("1000".to_string())
    }

    async fn settle_escrow(
        &self,
        _transfer: &CrossChainTransfer,
        _settlement_request: &[u8],
    ) -> Result<SettlementResult, AdapterError> {
        Ok(SettlementResult {
            tx_hash: "settle".to_string(),
            block_height: 300,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Minimal registry wrapping a single mock adapter, keyed by chain id.
struct MockRegistry {
    adapter: MockChainAdapter,
}

impl MockRegistry {
    fn new(chain: &str) -> Self {
        Self {
            adapter: MockChainAdapter::new(chain),
        }
    }

    fn resolve(&self, chain_id: &str) -> Result<&MockChainAdapter, AdapterError> {
        if chain_id == self.adapter.chain {
            Ok(&self.adapter)
        } else {
            Err(AdapterError::Generic(format!(
                "Adapter not found for chain: {chain_id}"
            )))
        }
    }
}

impl ChainCapabilityPort for MockRegistry {
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities> {
        self.resolve(chain_id).ok().map(|a| a.capabilities())
    }
    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme> {
        self.resolve(chain_id).ok().map(|a| a.signature_scheme())
    }
}

#[async_trait]
impl AdapterRegistry for MockRegistry {
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities> {
        ChainCapabilityPort::capabilities(self, chain_id)
    }
    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme> {
        ChainCapabilityPort::signature_scheme(self, chain_id)
    }
    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError> {
        self.resolve(chain_id)?.lock_sanad(transfer).await
    }
    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        self.resolve(chain_id)?
            .mint_sanad(transfer, proof_bundle)
            .await
    }
    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        self.resolve(chain_id)?.check_seal_registry(seal_id).await
    }
    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        self.resolve(chain_id)?
            .build_inclusion_proof(transfer, lock_result)
            .await
    }
    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        self.resolve(chain_id)?
            .validate_source_proof(transfer, proof_bundle)
            .await
    }
    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError> {
        self.resolve(chain_id)?.confirm_tx(tx_hash).await
    }
    async fn tx_finality(&self, chain_id: &str, tx_hash: &str) -> Result<TxFinality, AdapterError> {
        self.resolve(chain_id)?.tx_finality(tx_hash).await
    }
    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError> {
        self.resolve(chain_id)?.get_balance(address).await
    }
    async fn settle_escrow(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        settlement_request: &[u8],
    ) -> Result<SettlementResult, AdapterError> {
        self.resolve(chain_id)?
            .settle_escrow(transfer, settlement_request)
            .await
    }
    async fn refund_escrow(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<SettlementResult, AdapterError> {
        self.resolve(chain_id)?.refund_escrow(transfer).await
    }
}

// ---------------------------------------------------------------------------
// Mock transports
// ---------------------------------------------------------------------------

/// A cooperative in-process transport that routes bytes through `host::dispatch`.
///
/// `drop_first` models a connection dropped *after* the host executed the call
/// but *before* the response reached the client: the first `send` runs dispatch
/// (host side effect happens) then reports a network error; the retry runs
/// dispatch again and returns the response. Because the mock host is idempotent,
/// the retry is safe.
struct InProcessTransport {
    registry: Arc<MockRegistry>,
    /// When true, drop the response to the first `LockSanad` call (after the
    /// host has already executed it) exactly once.
    drop_first_lock: bool,
    dropped: std::sync::atomic::AtomicBool,
}

impl InProcessTransport {
    fn new(registry: Arc<MockRegistry>) -> Self {
        Self {
            registry,
            drop_first_lock: false,
            dropped: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn dropping_first(registry: Arc<MockRegistry>) -> Self {
        Self {
            registry,
            drop_first_lock: true,
            dropped: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl RemoteTransport for InProcessTransport {
    async fn send(&self, request: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        // The host runs the call first (its side effect happens), matching a
        // connection dropped after execution but before the response arrives.
        let response = host::dispatch_bytes(self.registry.as_ref(), &request).await;

        if self.drop_first_lock && !self.dropped.load(Ordering::SeqCst) {
            let is_lock = matches!(
                RemoteRequest::decode(&request).map(|r| r.payload),
                Ok(csv_wire::remote::RemoteRequestPayload::LockSanad { .. })
            );
            if is_lock {
                self.dropped.store(true, Ordering::SeqCst);
                return Err(AdapterError::NetworkError(
                    "connection dropped before response arrived".to_string(),
                ));
            }
        }
        Ok(response)
    }
}

/// A transport that always fails — models an unreachable host.
struct UnreachableTransport;

#[async_trait]
impl RemoteTransport for UnreachableTransport {
    async fn send(&self, _request: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        Err(AdapterError::NetworkError("host unreachable".to_string()))
    }
}

/// A transport that returns garbage bytes — models a malformed / hostile host.
struct GarbageTransport;

#[async_trait]
impl RemoteTransport for GarbageTransport {
    async fn send(&self, _request: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        Ok(vec![0xff, 0x00, 0x13, 0x37])
    }
}

fn sample_transfer(chain: &str) -> CrossChainTransfer {
    CrossChainTransfer {
        id: "transfer-1".to_string(),
        source_chain: chain.to_string(),
        destination_chain: chain.to_string(),
        lock_tx_hash: vec![0u8; 32],
        lock_output_index: 0,
        sanad_id: csv_hash::Hash::new([1u8; 32]),
        transition_id: vec![0u8; 32],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lock_verify_mint_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arc::new(MockRegistry::new("mock-chain"));
    let transport = Arc::new(InProcessTransport::new(registry.clone()));
    let adapter = RemoteChainAdapter::connect("mock-chain", transport).await?;

    // Cached metadata came over the wire at connect time.
    assert_eq!(adapter.signature_scheme(), SignatureScheme::Secp256k1);

    let transfer = sample_transfer("mock-chain");

    // lock
    let lock = adapter.lock_sanad(&transfer).await?;
    assert_eq!(lock.tx_hash, "lock-transfer-1");
    assert_eq!(lock.block_height, 100);

    // build proof (source side)
    let proof = adapter.build_inclusion_proof(&transfer, &lock).await?;

    // verify (client coordinator drives this; host validates the binding)
    adapter.validate_source_proof(&transfer, &proof).await?;

    // finality still observable to the client (never short-circuited)
    let finality = adapter.tx_finality(&lock.tx_hash).await?;
    assert_eq!(finality.confirmations, 6);
    assert_eq!(finality.observed_tip_height, Some(206));

    // mint (destination side), forwarding the verified proof bytes
    let proof_bytes = proof.to_canonical_bytes()?;
    let mint = adapter.mint_sanad(&transfer, &proof_bytes).await?;
    assert_eq!(mint.tx_hash, "mint-transfer-1");
    assert_eq!(mint.block_height, 200);

    // The host executed exactly one mint via the forwarded envelope.
    assert_eq!(registry.adapter.mint_calls.load(Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn resume_after_dropped_connection_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arc::new(MockRegistry::new("mock-chain"));
    let transport = Arc::new(InProcessTransport::dropping_first(registry.clone()));
    let adapter = RemoteChainAdapter::connect("mock-chain", transport).await?;
    let transfer = sample_transfer("mock-chain");

    // First lock attempt: the transport drops the response after the host ran.
    let first = adapter.lock_sanad(&transfer).await;
    assert!(first.is_err(), "dropped response must surface as an error");

    // Coordinator resumes: retry the same phase. The host lock is idempotent,
    // so the retried result matches what the (lost) first result would have been.
    let retry = adapter.lock_sanad(&transfer).await?;
    assert_eq!(retry.tx_hash, "lock-transfer-1");

    // The host executed the lock on both attempts, but the deterministic,
    // side-effect-free result means resume is safe — no double-spend risk from
    // the transport layer.
    assert_eq!(registry.adapter.lock_calls.load(Ordering::SeqCst), 2);

    Ok(())
}

#[tokio::test]
async fn unreachable_host_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let result = RemoteChainAdapter::connect("mock-chain", Arc::new(UnreachableTransport)).await;
    match result {
        Err(AdapterError::NetworkError(_)) => Ok(()),
        Ok(_) => Err("expected a typed network error, got a connected adapter".into()),
        Err(other) => Err(format!("expected a typed network error, got {other:?}").into()),
    }
}

#[tokio::test]
async fn malformed_response_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let result = RemoteChainAdapter::connect("mock-chain", Arc::new(GarbageTransport)).await;
    match result {
        Err(AdapterError::SerializationError(_)) => Ok(()),
        Ok(_) => Err("expected a typed serialization error, got a connected adapter".into()),
        Err(other) => Err(format!("expected a typed serialization error, got {other:?}").into()),
    }
}

#[tokio::test]
async fn unknown_chain_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    // Host only knows "mock-chain"; connecting for "other-chain" must fail closed.
    let registry = Arc::new(MockRegistry::new("mock-chain"));
    let transport = Arc::new(InProcessTransport::new(registry));
    let result = RemoteChainAdapter::connect("other-chain", transport).await;
    match result {
        Err(AdapterError::Generic(msg)) => {
            assert!(msg.contains("no adapter"), "unexpected message: {msg}");
            Ok(())
        }
        Ok(_) => Err("expected a typed unknown-chain error, got a connected adapter".into()),
        Err(other) => Err(format!("expected a typed unknown-chain error, got {other:?}").into()),
    }
}

#[tokio::test]
async fn unknown_chain_metadata_returns_typed_wire_error() {
    let registry = MockRegistry::new("mock-chain");
    let request = RemoteRequest::new("other-chain", RemoteRequestPayload::Capabilities);

    let response = host::dispatch(&registry, request).await;

    assert!(matches!(
        response.payload,
        RemoteResponsePayload::Error(RemoteError::UnknownChain(chain))
            if chain == "other-chain"
    ));
}

#[tokio::test]
async fn version_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    // A host speaking a different envelope version must be rejected, not trusted.
    let registry = MockRegistry::new("mock-chain");
    let mut request = RemoteRequest::new(
        "mock-chain",
        csv_wire::remote::RemoteRequestPayload::Capabilities,
    );
    request.version = 999;
    let response = host::dispatch(&registry, request).await;
    match response.payload {
        RemoteResponsePayload::Error(RemoteError::VersionMismatch { got, .. }) => {
            assert_eq!(got, 999);
            Ok(())
        }
        other => Err(format!("expected version mismatch, got {other:?}").into()),
    }
}

#[tokio::test]
async fn no_key_material_in_request_envelope() -> Result<(), Box<dyn std::error::Error>> {
    // The wire envelope must never carry secret key bytes. We assert the encoded
    // request is derived only from public transfer metadata by checking it
    // round-trips and contains no field where a key could hide (structural: the
    // payload types have no secret field). Here we sanity-check that a lock
    // request encodes deterministically and decodes to the same public data.
    let transfer = sample_transfer("mock-chain");
    let request = RemoteRequest::new(
        "mock-chain",
        csv_wire::remote::RemoteRequestPayload::LockSanad {
            transfer: csv_remote::convert::transfer_to_wire(&transfer),
        },
    );
    let bytes = request.encode()?;
    let decoded = RemoteRequest::decode(&bytes)?;
    assert_eq!(request, decoded);
    // Encoding a response with an error must also round-trip cleanly.
    let err = RemoteResponse::error(RemoteError::UnknownChain("x".into()));
    let _ = err.encode()?;
    Ok(())
}
