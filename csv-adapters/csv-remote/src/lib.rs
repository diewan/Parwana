//! Remote chain-dispatch adapter (WASM-REMOTE-001).
//!
//! A browser / thin-client coordinator runs client-side validation, proof
//! verification, and the execution journal locally, but the concrete chain
//! adapters cannot compile to wasm and must not run in a browser tab. This crate
//! bridges the gap: [`RemoteChainAdapter`] implements the [`ChainAdapter`] port
//! by encoding each call into a versioned `csv-wire` envelope and forwarding it
//! (over a [`RemoteTransport`]) to a **user-owned native host** — the `csv`
//! daemon — that owns the real adapter registry.
//!
//! ```text
//!  browser coordinator                          native host (csv daemon)
//!  ┌─────────────────────────┐   envelope       ┌────────────────────────┐
//!  │ TransferCoordinator      │  ───────────▶    │ host::dispatch          │
//!  │  └ RemoteChainAdapter ───┼── RemoteTransport┼─▶ AdapterRegistry        │
//!  │       (this crate)       │  ◀───────────    │    (concrete adapters)   │
//!  └─────────────────────────┘   envelope       └────────────────────────┘
//! ```
//!
//! # Security properties
//!
//! * **No key material crosses the wire.** The client holds wallet / ownership
//!   keys; the host holds only its own chain-submission keys. Payloads carry
//!   public transfer metadata, public proof bundles, and public chain reads.
//! * **Finality stays client-side.** The host cannot short-circuit the
//!   coordinator's finality gate; it only reports what it read, and
//!   `observed_tip_height` is forwarded verbatim (never reconstructed).
//! * **Fail closed.** An unreachable host, a malformed envelope, a version
//!   mismatch, or an unknown chain each surface as a typed [`AdapterError`];
//!   there is never a fallback value.
//! * **Authenticated.** The host is user-owned, not a public service; the
//!   bundled [`HttpTransport`] authenticates with a bearer token.

#![warn(missing_docs)]

pub mod convert;
pub mod host;
pub mod transport;

use std::sync::Arc;

use async_trait::async_trait;
use csv_chain_ports::{
    AdapterError, ChainAdapter, CrossChainTransfer, LockResult, MintResult, SealRegistryStatus,
    SettlementResult, TxFinality,
};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use csv_wire::remote::{
    REMOTE_DISPATCH_VERSION, RemoteError, RemoteRequest, RemoteRequestPayload, RemoteResponse,
    RemoteResponsePayload,
};

#[cfg(feature = "http")]
pub use transport::HttpTransport;
pub use transport::RemoteTransport;

/// Translate a typed wire error into the adapter error surface. Always
/// fail-closed — no variant maps to a success or default value.
fn remote_error_to_adapter(error: RemoteError) -> AdapterError {
    match error {
        RemoteError::VersionMismatch { expected, got } => AdapterError::Generic(format!(
            "remote dispatch version mismatch: host speaks {expected}, client used {got}"
        )),
        RemoteError::UnknownChain(chain) => {
            AdapterError::Generic(format!("remote host has no adapter for chain: {chain}"))
        }
        RemoteError::Malformed(message) => AdapterError::SerializationError(message),
        RemoteError::Adapter(message) => AdapterError::RpcError(message),
        RemoteError::Transport(message) => AdapterError::NetworkError(message),
    }
}

/// A [`ChainAdapter`] that forwards every call to a remote host over a
/// [`RemoteTransport`]. One instance per chain id.
///
/// Construct with [`RemoteChainAdapter::connect`], which fetches the chain's
/// capabilities and signature scheme once (the sync metadata the
/// [`ChainAdapter`] trait exposes non-async) and caches them, so the trait's
/// synchronous `capabilities()` / `signature_scheme()` never block on the
/// network.
pub struct RemoteChainAdapter {
    chain_id: String,
    transport: Arc<dyn RemoteTransport>,
    capabilities: ChainCapabilities,
    signature_scheme: SignatureScheme,
}

impl RemoteChainAdapter {
    /// Connect to a host for a single chain, fetching and caching its
    /// capabilities and signature scheme.
    ///
    /// Fails closed if the host does not know the chain (either metadata query
    /// returning absent), if the transport fails, or if the host reports a typed
    /// error.
    pub async fn connect(
        chain_id: impl Into<String>,
        transport: Arc<dyn RemoteTransport>,
    ) -> Result<Self, AdapterError> {
        let chain_id = chain_id.into();

        let capabilities =
            match call(&transport, &chain_id, RemoteRequestPayload::Capabilities).await? {
                RemoteResponsePayload::Capabilities(Some(caps)) => caps,
                RemoteResponsePayload::Capabilities(None) => {
                    return Err(AdapterError::Generic(format!(
                        "remote host has no adapter for chain: {chain_id}"
                    )));
                }
                other => return Err(unexpected_variant("Capabilities", &other)),
            };

        let signature_scheme =
            match call(&transport, &chain_id, RemoteRequestPayload::SignatureScheme).await? {
                RemoteResponsePayload::SignatureScheme(Some(scheme)) => scheme,
                RemoteResponsePayload::SignatureScheme(None) => {
                    return Err(AdapterError::Generic(format!(
                        "remote host has no signature scheme for chain: {chain_id}"
                    )));
                }
                other => return Err(unexpected_variant("SignatureScheme", &other)),
            };

        Ok(Self {
            chain_id,
            transport,
            capabilities,
            signature_scheme,
        })
    }

    async fn call(
        &self,
        payload: RemoteRequestPayload,
    ) -> Result<RemoteResponsePayload, AdapterError> {
        call(&self.transport, &self.chain_id, payload).await
    }
}

/// Encode a request, send it over the transport, decode the response, and
/// unwrap it to its payload — mapping every typed failure to an
/// [`AdapterError`].
async fn call(
    transport: &Arc<dyn RemoteTransport>,
    chain_id: &str,
    payload: RemoteRequestPayload,
) -> Result<RemoteResponsePayload, AdapterError> {
    let request = RemoteRequest::new(chain_id, payload);
    let request_bytes = request
        .encode()
        .map_err(|e| AdapterError::SerializationError(e.to_string()))?;

    let response_bytes = transport.send(request_bytes).await?;

    let response = RemoteResponse::decode(&response_bytes)
        .map_err(|e| AdapterError::SerializationError(e.to_string()))?;

    if response.version != REMOTE_DISPATCH_VERSION {
        return Err(AdapterError::Generic(format!(
            "remote dispatch version mismatch: client speaks {REMOTE_DISPATCH_VERSION}, host used {}",
            response.version
        )));
    }

    match response.payload {
        RemoteResponsePayload::Error(error) => Err(remote_error_to_adapter(error)),
        payload => Ok(payload),
    }
}

fn unexpected_variant(expected: &str, got: &RemoteResponsePayload) -> AdapterError {
    AdapterError::Generic(format!(
        "remote host returned an unexpected response for a {expected} request: {got:?}"
    ))
}

#[async_trait]
impl ChainAdapter for RemoteChainAdapter {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        self.capabilities.clone()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError> {
        let payload = RemoteRequestPayload::LockSanad {
            transfer: convert::transfer_to_wire(transfer),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::LockSanad(result) => Ok(convert::lock_result_from_wire(&result)),
            other => Err(unexpected_variant("LockSanad", &other)),
        }
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        let payload = RemoteRequestPayload::MintSanad {
            transfer: convert::transfer_to_wire(transfer),
            proof_bundle: proof_bundle.to_vec(),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::MintSanad(result) => Ok(convert::mint_result_from_wire(&result)),
            other => Err(unexpected_variant("MintSanad", &other)),
        }
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        let payload = RemoteRequestPayload::BuildInclusionProof {
            transfer: convert::transfer_to_wire(transfer),
            lock_result: convert::lock_result_to_wire(lock_result),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::BuildInclusionProof { proof_bundle } => {
                ProofBundle::from_canonical_bytes(&proof_bundle).map_err(|e| {
                    AdapterError::SerializationError(format!(
                        "remote host returned an undecodable inclusion proof: {e}"
                    ))
                })
            }
            other => Err(unexpected_variant("BuildInclusionProof", &other)),
        }
    }

    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        let proof_bytes = proof_bundle.to_canonical_bytes().map_err(|e| {
            AdapterError::SerializationError(format!("failed to encode proof bundle: {e}"))
        })?;
        let payload = RemoteRequestPayload::ValidateSourceProof {
            transfer: convert::transfer_to_wire(transfer),
            proof_bundle: proof_bytes,
        };
        match self.call(payload).await? {
            RemoteResponsePayload::ValidateSourceProof => Ok(()),
            other => Err(unexpected_variant("ValidateSourceProof", &other)),
        }
    }

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        let payload = RemoteRequestPayload::CheckSealRegistry {
            seal_id: seal_id.to_vec(),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::CheckSealRegistry(status) => {
                Ok(convert::seal_status_from_wire(status))
            }
            other => Err(unexpected_variant("CheckSealRegistry", &other)),
        }
    }

    async fn confirm_tx(&self, tx_hash: &str) -> Result<MintResult, AdapterError> {
        let payload = RemoteRequestPayload::ConfirmTx {
            tx_hash: tx_hash.to_string(),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::ConfirmTx(result) => Ok(convert::mint_result_from_wire(&result)),
            other => Err(unexpected_variant("ConfirmTx", &other)),
        }
    }

    async fn tx_finality(&self, tx_hash: &str) -> Result<TxFinality, AdapterError> {
        let payload = RemoteRequestPayload::TxFinality {
            tx_hash: tx_hash.to_string(),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::TxFinality(finality) => {
                Ok(convert::tx_finality_from_wire(&finality))
            }
            other => Err(unexpected_variant("TxFinality", &other)),
        }
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        let payload = RemoteRequestPayload::GetBalance {
            address: address.to_string(),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::GetBalance(balance) => Ok(balance),
            other => Err(unexpected_variant("GetBalance", &other)),
        }
    }

    async fn settle_escrow(
        &self,
        transfer: &CrossChainTransfer,
        settlement_request: &[u8],
    ) -> Result<SettlementResult, AdapterError> {
        let payload = RemoteRequestPayload::SettleEscrow {
            transfer: convert::transfer_to_wire(transfer),
            settlement_request: settlement_request.to_vec(),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::SettleEscrow(result) => {
                Ok(convert::settlement_from_wire(&result))
            }
            other => Err(unexpected_variant("SettleEscrow", &other)),
        }
    }

    async fn refund_escrow(
        &self,
        transfer: &CrossChainTransfer,
    ) -> Result<SettlementResult, AdapterError> {
        let payload = RemoteRequestPayload::RefundEscrow {
            transfer: convert::transfer_to_wire(transfer),
        };
        match self.call(payload).await? {
            RemoteResponsePayload::RefundEscrow(result) => {
                Ok(convert::settlement_from_wire(&result))
            }
            other => Err(unexpected_variant("RefundEscrow", &other)),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
