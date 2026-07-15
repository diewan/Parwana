//! Host-side endpoint: decode an envelope, dispatch it to the local adapter
//! registry, encode the result.
//!
//! The host is a **dumb port-forwarder** over the registry, not a second
//! decision-maker. It never verifies proofs, never decides finality, and never
//! mutates coordinator state — those stay in the client coordinator. It only
//! executes the exact registry call the client asked for and returns the exact
//! result. Every failure path returns a typed [`RemoteError`]; there is no
//! fallback value.
//!
//! Transport, authentication (bearer token / mTLS), and the process that owns
//! the registry live in the caller (the `csv runtime serve` subcommand). This
//! module is transport-agnostic so the same dispatch logic backs both a real
//! HTTP endpoint and the in-process round-trip tests.

use csv_chain_ports::AdapterError;
use csv_chain_ports::AdapterRegistry;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_wire::remote::{
    REMOTE_DISPATCH_VERSION, RemoteError, RemoteRequest, RemoteRequestPayload, RemoteResponse,
    RemoteResponsePayload,
};

use crate::convert;

/// Map a host adapter error into a typed wire error.
///
/// A missing adapter is surfaced as [`RemoteError::UnknownChain`] so the client
/// fails closed with an accurate cause; every other adapter failure is carried
/// verbatim as [`RemoteError::Adapter`].
fn adapter_error_to_remote(chain: &str, err: AdapterError) -> RemoteError {
    let message = err.to_string();
    if message.contains("Adapter not found") {
        RemoteError::UnknownChain(chain.to_string())
    } else {
        RemoteError::Adapter(message)
    }
}

/// Decode a request envelope, dispatch it, and encode the response envelope.
///
/// Used by the HTTP host handler. A request that cannot be decoded yields a
/// [`RemoteError::Malformed`] response (fail closed) rather than an error to the
/// caller, so the client always receives a typed answer.
pub async fn dispatch_bytes(registry: &dyn AdapterRegistry, request_bytes: &[u8]) -> Vec<u8> {
    let response = match RemoteRequest::decode(request_bytes) {
        Ok(request) => dispatch(registry, request).await,
        Err(err) => RemoteResponse::error(RemoteError::Malformed(err.to_string())),
    };
    // Encoding a response envelope is infallible in practice; if it ever fails,
    // return empty bytes so the client's decode fails closed rather than panic.
    response.encode().unwrap_or_default()
}

/// Dispatch a decoded request against the host's adapter registry.
///
/// The registry is the host's single source of chain authority; this function
/// adds no authority of its own.
pub async fn dispatch(registry: &dyn AdapterRegistry, request: RemoteRequest) -> RemoteResponse {
    if request.version != REMOTE_DISPATCH_VERSION {
        return RemoteResponse::error(RemoteError::VersionMismatch {
            expected: REMOTE_DISPATCH_VERSION,
            got: request.version,
        });
    }

    let chain = request.chain_id.as_str();
    let payload = match request.payload {
        RemoteRequestPayload::Capabilities => match registry.capabilities(chain) {
            Some(capabilities) => RemoteResponsePayload::Capabilities(Some(capabilities)),
            None => RemoteResponsePayload::Error(RemoteError::UnknownChain(chain.to_string())),
        },
        RemoteRequestPayload::SignatureScheme => match registry.signature_scheme(chain) {
            Some(signature_scheme) => {
                RemoteResponsePayload::SignatureScheme(Some(signature_scheme))
            }
            None => RemoteResponsePayload::Error(RemoteError::UnknownChain(chain.to_string())),
        },
        RemoteRequestPayload::LockSanad { transfer } => {
            let transfer = convert::transfer_from_wire(&transfer);
            match registry.lock_sanad(chain, &transfer).await {
                Ok(result) => {
                    RemoteResponsePayload::LockSanad(convert::lock_result_to_wire(&result))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::MintSanad {
            transfer,
            proof_bundle,
        } => {
            let transfer = convert::transfer_from_wire(&transfer);
            match registry.mint_sanad(chain, &transfer, &proof_bundle).await {
                Ok(result) => {
                    RemoteResponsePayload::MintSanad(convert::mint_result_to_wire(&result))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::CheckSealRegistry { seal_id } => {
            match registry.check_seal_registry(chain, &seal_id).await {
                Ok(status) => {
                    RemoteResponsePayload::CheckSealRegistry(convert::seal_status_to_wire(&status))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::BuildInclusionProof {
            transfer,
            lock_result,
        } => {
            let transfer = convert::transfer_from_wire(&transfer);
            let lock_result = convert::lock_result_from_wire(&lock_result);
            match registry
                .build_inclusion_proof(chain, &transfer, &lock_result)
                .await
            {
                Ok(bundle) => match bundle.to_canonical_bytes() {
                    Ok(proof_bundle) => RemoteResponsePayload::BuildInclusionProof { proof_bundle },
                    Err(err) => RemoteResponsePayload::Error(RemoteError::Adapter(format!(
                        "failed to encode inclusion proof: {err}"
                    ))),
                },
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::ValidateSourceProof {
            transfer,
            proof_bundle,
        } => {
            let transfer = convert::transfer_from_wire(&transfer);
            match ProofBundle::from_canonical_bytes(&proof_bundle) {
                Ok(bundle) => match registry
                    .validate_source_proof(chain, &transfer, &bundle)
                    .await
                {
                    Ok(()) => RemoteResponsePayload::ValidateSourceProof,
                    Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
                },
                Err(err) => RemoteResponsePayload::Error(RemoteError::Malformed(format!(
                    "invalid proof bundle: {err}"
                ))),
            }
        }
        RemoteRequestPayload::ConfirmTx { tx_hash } => {
            match registry.confirm_tx(chain, &tx_hash).await {
                Ok(result) => {
                    RemoteResponsePayload::ConfirmTx(convert::mint_result_to_wire(&result))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::TxFinality { tx_hash } => {
            match registry.tx_finality(chain, &tx_hash).await {
                Ok(finality) => {
                    RemoteResponsePayload::TxFinality(convert::tx_finality_to_wire(&finality))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::GetBalance { address } => {
            match registry.get_balance(chain, &address).await {
                Ok(balance) => RemoteResponsePayload::GetBalance(balance),
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::SettleEscrow {
            transfer,
            settlement_request,
        } => {
            let transfer = convert::transfer_from_wire(&transfer);
            match registry
                .settle_escrow(chain, &transfer, &settlement_request)
                .await
            {
                Ok(result) => {
                    RemoteResponsePayload::SettleEscrow(convert::settlement_to_wire(&result))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
        RemoteRequestPayload::RefundEscrow { transfer } => {
            let transfer = convert::transfer_from_wire(&transfer);
            match registry.refund_escrow(chain, &transfer).await {
                Ok(result) => {
                    RemoteResponsePayload::RefundEscrow(convert::settlement_to_wire(&result))
                }
                Err(err) => RemoteResponsePayload::Error(adapter_error_to_remote(chain, err)),
            }
        }
    };

    RemoteResponse::ok(payload)
}
