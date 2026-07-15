//! Remote chain-dispatch envelope (WASM-REMOTE-001).
//!
//! A browser / thin-client coordinator runs client-side validation, proof
//! verification, and the execution journal locally, but cannot execute chain
//! actions (the concrete chain adapters do not compile to wasm and must not run
//! in a browser tab). This module owns the **transport envelope** that forwards
//! each adapter-registry port call to a user-owned native host (the `csv`
//! daemon) which owns the real adapter registry.
//!
//! `csv-wire` owns ALL transport encoding, so the envelope types and their
//! canonical-CBOR (via `csv-codec`) encode/decode live here. `serde_json` is
//! deliberately never used on this path.
//!
//! # Security boundary
//!
//! * The envelope carries **no private key material** in either direction. The
//!   coordinator holds wallet / ownership keys; the host holds only its own
//!   chain-submission keys. Every payload below is derived from public transfer
//!   metadata, public proof bundles, and public chain reads.
//! * The host is a dumb port-forwarder over its registry, not a second
//!   decision-maker: finality and proof verification stay in the client
//!   coordinator. The envelope has no "skip finality" variant.
//! * Every failure is a typed [`RemoteError`] — an unreachable host, a
//!   malformed envelope, a version mismatch, or an unknown chain each produce an
//!   error, never a silent fallback.
//!
//! The wire structs here mirror the runtime port types (which live in the
//! higher `csv-chain-ports` layer that `csv-wire` must not depend on). The
//! `csv-remote` adapter crate and the host endpoint own the
//! port ⇄ wire conversions.

use csv_codec::{CodecError, from_canonical_cbor, to_canonical_cbor};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::signature::SignatureScheme;
use serde::{Deserialize, Serialize};

/// Version of the remote-dispatch envelope contract.
///
/// Both ends stamp this into every message and reject a mismatch (fail closed).
/// Bump on any breaking change to a payload's shape.
pub const REMOTE_DISPATCH_VERSION: u16 = 1;

/// Wire mirror of `CrossChainTransfer` (csv-chain-ports).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTransfer {
    /// Unique transfer id.
    pub id: String,
    /// Source chain id.
    pub source_chain: String,
    /// Destination chain id.
    pub destination_chain: String,
    /// Lock transaction hash on the source chain.
    pub lock_tx_hash: Vec<u8>,
    /// Lock output index on the source chain.
    pub lock_output_index: u32,
    /// Sanad id being transferred.
    pub sanad_id: [u8; 32],
    /// Transition id for the transfer.
    pub transition_id: Vec<u8>,
}

/// Wire mirror of `LockResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteLockResult {
    /// Transaction hash of the lock.
    pub tx_hash: String,
    /// Block height of the lock.
    pub block_height: u64,
}

/// Wire mirror of `DestinationMaterialization`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteMaterialization {
    /// Destination chain that produced the metadata.
    pub chain_id: String,
    /// Destination object/account/resource id, when observed.
    pub object_id: Option<String>,
    /// Destination seal reference, when observed.
    pub seal_ref: Option<String>,
    /// Destination registry reference, when observed.
    pub registry_ref: Option<String>,
    /// Commitment recorded by the destination chain, when observed.
    pub commitment: Option<[u8; 32]>,
    /// Destination owner bytes recorded by the destination chain, when observed.
    pub owner: Option<Vec<u8>>,
}

/// Wire mirror of `MintResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteMintResult {
    /// Transaction hash of the mint.
    pub tx_hash: String,
    /// Block height of the mint.
    pub block_height: u64,
    /// Destination-side materialization data observed by the adapter.
    pub materialization: RemoteMaterialization,
}

/// Wire mirror of `TxFinality`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTxFinality {
    /// Height of the block that includes the transaction (`0` when unconfirmed).
    pub block_height: u64,
    /// Number of confirmations (`0` when unconfirmed).
    pub confirmations: u64,
    /// Chain tip height the host actually read when it measured `confirmations`.
    ///
    /// `None` means no tip was read — never "tip unknown, assume final". The
    /// client finality gate must treat `None` as the absence of an observed tip
    /// and must never reconstruct it as `block_height + confirmations`.
    pub observed_tip_height: Option<u64>,
}

/// Wire mirror of `SealRegistryStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteSealRegistryStatus {
    /// Seal is available for use.
    Available,
    /// Seal has been consumed.
    Consumed,
    /// Seal is locked.
    Locked,
}

/// Wire mirror of `SettlementResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSettlementResult {
    /// Transaction hash of the settlement.
    pub tx_hash: String,
    /// Block height of the settlement.
    pub block_height: u64,
}

/// Request payload — one variant per adapter-registry port method.
///
/// Proof bundles travel as their canonical byte encoding
/// (`ProofBundle::to_canonical_bytes`), kept opaque at this layer so the
/// envelope never re-encodes protocol proof state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteRequestPayload {
    /// Query the chain capabilities (sync metadata query).
    Capabilities,
    /// Query the signature scheme (sync metadata query).
    SignatureScheme,
    /// Lock a Sanad on the source chain.
    LockSanad {
        /// Transfer being locked.
        transfer: RemoteTransfer,
    },
    /// Mint a Sanad on the destination chain.
    MintSanad {
        /// Transfer being minted.
        transfer: RemoteTransfer,
        /// Canonical bytes of the verified source proof bundle / mint request.
        proof_bundle: Vec<u8>,
    },
    /// Check the status of a seal in the registry.
    CheckSealRegistry {
        /// Seal id to look up.
        seal_id: Vec<u8>,
    },
    /// Build an inclusion proof for a locked transaction.
    BuildInclusionProof {
        /// Transfer whose lock is being proven.
        transfer: RemoteTransfer,
        /// The lock result returned by a prior `LockSanad`.
        lock_result: RemoteLockResult,
    },
    /// Validate source-chain proof material against a transfer.
    ValidateSourceProof {
        /// Transfer the proof must bind.
        transfer: RemoteTransfer,
        /// Canonical bytes of the proof bundle to validate.
        proof_bundle: Vec<u8>,
    },
    /// Confirm a transaction on the chain.
    ConfirmTx {
        /// Transaction hash to confirm.
        tx_hash: String,
    },
    /// Query the confirmation status of a transaction.
    TxFinality {
        /// Transaction hash to query.
        tx_hash: String,
    },
    /// Get the balance for an address.
    GetBalance {
        /// Address to query.
        address: String,
    },
    /// Release a source-chain escrow on a verifier-signed settlement receipt.
    SettleEscrow {
        /// Transfer whose escrow is being released.
        transfer: RemoteTransfer,
        /// Canonical bytes of the runtime settlement request.
        settlement_request: Vec<u8>,
    },
    /// Refund a source-chain escrow to the original locker after timeout.
    RefundEscrow {
        /// Transfer whose escrow is being refunded.
        transfer: RemoteTransfer,
    },
}

/// A versioned request forwarded to the host for one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRequest {
    /// Envelope contract version. See [`REMOTE_DISPATCH_VERSION`].
    pub version: u16,
    /// Chain id this call targets (the client holds one adapter per chain).
    pub chain_id: String,
    /// The call to perform.
    pub payload: RemoteRequestPayload,
}

impl RemoteRequest {
    /// Build a request stamped with the current envelope version.
    pub fn new(chain_id: impl Into<String>, payload: RemoteRequestPayload) -> Self {
        Self {
            version: REMOTE_DISPATCH_VERSION,
            chain_id: chain_id.into(),
            payload,
        }
    }

    /// Encode to canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        to_canonical_cbor(self)
    }

    /// Decode from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        from_canonical_cbor(bytes)
    }
}

/// Response payload — mirrors the corresponding [`RemoteRequestPayload`] result,
/// or a typed [`RemoteError`].
///
/// Not `PartialEq`: `ChainCapabilities` (embedded in `Capabilities`) does not
/// implement it. Compare responses by their canonical encoding when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemoteResponsePayload {
    /// Result of `Capabilities` (absent when the host has no such chain).
    Capabilities(Option<ChainCapabilities>),
    /// Result of `SignatureScheme` (absent when the host has no such chain).
    SignatureScheme(Option<SignatureScheme>),
    /// Result of `LockSanad`.
    LockSanad(RemoteLockResult),
    /// Result of `MintSanad`.
    MintSanad(RemoteMintResult),
    /// Result of `CheckSealRegistry`.
    CheckSealRegistry(RemoteSealRegistryStatus),
    /// Result of `BuildInclusionProof` — canonical proof-bundle bytes.
    BuildInclusionProof {
        /// Canonical bytes of the produced proof bundle.
        proof_bundle: Vec<u8>,
    },
    /// Result of `ValidateSourceProof` (success carries no data).
    ValidateSourceProof,
    /// Result of `ConfirmTx`.
    ConfirmTx(RemoteMintResult),
    /// Result of `TxFinality`.
    TxFinality(RemoteTxFinality),
    /// Result of `GetBalance`.
    GetBalance(String),
    /// Result of `SettleEscrow`.
    SettleEscrow(RemoteSettlementResult),
    /// Result of `RefundEscrow`.
    RefundEscrow(RemoteSettlementResult),
    /// A typed failure. Always fail closed; never a fallback value.
    Error(RemoteError),
}

/// A versioned response from the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteResponse {
    /// Envelope contract version. See [`REMOTE_DISPATCH_VERSION`].
    pub version: u16,
    /// The result of the call.
    pub payload: RemoteResponsePayload,
}

impl RemoteResponse {
    /// Build an `Ok` response stamped with the current envelope version.
    pub fn ok(payload: RemoteResponsePayload) -> Self {
        Self {
            version: REMOTE_DISPATCH_VERSION,
            payload,
        }
    }

    /// Build an error response stamped with the current envelope version.
    pub fn error(error: RemoteError) -> Self {
        Self::ok(RemoteResponsePayload::Error(error))
    }

    /// Encode to canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        to_canonical_cbor(self)
    }

    /// Decode from canonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        from_canonical_cbor(bytes)
    }
}

/// Typed error carried over the remote-dispatch boundary.
///
/// Every variant is fail-closed: the client maps each back to an adapter error
/// and never substitutes a default result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum RemoteError {
    /// The two ends disagree on the envelope contract version.
    #[error("remote dispatch version mismatch: host speaks {expected}, request used {got}")]
    VersionMismatch {
        /// Version the host implements.
        expected: u16,
        /// Version the incoming message used.
        got: u16,
    },
    /// The host has no adapter registered for the requested chain.
    #[error("unknown chain at host: {0}")]
    UnknownChain(String),
    /// The envelope (or an embedded proof bundle) could not be decoded.
    #[error("malformed remote envelope: {0}")]
    Malformed(String),
    /// The host adapter returned an error executing the call.
    #[error("host adapter error: {0}")]
    Adapter(String),
    /// The client rejected the request before dispatch (authentication /
    /// transport failure surfaced as a typed error rather than a panic).
    #[error("remote transport error: {0}")]
    Transport(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_through_canonical_cbor() {
        let req = RemoteRequest::new(
            "bitcoin",
            RemoteRequestPayload::LockSanad {
                transfer: RemoteTransfer {
                    id: "t1".into(),
                    source_chain: "bitcoin".into(),
                    destination_chain: "ethereum".into(),
                    lock_tx_hash: vec![1, 2, 3],
                    lock_output_index: 0,
                    sanad_id: [7u8; 32],
                    transition_id: vec![9, 9],
                },
            },
        );
        let bytes = req.encode().unwrap();
        let decoded = RemoteRequest::decode(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn response_round_trips_and_is_deterministic() {
        let resp = RemoteResponse::ok(RemoteResponsePayload::TxFinality(RemoteTxFinality {
            block_height: 100,
            confirmations: 6,
            observed_tip_height: Some(106),
        }));
        let a = resp.encode().unwrap();
        let b = resp.encode().unwrap();
        assert_eq!(a, b, "canonical encoding must be deterministic");
        // RemoteResponse is not PartialEq (ChainCapabilities); compare by re-encoding.
        let reencoded = RemoteResponse::decode(&a).unwrap().encode().unwrap();
        assert_eq!(a, reencoded);
    }

    #[test]
    fn error_response_round_trips() {
        let resp = RemoteResponse::error(RemoteError::VersionMismatch {
            expected: REMOTE_DISPATCH_VERSION,
            got: 999,
        });
        let bytes = resp.encode().unwrap();
        let decoded = RemoteResponse::decode(&bytes).unwrap();
        match decoded.payload {
            RemoteResponsePayload::Error(RemoteError::VersionMismatch { expected, got }) => {
                assert_eq!(expected, REMOTE_DISPATCH_VERSION);
                assert_eq!(got, 999);
            }
            other => panic!("expected version mismatch error, got {other:?}"),
        }
    }
}
