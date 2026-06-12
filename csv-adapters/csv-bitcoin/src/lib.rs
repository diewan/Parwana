//! Bitcoin Adapter for CSV (Client-Side Validation)
#![allow(clippy::needless_return)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_borrows_for_generic_args)]
//!
//! This adapter implements the SealProtocol trait for Bitcoin,
//! using UTXOs as single-use seals and Tapret/Opret for commitment publication.

#![warn(missing_docs)]
#![allow(missing_docs)]
#![allow(dead_code)]

pub mod adapter_impl;
pub mod bip341;
pub mod config;
pub mod error;
pub mod mint;
pub mod mpc_batch;
pub mod node;
pub mod ops;
pub mod proofs;
pub mod rpc;
pub mod seal;
pub mod seal_protocol;
pub mod signatures;
pub mod sp1_guest;
pub mod spv;
pub mod tapret;
pub mod tx_builder;
pub mod types;
// pub mod verifier;  // REMOVED: verification centralized in csv-verifier per implementation.md
pub mod wallet;
pub mod wallet_operations;
pub mod zk_prover;

#[cfg(feature = "signet-rest")]
pub mod mempool_rpc;

pub mod json_rpc;

pub mod runtime_adapter;

pub use bip341::{Bip341Error, TaprootOutput, derive_output_key, generate_test_keypair};
pub use config::{BitcoinConfig, BitcoinRpcBackend, Network};
pub use rpc::BitcoinRpc;
pub use seal_protocol::BitcoinSealProtocol;
pub use sp1_guest::{
    Sp1BtcSpvInput as Sp1GuestInput, Sp1BtcSpvOutput as Sp1GuestOutput, verify_bitcoin_spv,
};
pub use spv::SpvVerifier;
pub use tapret::{
    OpretCommitment, TAPRET_SCRIPT_SIZE, TapretCommitment, TapretError, mine_tapret_nonce,
};
pub use tx_builder::{CommitmentData, CommitmentTxBuilder, TxBuilderError};
pub use types::{
    BitcoinCommitAnchor, BitcoinFinalityProof, BitcoinInclusionProof, BitcoinSealPoint,
};
pub use wallet::{Bip86Path, DerivedTaprootKey, SealWallet, WalletError, WalletUtxo};
pub use wallet_operations::{BitcoinWalletOperations, Network as WalletNetwork, WalletUtxo as WalletOpsUtxo};
pub use zk_prover::{BitcoinSpvProver, Sp1BtcSpvInput};

// MPC batching for cost optimization
pub use mpc_batch::{
    BatchedPublication, CSV_BTC_PROTOCOL_ID, MpcBatcher, MpcTreeExt, PendingCommitment,
};

// Ops exports
pub use ops::{
    BitcoinBackend, BitcoinChainBroadcaster, BitcoinChainDeployer, BitcoinChainProofProvider,
    BitcoinChainQuery, BitcoinChainSanadOps, BitcoinChainSigner,
};

#[cfg(feature = "rpc")]
pub use node::real_rpc::{BitcoinNode, TxInfo};

#[cfg(feature = "signet-rest")]
pub use mempool_rpc::MempoolSignetRpc;

pub use json_rpc::BitcoinJsonRpc;
