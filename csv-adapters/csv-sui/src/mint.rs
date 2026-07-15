//! Verifier-attested destination mint for CSV sanads on Sui (RFC-0012 §9).
//!
//! Under the thin-registry model, materializing a Sanad on Sui calls
//! `csv_seal::mint_sanad` on the shared `Registry` object, carrying the frozen
//! §9.2 attestation fields and a set of secp256k1 verifier signatures over the
//! attestation digest. There is NO proof root, state root, Merkle proof, or leaf
//! index on this path: cross-chain validity is adjudicated off-chain by the
//! canonical verifier, and the only on-chain authenticity check is
//! `ecdsa_k1::secp256k1_ecrecover` of the verifier signatures.
//!
//! This module owns the Move call-argument shaping ([`build_sui_mint_args`],
//! pure and unit-testable) and, under the `rpc` feature, the real transaction
//! submission ([`submit_mint`]). The runtime adapter
//! (`SuiRuntimeAdapter::mint_sanad`) is the sole caller: it binds
//! `destinationContract = Registry` object id, computes and signs the digest,
//! then hands the finished [`SuiMintArgs`] here.

use csv_chain_ports::MintAttestationInputs;

#[cfg(feature = "rpc")]
use crate::error::{SuiError, SuiResult};
#[cfg(feature = "rpc")]
use crate::node::SuiNode;
#[cfg(feature = "rpc")]
use std::sync::Arc;

/// Well-known initial shared version of the Sui system `Clock` object (`0x6`).
///
/// The `Clock` is shared at genesis on every Sui network, so its
/// `initial_shared_version` is a fixed constant rather than something to fetch.
#[cfg(feature = "rpc")]
const CLOCK_INITIAL_SHARED_VERSION: u64 = 1;

/// The `0x6` system `Clock` object id (32-byte, big-endian).
#[cfg(feature = "rpc")]
const CLOCK_OBJECT_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[31] = 0x06;
    id
};

/// Frozen §9.2 Move-call arguments for `csv_seal::mint_sanad`.
///
/// Every field is already bound and validated by the runtime adapter; this struct
/// is a faithful 1:1 image of the Move entry parameters (minus the shared
/// `Registry` / `Clock` / `TxContext`, which the submitter supplies). Keeping the
/// shaping in a plain struct makes the field mapping unit-testable without a live
/// signer or RPC — the Sui analogue of the Ethereum adapter's `build_mint_call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiMintArgs {
    /// Sanad identifier (`vector<u8>`, 32 bytes). Primary duplicate-mint key.
    pub sanad_id: [u8; 32],
    /// Commitment binding the sanad content/ownership (`vector<u8>`, 32 bytes).
    pub commitment: [u8; 32],
    /// Contract-layer source chain identity `keccak256("csv.chain.<src>")`
    /// (`vector<u8>`, 32 bytes).
    pub source_chain: [u8; 32],
    /// Recipient Sui address bytes (`address`, 32 bytes). The Move contract binds
    /// `keccak256(address::to_bytes(destination_owner))` into the digest, so these
    /// bytes MUST equal the `destination_owner` bytes used to compute the signed
    /// §9.2 digest.
    pub destination_owner: [u8; 32],
    /// Source lock-event id (`vector<u8>`, 32 bytes). Duplicate-source-lock key.
    pub lock_event_id: [u8; 32],
    /// Replay nullifier (`vector<u8>`, 32 bytes).
    pub nullifier: [u8; 32],
    /// Attestation expiry, unix seconds (`u64`); 0 = no expiry.
    pub attestation_expiry: u64,
    /// M-of-N secp256k1 verifier signatures over the §9.2 digest
    /// (`vector<vector<u8>>`, each 65 bytes `r || s || v`).
    pub verifier_signatures: Vec<Vec<u8>>,
}

/// Parse the RFC-0012 §9.2 `destination_owner` bytes into a concrete 32-byte Sui
/// address.
///
/// The Move `mint_sanad` takes `destination_owner: address` and hashes its 32
/// canonical bytes into the digest, so the recipient must be a fully specified
/// 32-byte, non-zero address. Fails closed on any other width (an empty owner —
/// the runtime's un-bound default — cannot mint) or the zero address.
pub fn parse_destination_owner(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!(
            "destination owner must be a 32-byte Sui address, got {} bytes",
            bytes.len()
        ));
    }
    if bytes.iter().all(|b| *b == 0) {
        return Err("destination owner must not be the zero address".to_string());
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(bytes);
    Ok(owner)
}

/// Shape the §9.2 attestation inputs and the attached verifier signatures into
/// the Move call arguments for `csv_seal::mint_sanad`.
///
/// Pure and infallible: `destination_owner` is supplied pre-validated (see
/// [`parse_destination_owner`]) and every other field is copied straight from the
/// attestation the digest was computed over, guaranteeing the on-chain call and
/// the signed digest agree byte-for-byte.
pub fn build_sui_mint_args(
    attestation: &MintAttestationInputs,
    destination_owner: [u8; 32],
    verifier_signatures: &[Vec<u8>],
) -> SuiMintArgs {
    SuiMintArgs {
        sanad_id: attestation.sanad_id,
        commitment: attestation.commitment,
        source_chain: attestation.source_chain,
        destination_owner,
        lock_event_id: attestation.lock_event_id,
        nullifier: attestation.nullifier,
        attestation_expiry: attestation.attestation_expiry,
        verifier_signatures: verifier_signatures.to_vec(),
    }
}

/// Parse a Sui object ID string (hex) into 32 bytes.
#[cfg(feature = "rpc")]
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

#[cfg(feature = "rpc")]
use crate::rpc_utils::tx_digest_to_runtime_hex;

/// Fetch a shared object's `initial_shared_version`, required to reference it as
/// an input in a programmable transaction.
#[cfg(feature = "rpc")]
async fn fetch_initial_shared_version(
    node: &Arc<SuiNode>,
    object_id: &sui_sdk_types::Address,
) -> SuiResult<u64> {
    use sui_rpc::proto::sui::rpc::v2::{GetObjectRequest, owner::OwnerKind};

    let client = node.client();
    let mut client_guard = client.lock().await;
    let mut request = GetObjectRequest::new(object_id);
    request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["owner".to_string()],
    });
    let response = (*client_guard)
        .ledger_client()
        .get_object(request)
        .await
        .map_err(|e| {
            SuiError::TransactionFailed(format!("Failed to fetch Registry object: {}", e))
        })?;

    let object = response
        .into_inner()
        .object
        .ok_or_else(|| SuiError::TransactionFailed("Registry object not found".to_string()))?;

    // For a shared object the owner carries `initial_shared_version` in `version`.
    let owner = object.owner.ok_or_else(|| {
        SuiError::TransactionFailed(
            "Registry owner was not returned by Sui RPC; cannot fetch initial_shared_version"
                .to_string(),
        )
    })?;
    if owner.kind != Some(OwnerKind::Shared as i32) {
        return Err(SuiError::TransactionFailed(format!(
            "Registry is not a shared object (owner kind {:?})",
            owner.kind
        )));
    }
    owner.version.ok_or_else(|| {
        SuiError::TransactionFailed(
            "Registry is shared but initial_shared_version was not returned".to_string(),
        )
    })
}

/// Submit a verifier-attested `csv_seal::mint_sanad` call and wait for its
/// effects, returning `(tx_digest_hex, checkpoint)`.
///
/// Builds the programmable transaction with the shared `Registry` (mutable) and
/// system `Clock` inputs plus the pure §9.2 arguments, signs it with the Ed25519
/// submitter key, executes it, and fails closed if the transaction reverted.
#[cfg(feature = "rpc")]
pub async fn submit_mint(
    node: &Arc<SuiNode>,
    package_id: &str,
    registry_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
    args: SuiMintArgs,
) -> SuiResult<(String, u64)> {
    use ed25519_dalek::Signer;
    use sui_sdk_types::{Address, Identifier};
    use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};

    let package_addr = Address::from_bytes(
        parse_object_id(package_id)
            .map_err(|e| SuiError::TransactionFailed(format!("Invalid package ID: {}", e)))?,
    )
    .map_err(|e| SuiError::TransactionFailed(format!("Invalid package ID: {}", e)))?;

    let registry_addr = Address::from_bytes(
        parse_object_id(registry_id)
            .map_err(|e| SuiError::TransactionFailed(format!("Invalid Registry ID: {}", e)))?,
    )
    .map_err(|e| SuiError::TransactionFailed(format!("Invalid Registry ID: {}", e)))?;

    let owner_addr = Address::from_bytes(args.destination_owner)
        .map_err(|e| SuiError::TransactionFailed(format!("Invalid destination owner: {}", e)))?;

    let clock_addr = Address::from_bytes(CLOCK_OBJECT_ID)
        .map_err(|e| SuiError::TransactionFailed(format!("Invalid Clock object id: {}", e)))?;

    // Derive the submitter address from the Ed25519 signing key.
    let public_key = signing_key.verifying_key();
    let pubkey_bytes = public_key.as_bytes();
    use blake2::Blake2b;
    use blake2::Digest as Blake2Digest;
    let mut hasher = Blake2b::new();
    hasher.update([0x00]); // Sui address prefix
    hasher.update(pubkey_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    let sender_address = Address::from_bytes(hash)
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to derive address: {}", e)))?;

    // The Registry's initial shared version is needed to reference it as input.
    let registry_initial_version = fetch_initial_shared_version(node, &registry_addr).await?;

    let gas_objects = crate::gas_utils::fetch_gas_objects(node, &sender_address)
        .await
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to fetch gas objects: {}", e)))?;
    if gas_objects.is_empty() {
        return Err(SuiError::TransactionFailed(
            "No gas objects found".to_string(),
        ));
    }

    let mut tx_builder = TransactionBuilder::new();
    tx_builder.set_sender(sender_address);
    tx_builder.set_gas_budget(100_000_000);
    tx_builder.set_gas_price(1000);
    tx_builder.add_gas_objects(gas_objects);

    let function = Function::new(
        package_addr,
        Identifier::new("csv_seal")
            .map_err(|e| SuiError::TransactionFailed(format!("Invalid module name: {}", e)))?,
        Identifier::new("mint_sanad")
            .map_err(|e| SuiError::TransactionFailed(format!("Invalid function name: {}", e)))?,
    );

    // Argument order MUST match the Move entry signature:
    // (registry, sanad_id, commitment, source_chain, destination_owner,
    //  lock_event_id, nullifier, attestation_expiry, verifier_signatures, clock)
    let registry_arg = tx_builder.object(ObjectInput::shared(
        registry_addr,
        registry_initial_version,
        true, // mutable: the mint records replay keys into the Registry tables
    ));
    let sanad_id_arg = tx_builder.pure(&args.sanad_id.to_vec());
    let commitment_arg = tx_builder.pure(&args.commitment.to_vec());
    let source_chain_arg = tx_builder.pure(&args.source_chain.to_vec());
    let destination_owner_arg = tx_builder.pure(&owner_addr);
    let lock_event_id_arg = tx_builder.pure(&args.lock_event_id.to_vec());
    let nullifier_arg = tx_builder.pure(&args.nullifier.to_vec());
    let attestation_expiry_arg = tx_builder.pure(&args.attestation_expiry);
    let verifier_signatures_arg = tx_builder.pure(&args.verifier_signatures);
    let clock_arg = tx_builder.object(ObjectInput::shared(
        clock_addr,
        CLOCK_INITIAL_SHARED_VERSION,
        false, // read-only: mint only reads the timestamp
    ));

    tx_builder.move_call(
        function,
        vec![
            registry_arg,
            sanad_id_arg,
            commitment_arg,
            source_chain_arg,
            destination_owner_arg,
            lock_event_id_arg,
            nullifier_arg,
            attestation_expiry_arg,
            verifier_signatures_arg,
            clock_arg,
        ],
    );

    let tx_data = tx_builder
        .try_build()
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to build transaction: {}", e)))?;

    // Sign the intent-scoped signing digest with Ed25519.
    let signing_digest = tx_data.signing_digest();
    let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();
    let tx_bytes = bcs::to_bytes(&tx_data).map_err(|e| {
        SuiError::TransactionFailed(format!("Failed to serialize transaction: {}", e))
    })?;

    // Execute via sui-rpc, mirroring the lock path's real execution.
    use sui_rpc::proto::sui::rpc::v2::{ExecuteTransactionRequest, Transaction, UserSignature};
    use sui_sdk_types::SimpleSignature;

    let client = node.client();
    let mut client_guard = client.lock().await;

    let mut sui_transaction = Transaction::default();
    sui_transaction.bcs = Some(tx_bytes.clone().into());

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|e| SuiError::TransactionFailed(format!("Invalid signature bytes: {:?}", e)))?;
    let simple_sig = SimpleSignature::Ed25519 {
        signature: sig_array.into(),
        public_key: (*pubkey_bytes).into(),
    };
    let sig_bcs = bcs::to_bytes(&simple_sig).map_err(|e| {
        SuiError::TransactionFailed(format!("Failed to serialize signature: {}", e))
    })?;
    let mut user_signature = UserSignature::default();
    user_signature.bcs = Some(sig_bcs.into());

    let mut execute_request = ExecuteTransactionRequest::default();
    execute_request.transaction = Some(sui_transaction);
    execute_request.signatures = vec![user_signature];
    execute_request.read_mask = Some(crate::rpc_utils::execution_read_mask());

    let execution_response = (*client_guard)
        .execution_client()
        .execute_transaction(execute_request)
        .await
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to execute mint: {}", e)))?;

    let executed_tx = execution_response
        .into_inner()
        .transaction
        .ok_or_else(|| SuiError::TransactionFailed("No transaction in response".to_string()))?;

    // Fail closed on a reverted mint.
    if let Some(ref effects) = executed_tx.effects {
        if let Some(ref status) = effects.status {
            if let Some(success) = status.success {
                if !success {
                    let error_msg = status
                        .error
                        .as_ref()
                        .map(|e| format!("mint reverted: {:?}", e))
                        .unwrap_or_else(|| "mint reverted (unknown error)".to_string());
                    return Err(SuiError::TransactionFailed(error_msg));
                }
            }
        }
    }

    let tx_digest_str = executed_tx.digest.ok_or_else(|| {
        SuiError::TransactionFailed("Mint response did not include transaction digest".to_string())
    })?;
    let tx_digest_hex =
        tx_digest_to_runtime_hex(&tx_digest_str).map_err(SuiError::TransactionFailed)?;
    let checkpoint = executed_tx.checkpoint.unwrap_or(0);

    Ok((tx_digest_hex, checkpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation(sanad: u8) -> MintAttestationInputs {
        MintAttestationInputs {
            destination_chain_id: [1u8; 32],
            destination_contract: [2u8; 32],
            sanad_id: [sanad; 32],
            commitment: [3u8; 32],
            source_chain: [4u8; 32],
            destination_owner: vec![0x11u8; 32],
            lock_event_id: [5u8; 32],
            nullifier: [6u8; 32],
            attestation_expiry: 42,
        }
    }

    #[test]
    fn parse_destination_owner_requires_32_nonzero_bytes() {
        assert!(parse_destination_owner(&[]).is_err());
        assert!(parse_destination_owner(&[0x11u8; 31]).is_err());
        assert!(parse_destination_owner(&[0x11u8; 33]).is_err());
        assert!(parse_destination_owner(&[0u8; 32]).is_err());
        assert_eq!(
            parse_destination_owner(&[0x11u8; 32]).unwrap(),
            [0x11u8; 32]
        );
    }

    #[test]
    fn build_sui_mint_args_maps_every_field_from_the_attestation() {
        let att = attestation(7);
        let owner = [0x11u8; 32];
        let sigs = vec![vec![9u8; 65]];
        let args = build_sui_mint_args(&att, owner, &sigs);

        assert_eq!(args.sanad_id, att.sanad_id);
        assert_eq!(args.commitment, att.commitment);
        assert_eq!(args.source_chain, att.source_chain);
        assert_eq!(args.destination_owner, owner);
        assert_eq!(args.lock_event_id, att.lock_event_id);
        assert_eq!(args.nullifier, att.nullifier);
        assert_eq!(args.attestation_expiry, att.attestation_expiry);
        assert_eq!(args.verifier_signatures, sigs);
    }

    #[test]
    fn build_sui_mint_args_carries_all_verifier_signatures() {
        let att = attestation(7);
        let sigs = vec![vec![1u8; 65], vec![2u8; 65], vec![3u8; 65]];
        let args = build_sui_mint_args(&att, [0x11u8; 32], &sigs);
        assert_eq!(args.verifier_signatures.len(), 3);
    }

    #[test]
    fn mint_args_owner_matches_digest_owner_bytes() {
        // The bytes used for the Move `address` arg must be identical to the
        // `destination_owner` bytes the §9.2 digest hashes, or the on-chain
        // ecrecover would fail. Assert the wiring keeps them equal.
        let att = attestation(7);
        let owner = parse_destination_owner(&att.destination_owner).unwrap();
        let args = build_sui_mint_args(&att, owner, &[]);
        assert_eq!(args.destination_owner.to_vec(), att.destination_owner);
    }
}
