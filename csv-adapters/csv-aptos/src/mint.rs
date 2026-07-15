//! Verifier-attested destination mint for CSV sanads on Aptos (RFC-0012 §9).
//!
//! Under the thin-registry model, materializing a Sanad on Aptos calls
//! `csv_seal::mint_sanad` on the deployed module, carrying the frozen §9.2
//! attestation fields and a set of secp256k1 verifier signatures over the
//! attestation digest. There is NO proof root, state root, Merkle proof, or leaf
//! index on this path, and NO `u8` contract-chain tag: cross-chain validity is
//! adjudicated off-chain by the canonical verifier, and the only on-chain
//! authenticity check is `secp256k1::ecdsa_recover` of the verifier signatures.
//!
//! This module owns the Move call-argument shaping ([`build_aptos_mint_args`],
//! pure and unit-testable). The runtime adapter (`AptosRuntimeAdapter::mint_sanad`)
//! is the sole caller: it binds `destinationContract = @csv_seal` module address,
//! forces `destinationChainId = keccak256("csv.chain.aptos")`, computes and signs
//! the §9.2 digest, then hands the finished [`AptosMintArgs`] to the backend for
//! submission (`AptosBackend::submit_attested_mint`).

use csv_chain_ports::MintAttestationInputs;

/// Frozen §9.2 Move-call arguments for `csv_seal::mint_sanad`.
///
/// Every field is already bound and validated by the runtime adapter; this struct
/// is a faithful 1:1 image of the Move entry parameters (minus the leading
/// `&signer`, which the submitter supplies). Keeping the shaping in a plain struct
/// makes the field mapping unit-testable without a live signer or RPC — the Aptos
/// analogue of the Sui adapter's `SuiMintArgs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosMintArgs {
    /// Sanad identifier (`vector<u8>`, 32 bytes). Primary duplicate-mint key.
    pub sanad_id: [u8; 32],
    /// Commitment binding the sanad content/ownership (`vector<u8>`, 32 bytes).
    pub commitment: [u8; 32],
    /// Contract-layer source chain identity `keccak256("csv.chain.<src>")`
    /// (`vector<u8>`, 32 bytes). Fixed-width — never a `u8` chain tag.
    pub source_chain: [u8; 32],
    /// Recipient identity bytes (`vector<u8>`). The Move contract hashes these with
    /// `keccak256` into the digest and emits the full bytes, so these bytes MUST
    /// equal the `destination_owner` bytes used to compute the signed §9.2 digest.
    pub destination_owner: Vec<u8>,
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

/// Validate the RFC-0012 §9.2 `destination_owner` bytes for an Aptos mint.
///
/// The Move `mint_sanad` takes `destination_owner: vector<u8>`, emits the full
/// bytes, and hashes them (`keccak256`) into the digest, requiring only a
/// non-empty vector. This fails closed on the runtime's un-bound default (an empty
/// owner) and on an all-zero owner, returning the exact bytes that must both be
/// passed to the Move call and hashed into the signed digest.
pub fn parse_destination_owner(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        return Err("destination owner must not be empty (mint recipient is unbound)".to_string());
    }
    if bytes.iter().all(|b| *b == 0) {
        return Err("destination owner must not be all-zero".to_string());
    }
    Ok(bytes.to_vec())
}

/// Shape the §9.2 attestation inputs and the attached verifier signatures into
/// the Move call arguments for `csv_seal::mint_sanad`.
///
/// Pure and infallible: `destination_owner` is supplied pre-validated (see
/// [`parse_destination_owner`]) and every other field is copied straight from the
/// attestation the digest was computed over, guaranteeing the on-chain call and
/// the signed digest agree byte-for-byte.
pub fn build_aptos_mint_args(
    attestation: &MintAttestationInputs,
    destination_owner: Vec<u8>,
    verifier_signatures: &[Vec<u8>],
) -> AptosMintArgs {
    AptosMintArgs {
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
    fn parse_destination_owner_requires_nonempty_nonzero() {
        assert!(parse_destination_owner(&[]).is_err());
        assert!(parse_destination_owner(&[0u8; 32]).is_err());
        assert_eq!(
            parse_destination_owner(&[0x11u8; 32]).unwrap(),
            vec![0x11u8; 32]
        );
        // Aptos accepts a variable-width owner (only its hash enters the digest).
        assert_eq!(
            parse_destination_owner(&[0xAB, 0xCD]).unwrap(),
            vec![0xAB, 0xCD]
        );
    }

    #[test]
    fn build_aptos_mint_args_maps_every_field_from_the_attestation() {
        let att = attestation(7);
        let owner = vec![0x11u8; 32];
        let sigs = vec![vec![9u8; 65]];
        let args = build_aptos_mint_args(&att, owner.clone(), &sigs);

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
    fn build_aptos_mint_args_carries_all_verifier_signatures() {
        let att = attestation(7);
        let sigs = vec![vec![1u8; 65], vec![2u8; 65], vec![3u8; 65]];
        let args = build_aptos_mint_args(&att, vec![0x11u8; 32], &sigs);
        assert_eq!(args.verifier_signatures.len(), 3);
    }

    #[test]
    fn mint_args_owner_matches_digest_owner_bytes() {
        // The bytes used for the Move `destination_owner` arg must be identical to
        // the `destination_owner` bytes the §9.2 digest hashes, or the on-chain
        // recover would fail. Assert the wiring keeps them equal.
        let att = attestation(7);
        let owner = parse_destination_owner(&att.destination_owner).unwrap();
        let args = build_aptos_mint_args(&att, owner, &[]);
        assert_eq!(args.destination_owner, att.destination_owner);
    }
}
