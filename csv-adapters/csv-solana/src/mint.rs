//! Verifier-attested destination mint for CSV sanads on Solana (RFC-0012 §9).
//!
//! Under the thin-registry model, materializing a Sanad on Solana calls the
//! redesigned `csv_seal::mint_sanad` Anchor instruction, carrying the frozen §9.2
//! attestation fields and a set of secp256k1 verifier signatures over the
//! attestation digest. There is NO proof root, state root, Merkle proof, or leaf
//! index on this path: cross-chain validity is adjudicated off-chain by the
//! canonical verifier, and the only on-chain authenticity check is
//! `secp256k1_recover` of the verifier signatures against the on-chain verifier
//! set. Solana's native single-use guarantee is the weakest of the supported
//! chains, so the three replay-tombstone PDAs (`minted` / `nullifier` /
//! `lock_event`) created by this instruction are load-bearing.
//!
//! This module owns the instruction shaping ([`build_solana_mint_args`] and
//! [`build_mint_instruction`], both pure and unit-testable). The runtime adapter
//! (`SolanaRuntimeAdapter::mint_sanad`) is the sole caller: it binds
//! `destinationContract = program id` and `destinationChainId =
//! keccak256("csv.chain.solana")`, computes and signs the digest, then hands the
//! finished [`SolanaMintArgs`] here before submitting the transaction.

use crate::anchor_client::{discriminators, pdas};
use csv_adapter_core::MintAttestationInputs;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// Frozen §9.2 arguments for the `csv_seal::mint_sanad` Anchor instruction.
///
/// Every field is already bound and validated by the runtime adapter; this struct
/// is a faithful image of the Anchor entry parameters (minus the accounts, which
/// [`build_mint_instruction`] derives). Keeping the shaping in a plain struct makes
/// the mapping unit-testable without a live signer or RPC — the Solana analogue of
/// the Ethereum adapter's `build_mint_call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaMintArgs {
    /// Sanad identifier (32 bytes). Primary duplicate-mint key.
    pub sanad_id: [u8; 32],
    /// Commitment binding the sanad content/ownership (32 bytes).
    pub commitment: [u8; 32],
    /// Contract-layer source chain identity `keccak256("csv.chain.<src>")` (32 bytes).
    pub source_chain: [u8; 32],
    /// Recipient identity bytes. The Anchor instruction hashes
    /// `keccak256(destination_owner)` into the digest, so these bytes MUST equal the
    /// `destination_owner` bytes used to compute the signed §9.2 digest.
    pub destination_owner: Vec<u8>,
    /// Source lock-event id (32 bytes). Duplicate-source-lock key.
    pub lock_event_id: [u8; 32],
    /// Replay nullifier (32 bytes).
    pub nullifier: [u8; 32],
    /// Attestation expiry, unix seconds; 0 = no expiry.
    pub attestation_expiry: u64,
    /// M-of-N secp256k1 verifier signatures over the §9.2 digest (each 65 bytes
    /// `r || s || v`).
    pub verifier_signatures: Vec<Vec<u8>>,
}

/// Shape the §9.2 attestation inputs and the attached verifier signatures into the
/// arguments for the `csv_seal::mint_sanad` instruction.
///
/// Pure and infallible: every field is copied straight from the attestation the
/// digest was computed over, guaranteeing the on-chain call and the signed digest
/// agree byte-for-byte. `destination_owner` is carried through unchanged so the
/// keccak the program recomputes matches the one the digest bound.
pub fn build_solana_mint_args(
    attestation: &MintAttestationInputs,
    verifier_signatures: &[Vec<u8>],
) -> SolanaMintArgs {
    SolanaMintArgs {
        sanad_id: attestation.sanad_id,
        commitment: attestation.commitment,
        source_chain: attestation.source_chain,
        destination_owner: attestation.destination_owner.clone(),
        lock_event_id: attestation.lock_event_id,
        nullifier: attestation.nullifier,
        attestation_expiry: attestation.attestation_expiry,
        verifier_signatures: verifier_signatures.to_vec(),
    }
}

/// Borsh-encode the `mint_sanad` instruction data (discriminator + args).
///
/// Field order and widths mirror the Anchor entry signature exactly:
/// `sanad_id([u8;32]) || commitment([u8;32]) || source_chain([u8;32]) ||
/// destination_owner(Vec<u8>) || lock_event_id([u8;32]) || nullifier([u8;32]) ||
/// attestation_expiry(u64 LE) || verifier_signatures(Vec<Vec<u8>>)`. Anchor
/// deserializes with Borsh, so vectors are length-prefixed with a little-endian
/// `u32` and integers are little-endian.
fn encode_mint_data(args: &SolanaMintArgs) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&discriminators::mint_sanad());
    data.extend_from_slice(&args.sanad_id);
    data.extend_from_slice(&args.commitment);
    data.extend_from_slice(&args.source_chain);
    // destination_owner: Vec<u8>
    data.extend_from_slice(&(args.destination_owner.len() as u32).to_le_bytes());
    data.extend_from_slice(&args.destination_owner);
    data.extend_from_slice(&args.lock_event_id);
    data.extend_from_slice(&args.nullifier);
    data.extend_from_slice(&args.attestation_expiry.to_le_bytes());
    // verifier_signatures: Vec<Vec<u8>>
    data.extend_from_slice(&(args.verifier_signatures.len() as u32).to_le_bytes());
    for sig in &args.verifier_signatures {
        data.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        data.extend_from_slice(sig);
    }
    data
}

/// Build the verifier-attested `mint_sanad` instruction for the redesigned
/// thin-registry program.
///
/// The account list matches the `MintSanad` context field order exactly:
/// `verifier_registry` (read-only; the mint only reads the verifier set),
/// the three replay-tombstone PDAs `mint_record` / `nullifier_record` /
/// `lock_event_record` (writable, `init`-ed on-chain from the verifier signatures),
/// `payer` (writable signer that funds rent and gas but holds NO mint authority),
/// and the System program. The tombstone PDAs are keyed by `sanad_id`, `nullifier`,
/// and `lock_event_id` respectively; their `init` is the on-chain uniqueness guard.
pub fn build_mint_instruction(
    program_id: &Pubkey,
    payer: &Pubkey,
    args: &SolanaMintArgs,
) -> Instruction {
    let (verifier_registry, _) = pdas::verifier_registry(program_id);
    let (mint_record, _) = pdas::mint_record(program_id, &args.sanad_id);
    let (nullifier_record, _) = pdas::nullifier_record(program_id, &args.nullifier);
    let (lock_event_record, _) = pdas::lock_event_record(program_id, &args.lock_event_id);

    // The System program id is the all-ones base58 / all-zero-bytes pubkey.
    let system_program = Pubkey::from([0u8; 32]);

    Instruction::new_with_bytes(
        *program_id,
        &encode_mint_data(args),
        vec![
            AccountMeta::new_readonly(verifier_registry, false),
            AccountMeta::new(mint_record, false),
            AccountMeta::new(nullifier_record, false),
            AccountMeta::new(lock_event_record, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(system_program, false),
        ],
    )
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
    fn build_solana_mint_args_maps_every_field_from_the_attestation() {
        let att = attestation(7);
        let sigs = vec![vec![9u8; 65]];
        let args = build_solana_mint_args(&att, &sigs);

        assert_eq!(args.sanad_id, att.sanad_id);
        assert_eq!(args.commitment, att.commitment);
        assert_eq!(args.source_chain, att.source_chain);
        assert_eq!(args.destination_owner, att.destination_owner);
        assert_eq!(args.lock_event_id, att.lock_event_id);
        assert_eq!(args.nullifier, att.nullifier);
        assert_eq!(args.attestation_expiry, att.attestation_expiry);
        assert_eq!(args.verifier_signatures, sigs);
    }

    #[test]
    fn build_solana_mint_args_carries_all_verifier_signatures() {
        let att = attestation(7);
        let sigs = vec![vec![1u8; 65], vec![2u8; 65], vec![3u8; 65]];
        let args = build_solana_mint_args(&att, &sigs);
        assert_eq!(args.verifier_signatures.len(), 3);
    }

    #[test]
    fn encode_mint_data_matches_anchor_borsh_layout() {
        let att = attestation(7);
        let sigs = vec![vec![9u8; 65], vec![8u8; 65]];
        let args = build_solana_mint_args(&att, &sigs);
        let data = encode_mint_data(&args);

        // discriminator(8) + sanad_id(32) + commitment(32) + source_chain(32)
        // + owner_len(4) + owner(32) + lock_event_id(32) + nullifier(32)
        // + expiry(8) + sigs_count(4) + 2 * (len(4) + 65)
        let expected = 8 + 32 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 4 + 2 * (4 + 65);
        assert_eq!(data.len(), expected);

        // discriminator is sha256("global:mint_sanad")[..8]
        assert_eq!(&data[..8], &discriminators::mint_sanad());

        // Borsh Vec<u8> length prefix for destination_owner is a LE u32 == 32.
        let owner_len_off = 8 + 32 + 32 + 32;
        assert_eq!(
            u32::from_le_bytes(data[owner_len_off..owner_len_off + 4].try_into().unwrap()),
            32
        );

        // The signatures vector length prefix is a LE u32 == 2.
        let sigs_count_off = owner_len_off + 4 + 32 + 32 + 32 + 8;
        assert_eq!(
            u32::from_le_bytes(data[sigs_count_off..sigs_count_off + 4].try_into().unwrap()),
            2
        );
    }

    #[test]
    fn build_mint_instruction_has_thin_registry_account_layout() {
        let program_id = Pubkey::new_unique();
        let payer = Pubkey::new_unique();
        let args = build_solana_mint_args(&attestation(7), &[vec![9u8; 65]]);
        let ix = build_mint_instruction(&program_id, &payer, &args);

        assert_eq!(ix.program_id, program_id);
        // verifier_registry, mint_record, nullifier_record, lock_event_record,
        // payer, system_program.
        assert_eq!(ix.accounts.len(), 6);

        // verifier_registry is read-only, never a signer.
        assert!(!ix.accounts[0].is_writable);
        assert!(!ix.accounts[0].is_signer);
        // the three tombstone PDAs are writable (init) but not signers.
        for meta in &ix.accounts[1..4] {
            assert!(meta.is_writable);
            assert!(!meta.is_signer);
        }
        // payer is the sole signer and writable (pays rent/gas).
        assert_eq!(ix.accounts[4].pubkey, payer);
        assert!(ix.accounts[4].is_writable);
        assert!(ix.accounts[4].is_signer);
        // system program is read-only.
        assert!(!ix.accounts[5].is_writable);
        assert!(!ix.accounts[5].is_signer);

        // The tombstone PDAs are the ones keyed off the request's replay fields.
        assert_eq!(
            ix.accounts[1].pubkey,
            pdas::mint_record(&program_id, &args.sanad_id).0
        );
        assert_eq!(
            ix.accounts[2].pubkey,
            pdas::nullifier_record(&program_id, &args.nullifier).0
        );
        assert_eq!(
            ix.accounts[3].pubkey,
            pdas::lock_event_record(&program_id, &args.lock_event_id).0
        );
    }
}
