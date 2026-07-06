//! Unit tests for the RFC-0012 thin-registry mint authentication primitives.
//!
//! These exercise the security-critical pure functions off-chain: the frozen §9.2 /
//! §10 digest byte layouts, secp256k1 signature recovery/compression, low-s
//! malleability rejection, and the M-of-N distinct-verifier threshold — including
//! the adversarial cases (forged attestation, duplicate signatures, high-s).

use crate::constants::*;
use crate::state::VerifierRegistry;
use crate::{
    is_high_s, mint_attestation_digest, recover_compressed_verifier, require_verifier_threshold,
    settlement_receipt_digest, solana_chain_id,
};
use anchor_lang::prelude::Pubkey;
use libsecp256k1::{sign, Message, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

// ---- helpers ----

fn secret(byte: u8) -> SecretKey {
    SecretKey::parse(&[byte; 32]).expect("valid secret key")
}

fn compressed_pubkey(sk: &SecretKey) -> [u8; 33] {
    PublicKey::from_secret_key(sk).serialize_compressed()
}

/// Produce a 65-byte `r || s || v` signature (low-s, `v` in {0,1}) over `digest`.
fn sign65(sk: &SecretKey, digest: &[u8; 32]) -> Vec<u8> {
    let msg = Message::parse(digest);
    let (sig, recid) = sign(&msg, sk);
    let mut out = sig.serialize().to_vec(); // 64 bytes, low-s normalized by libsecp256k1
    out.push(recid.serialize()); // 0 or 1
    out
}

fn registry(threshold: u8, verifiers: Vec<[u8; 33]>) -> VerifierRegistry {
    VerifierRegistry {
        authority: Pubkey::default(),
        threshold,
        verifiers,
        bump: 0,
    }
}

fn sample_mint_digest() -> [u8; 32] {
    mint_attestation_digest(
        &[1u8; 32],
        &[2u8; 32],
        &[3u8; 32],
        &[4u8; 32],
        &[5u8; 32],
        &[6u8; 32],
        0,
    )
}

// ---- digest layout ----

#[test]
fn mint_digest_matches_independent_sha256_over_287_byte_preimage() {
    let sanad_id = [11u8; 32];
    let commitment = [22u8; 32];
    let source_chain = [33u8; 32];
    let dest_owner_hash = [44u8; 32];
    let lock_event_id = [55u8; 32];
    let nullifier = [66u8; 32];
    let expiry: u64 = 0x0102_0304_0506_0708;

    // Reconstruct the frozen preimage independently.
    let mut pre = Vec::new();
    pre.extend_from_slice(MINT_ATTESTATION_DOMAIN);
    pre.extend_from_slice(&solana_chain_id());
    pre.extend_from_slice(&crate::ID.to_bytes());
    pre.extend_from_slice(&sanad_id);
    pre.extend_from_slice(&commitment);
    pre.extend_from_slice(&source_chain);
    pre.extend_from_slice(&dest_owner_hash);
    pre.extend_from_slice(&lock_event_id);
    pre.extend_from_slice(&nullifier);
    pre.extend_from_slice(&expiry.to_be_bytes());

    assert_eq!(pre.len(), 287, "frozen §9.2 preimage must be 287 bytes");

    let expected: [u8; 32] = Sha256::digest(&pre).into();
    let got = mint_attestation_digest(
        &sanad_id,
        &commitment,
        &source_chain,
        &dest_owner_hash,
        &lock_event_id,
        &nullifier,
        expiry,
    );
    assert_eq!(got, expected);
}

#[test]
fn settlement_digest_matches_independent_sha256_over_257_byte_preimage() {
    let sanad_id = [7u8; 32];
    let lock_event_id = [8u8; 32];
    let dest_chain = [9u8; 32];
    let dest_mint_tx_ref = [10u8; 32];
    let operator = [12u8; 32];
    let expiry: u64 = 42;

    let mut pre = Vec::new();
    pre.extend_from_slice(SETTLEMENT_RECEIPT_DOMAIN);
    pre.extend_from_slice(&solana_chain_id());
    pre.extend_from_slice(&crate::ID.to_bytes());
    pre.extend_from_slice(&sanad_id);
    pre.extend_from_slice(&lock_event_id);
    pre.extend_from_slice(&dest_chain);
    pre.extend_from_slice(&dest_mint_tx_ref);
    pre.extend_from_slice(&operator);
    pre.extend_from_slice(&expiry.to_be_bytes());

    assert_eq!(pre.len(), 257, "frozen §10 preimage must be 257 bytes");

    let expected: [u8; 32] = Sha256::digest(&pre).into();
    let got = settlement_receipt_digest(
        &sanad_id,
        &lock_event_id,
        &dest_chain,
        &dest_mint_tx_ref,
        &operator,
        expiry,
    );
    assert_eq!(got, expected);
}

#[test]
fn mint_digest_is_field_sensitive() {
    let base = sample_mint_digest();
    // Flipping any single field must change the digest (no field silently dropped).
    assert_ne!(
        base,
        mint_attestation_digest(&[9u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32], 0)
    );
    assert_ne!(
        base,
        mint_attestation_digest(&[1u8; 32], &[9u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32], 0)
    );
    assert_ne!(
        base,
        mint_attestation_digest(&[1u8; 32], &[2u8; 32], &[9u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32], 0)
    );
    assert_ne!(
        base,
        mint_attestation_digest(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[9u8; 32], &[5u8; 32], &[6u8; 32], 0)
    );
    assert_ne!(
        base,
        mint_attestation_digest(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[9u8; 32], &[6u8; 32], 0)
    );
    assert_ne!(
        base,
        mint_attestation_digest(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[9u8; 32], 0)
    );
    assert_ne!(
        base,
        mint_attestation_digest(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32], 1)
    );
}

// ---- signature recovery ----

#[test]
fn recover_yields_the_signing_verifier_compressed_key() {
    let sk = secret(0x11);
    let digest = sample_mint_digest();
    let sig = sign65(&sk, &digest);
    let recovered = recover_compressed_verifier(&digest, &sig).expect("recovers");
    assert_eq!(recovered, compressed_pubkey(&sk));
}

#[test]
fn recover_accepts_eip155_style_v_27_28() {
    let sk = secret(0x22);
    let digest = sample_mint_digest();
    let mut sig = sign65(&sk, &digest);
    // Rewrite v from {0,1} to the EVM {27,28} form; recovery must still succeed.
    sig[64] += 27;
    let recovered = recover_compressed_verifier(&digest, &sig).expect("recovers with v+27");
    assert_eq!(recovered, compressed_pubkey(&sk));
}

#[test]
fn recover_rejects_wrong_length_signature() {
    let digest = sample_mint_digest();
    assert!(recover_compressed_verifier(&digest, &[0u8; 64]).is_err());
    assert!(recover_compressed_verifier(&digest, &[0u8; 66]).is_err());
}

#[test]
fn recover_rejects_high_s_malleable_signature() {
    let sk = secret(0x33);
    let digest = sample_mint_digest();
    let mut sig = sign65(&sk, &digest);
    // Force s to n - s (the high-s counterpart). n (big-endian):
    let n: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..64]);
    let high = sub_be(&n, &s);
    sig[32..64].copy_from_slice(&high);
    assert!(is_high_s(&high));
    assert!(recover_compressed_verifier(&digest, &sig).is_err());
}

/// 256-bit big-endian subtraction (a - b), assuming a >= b. Test helper only.
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let mut diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = diff as u8;
    }
    out
}

#[test]
fn is_high_s_boundary() {
    // n/2 exactly is permitted (not high).
    assert!(!is_high_s(&SECP256K1_HALF_ORDER_BE));
    // n/2 + 1 is high.
    let mut over = SECP256K1_HALF_ORDER_BE;
    over[31] += 1;
    assert!(is_high_s(&over));
    // A small value is not high.
    assert!(!is_high_s(&[0u8; 32]));
}

// ---- M-of-N threshold ----

#[test]
fn happy_single_signature_meets_threshold() {
    let sk = secret(0x44);
    let reg = registry(1, vec![compressed_pubkey(&sk)]);
    let digest = sample_mint_digest();
    let sigs = vec![sign65(&sk, &digest)];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_ok());
}

#[test]
fn forged_signature_from_unknown_key_is_rejected() {
    let authorized = secret(0x55);
    let attacker = secret(0x56);
    let reg = registry(1, vec![compressed_pubkey(&authorized)]);
    let digest = sample_mint_digest();
    // Valid signature, but by a key not in the verifier set.
    let sigs = vec![sign65(&attacker, &digest)];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_err());
}

#[test]
fn signature_over_a_different_digest_is_rejected() {
    let sk = secret(0x57);
    let reg = registry(1, vec![compressed_pubkey(&sk)]);
    let digest = sample_mint_digest();
    // Sign a DIFFERENT digest; recovery yields a different key than the signer's, so
    // membership fails — a signature cannot be replayed onto another attestation.
    let other = mint_attestation_digest(&[99u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32], &[6u8; 32], 0);
    let sigs = vec![sign65(&sk, &other)];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_err());
}

#[test]
fn duplicate_signatures_do_not_satisfy_two_of_n() {
    let a = secret(0x61);
    let b = secret(0x62);
    let reg = registry(2, vec![compressed_pubkey(&a), compressed_pubkey(&b)]);
    let digest = sample_mint_digest();
    // Same verifier's signature twice: distinct count is 1 < threshold 2.
    let sig = sign65(&a, &digest);
    let sigs = vec![sig.clone(), sig];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_err());
}

#[test]
fn two_distinct_signatures_satisfy_two_of_n() {
    let a = secret(0x71);
    let b = secret(0x72);
    let reg = registry(2, vec![compressed_pubkey(&a), compressed_pubkey(&b)]);
    let digest = sample_mint_digest();
    let sigs = vec![sign65(&a, &digest), sign65(&b, &digest)];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_ok());
}

#[test]
fn too_few_signatures_is_rejected() {
    let a = secret(0x81);
    let b = secret(0x82);
    let reg = registry(2, vec![compressed_pubkey(&a), compressed_pubkey(&b)]);
    let digest = sample_mint_digest();
    // Only one signature for a 2-of-N set.
    let sigs = vec![sign65(&a, &digest)];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_err());
}

#[test]
fn one_valid_plus_one_forged_does_not_reach_two_of_n() {
    let a = secret(0x91);
    let b = secret(0x92);
    let attacker = secret(0x93);
    let reg = registry(2, vec![compressed_pubkey(&a), compressed_pubkey(&b)]);
    let digest = sample_mint_digest();
    // A forged signature causes an immediate rejection (unknown signer).
    let sigs = vec![sign65(&a, &digest), sign65(&attacker, &digest)];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_err());
}

#[test]
fn empty_signature_set_is_rejected() {
    let a = secret(0xA1);
    let reg = registry(1, vec![compressed_pubkey(&a)]);
    let digest = sample_mint_digest();
    let sigs: Vec<Vec<u8>> = vec![];
    assert!(require_verifier_threshold(&reg, &digest, &sigs).is_err());
}
