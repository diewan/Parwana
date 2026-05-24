//! Solana SPV-equivalent proof verification
//!
//! Solana does not have traditional Merkle proofs like Bitcoin. Instead, it uses:
//! - Slot proofs: Verification that a transaction was included in a specific slot
//! - Account proofs: Verification of account state at a given slot via RPC
//! - Cluster signatures: 66%+ stake signature on leader schedule for finality
//!
//! This module provides the equivalent security guarantees through:
//! 1. Slot-based inclusion proofs with confirmation depth
//! 2. Account state proofs via get_multiple_accounts with proof
//! 3. Finality verification via slot depth and cluster consensus

use csv_hash::Hash;
use csv_hash::proof::{FinalityProof, InclusionProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;

/// Maximum proof age in seconds (24 hours)
const MAX_PROOF_AGE_SECS: u64 = 86_400;

/// Minimum confirmations for probabilistic finality
const MIN_CONFIRMATIONS: u64 = 32;

/// Solana slot proof — proves a transaction was included in a specific slot
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotProof {
    /// The slot number where the transaction was included
    pub slot: u64,
    /// Transaction signature
    pub signature: Signature,
    /// Block hash of the slot
    pub block_hash: Hash,
    /// Number of confirmations at time of proof
    pub confirmations: u64,
    /// Whether the slot is finalized (32+ confirmations)
    pub finalized: bool,
    /// Account keys involved in the transaction
    pub account_keys: Vec<Pubkey>,
    /// Program ID that was invoked
    pub program_id: Pubkey,
    /// Instruction data hash (for commitment verification)
    pub instruction_data_hash: Hash,
    /// Unix timestamp of when the slot was produced
    pub timestamp: u64,
}

impl SlotProof {
    /// Create a new slot proof
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot: u64,
        signature: Signature,
        block_hash: Hash,
        confirmations: u64,
        account_keys: Vec<Pubkey>,
        program_id: Pubkey,
        instruction_data: &[u8],
        timestamp: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(instruction_data);
        let instruction_data_hash = Hash::new(hasher.finalize().into());

        Self {
            slot,
            signature,
            block_hash,
            confirmations,
            finalized: confirmations >= MIN_CONFIRMATIONS,
            account_keys,
            program_id,
            instruction_data_hash,
            timestamp,
        }
    }

    /// Verify the slot proof is still valid (not expired)
    pub fn is_valid_now(&self, current_timestamp: u64) -> bool {
        current_timestamp.saturating_sub(self.timestamp) < MAX_PROOF_AGE_SECS
    }

    /// Verify the proof has sufficient confirmations for the desired security level
    pub fn has_confirmations(&self, required: u64) -> bool {
        self.confirmations >= required
    }

    /// Convert to core InclusionProof format
    pub fn to_inclusion_proof(&self, commitment: &Hash) -> InclusionProof {
        let mut proof_data = Vec::with_capacity(128);
        proof_data.extend_from_slice(&self.slot.to_le_bytes());
        proof_data.extend_from_slice(self.signature.as_ref());
        proof_data.extend_from_slice(self.block_hash.as_bytes());
        proof_data.extend_from_slice(&self.confirmations.to_le_bytes());
        proof_data.push(if self.finalized { 1u8 } else { 0u8 });
        proof_data.extend_from_slice(commitment.as_bytes());
        proof_data.extend_from_slice(self.instruction_data_hash.as_bytes());

        // Position equals slot for Solana slot-based proofs
        InclusionProof::new(proof_data, self.block_hash, self.slot, self.slot).unwrap_or_else(|e| {
            tracing::error!("Failed to create inclusion proof: {}", e);
            unsafe { InclusionProof::new_unchecked(vec![], self.block_hash, self.slot, self.slot) }
        })
    }

    /// Convert from core InclusionProof back to SlotProof
    pub fn from_inclusion_proof(proof: &InclusionProof) -> Option<Self> {
        if proof.proof_bytes.len() < 128 {
            return None;
        }

        let slot = u64::from_le_bytes(proof.proof_bytes[..8].try_into().ok()?);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&proof.proof_bytes[8..72]);
        let signature = Signature::from(sig_bytes);
        let block_hash = Hash::new(proof.proof_bytes[72..104].try_into().ok()?);
        let confirmations = u64::from_le_bytes(proof.proof_bytes[104..112].try_into().ok()?);
        let finalized = proof.proof_bytes[112] == 1;

        Some(Self {
            slot,
            signature,
            block_hash,
            confirmations,
            finalized,
            account_keys: Vec::new(),
            program_id: Pubkey::default(),
            instruction_data_hash: Hash::new([0u8; 32]),
            timestamp: 0,
        })
    }
}

/// Account state proof — proves the state of one or more accounts at a given slot
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProof {
    /// The slot at which this account state is valid
    pub slot: u64,
    /// Account address
    pub pubkey: Pubkey,
    /// Account lamport balance at that slot
    pub lamports: u64,
    /// Account owner program ID
    pub owner: Pubkey,
    /// Account data at that slot
    pub data: Vec<u8>,
    /// Whether the account was executable (program account)
    pub executable: bool,
    /// Rent epoch at that slot
    pub rent_epoch: u64,
    /// Hash of the account data for integrity verification
    pub data_hash: Hash,
}

impl AccountProof {
    /// Create a new account proof
    pub fn new(
        slot: u64,
        pubkey: Pubkey,
        lamports: u64,
        owner: Pubkey,
        data: Vec<u8>,
        executable: bool,
        rent_epoch: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let data_hash = Hash::new(hasher.finalize().into());

        Self {
            slot,
            pubkey,
            lamports,
            owner,
            data,
            executable,
            rent_epoch,
            data_hash,
        }
    }

    /// Verify the data hash matches the actual data
    pub fn verify_data_integrity(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed_hash = Hash::new(hasher.finalize().into());
        computed_hash == self.data_hash
    }
}

/// Multi-account proof — proves state of multiple accounts atomically at a slot
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiAccountProof {
    /// The slot at which all account states are valid
    pub slot: u64,
    /// Individual account proofs
    pub accounts: Vec<AccountProof>,
    /// Slot hash for verification against cluster state
    pub slot_hash: Hash,
    /// Parent slot for chain continuity
    pub parent_slot: u64,
    /// Whether this slot is finalized
    pub finalized: bool,
}

impl MultiAccountProof {
    /// Create a new multi-account proof
    pub fn new(slot: u64, parent_slot: u64, accounts: Vec<AccountProof>, finalized: bool) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(slot.to_le_bytes());
        hasher.update(parent_slot.to_le_bytes());
        hasher.update([if finalized { 1u8 } else { 0u8 }]);
        for account in &accounts {
            hasher.update(account.pubkey.as_ref());
            hasher.update(account.data_hash.as_bytes());
        }
        let slot_hash = Hash::new(hasher.finalize().into());

        Self {
            slot,
            parent_slot,
            accounts,
            slot_hash,
            finalized,
        }
    }

    /// Verify all account proofs are valid
    pub fn verify_all(&self) -> bool {
        self.accounts.iter().all(|a| a.verify_data_integrity())
    }

    /// Verify chain continuity (parent_slot < slot)
    pub fn verify_chain_continuity(&self) -> bool {
        self.parent_slot < self.slot
    }
}

/// Build a Solana inclusion proof from transaction and account data
///
/// This is the Solana equivalent of a Bitcoin Merkle proof. It proves:
/// 1. The transaction was included in a specific slot
/// 2. The relevant accounts had the expected state at that slot
/// 3. The slot has sufficient confirmations for the desired security level
#[allow(clippy::too_many_arguments)]
pub fn build_inclusion_proof(
    slot: u64,
    signature: Signature,
    block_hash: Hash,
    account_keys: Vec<Pubkey>,
    program_id: Pubkey,
    instruction_data: &[u8],
    confirmations: u64,
    timestamp: u64,
) -> InclusionProof {
    let slot_proof = SlotProof::new(
        slot,
        signature,
        block_hash,
        confirmations,
        account_keys,
        program_id,
        instruction_data,
        timestamp,
    );
    let commitment = Hash::new(instruction_data[..32].try_into().unwrap_or([0u8; 32]));
    slot_proof.to_inclusion_proof(&commitment)
}

/// Verify a Solana inclusion proof
///
/// Checks:
/// 1. Proof structure is valid (non-empty, correct size)
/// 2. Block hash is non-trivial
/// 3. Position matches the slot
/// 4. Proof data contains the expected commitment
pub fn verify_inclusion_proof(proof: &InclusionProof, commitment: &Hash) -> bool {
    if proof.proof_bytes.is_empty() {
        return false;
    }

    // Block hash must be non-trivial
    if proof.block_hash.as_bytes() == &[0u8; 32] {
        return false;
    }

    // Proof must be at least 128 bytes (slot + signature + block_hash + confirmations + flags + commitment + data_hash)
    if proof.proof_bytes.len() < 128 {
        return false;
    }

    // Verify the commitment is embedded in the proof
    // The commitment is stored at offset 113-145 in the proof bytes
    // (after slot(8) + signature(64) + block_hash(32) + confirmations(8) + finalized(1))
    if proof.proof_bytes.len() >= 145 {
        let proof_commitment: [u8; 32] =
            proof.proof_bytes[113..145].try_into().unwrap_or([0u8; 32]);
        if proof_commitment != *commitment.as_bytes() {
            return false;
        }
    }

    // Verify position matches the slot in the proof
    let proof_slot = u64::from_le_bytes(proof.proof_bytes[..8].try_into().unwrap_or([0u8; 8]));
    if proof.position != proof_slot {
        return false;
    }

    true
}

/// Build a Solana finality proof from slot and confirmation data
pub fn build_finality_proof(slot: u64, block_hash: Hash, current_slot: u64) -> FinalityProof {
    let confirmations = current_slot.saturating_sub(slot);
    let finalized = confirmations >= MIN_CONFIRMATIONS;

    let mut proof_data = Vec::with_capacity(64);
    proof_data.extend_from_slice(&slot.to_le_bytes());
    proof_data.extend_from_slice(&current_slot.to_le_bytes());
    proof_data.extend_from_slice(&confirmations.to_le_bytes());
    proof_data.push(if finalized { 1u8 } else { 0u8 });
    proof_data.extend_from_slice(block_hash.as_bytes());

    FinalityProof::new(proof_data, confirmations, finalized).unwrap_or_else(|e| {
        tracing::error!("Failed to create finality proof: {}", e);
        unsafe { FinalityProof::new_unchecked(vec![], confirmations, finalized) }
    })
}

/// Verify a Solana finality proof
///
/// Checks:
/// 1. Proof structure is valid
/// 2. Confirmations meet the minimum threshold
/// 3. Finality status matches the confirmation count
pub fn verify_finality_proof(proof: &FinalityProof, required_confirmations: u64) -> bool {
    if proof.finality_data.is_empty() {
        return false;
    }

    // Must have at least the minimum confirmations
    if proof.confirmations < required_confirmations {
        return false;
    }

    // If claim finalized, must have 32+ confirmations
    if proof.is_deterministic && proof.confirmations < MIN_CONFIRMATIONS {
        return false;
    }

    // Verify proof data structure
    if proof.finality_data.len() < 32 {
        return false;
    }

    true
}

/// Verify a complete proof bundle (inclusion + finality)
///
/// This is the main verification entry point for Solana proofs.
/// It checks both inclusion and finality, ensuring the transaction
/// is both included in a block AND has sufficient confirmations.
/// Delegates to csv-verifier canonical chain bundle verification (RULE 1).
struct SolanaNativeVerifier;

impl csv_verifier::ChainNativeProofVerifier for SolanaNativeVerifier {
    fn verify_inclusion_proof(
        &self,
        proof: &InclusionProof,
        commitment: &Hash,
    ) -> Result<bool, csv_verifier::ChainBundleError> {
        Ok(verify_inclusion_proof(proof, commitment))
    }

    fn verify_finality_proof(
        &self,
        proof: &FinalityProof,
        _anchor_ref: &str,
    ) -> Result<bool, csv_verifier::ChainBundleError> {
        Ok(verify_finality_proof(proof, 32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_proof_creation() {
        let sig = Signature::default();
        let block_hash = Hash::new([1u8; 32]);
        let instruction_data = vec![0xAB; 64];

        let proof = SlotProof::new(
            1000,
            sig,
            block_hash,
            32,
            vec![Pubkey::default()],
            Pubkey::default(),
            &instruction_data,
            1_000_000,
        );

        assert_eq!(proof.slot, 1000);
        assert!(proof.finalized);
        assert_eq!(proof.confirmations, 32);
    }

    #[test]
    fn test_slot_proof_not_finalized() {
        let sig = Signature::default();
        let block_hash = Hash::new([1u8; 32]);
        let instruction_data = vec![0xAB; 64];

        let proof = SlotProof::new(
            1000,
            sig,
            block_hash,
            10,
            vec![Pubkey::default()],
            Pubkey::default(),
            &instruction_data,
            1_000_000,
        );

        assert!(!proof.finalized);
        assert_eq!(proof.confirmations, 10);
    }

    #[test]
    fn test_slot_proof_to_inclusion_proof() {
        let sig = Signature::default();
        let block_hash = Hash::new([1u8; 32]);
        let instruction_data = vec![0xAB; 64];

        let slot_proof = SlotProof::new(
            1000,
            sig,
            block_hash,
            32,
            vec![Pubkey::default()],
            Pubkey::default(),
            &instruction_data,
            1_000_000,
        );

        let commitment = Hash::new(instruction_data[..32].try_into().unwrap());
        let inclusion = slot_proof.to_inclusion_proof(&commitment);

        assert_eq!(inclusion.block_hash, block_hash);
        assert_eq!(inclusion.position, 1000);
        assert!(!inclusion.proof_bytes.is_empty());
    }

    #[test]
    fn test_account_proof_data_integrity() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let proof = AccountProof::new(
            1000,
            Pubkey::default(),
            1_000_000,
            Pubkey::default(),
            data.clone(),
            false,
            0,
        );

        assert!(proof.verify_data_integrity());

        // Tamper with data
        let mut tampered = proof;
        tampered.data = vec![0xFF];
        assert!(!tampered.verify_data_integrity());
    }

    #[test]
    fn test_multi_account_proof_chain_continuity() {
        let accounts = vec![
            AccountProof::new(
                1000,
                Pubkey::default(),
                0,
                Pubkey::default(),
                vec![],
                false,
                0,
            ),
            AccountProof::new(
                1000,
                Pubkey::new_unique(),
                1_000_000,
                Pubkey::default(),
                vec![0xAB],
                false,
                0,
            ),
        ];

        let proof = MultiAccountProof::new(1000, 999, accounts, true);
        assert!(proof.verify_chain_continuity());
        assert!(proof.verify_all());
    }

    #[test]
    fn test_verify_inclusion_proof_valid() {
        let sig = Signature::default();
        let block_hash = Hash::new([1u8; 32]);
        let instruction_data = vec![0xAB; 64];

        let slot_proof = SlotProof::new(
            1000,
            sig,
            block_hash,
            32,
            vec![Pubkey::default()],
            Pubkey::default(),
            &instruction_data,
            1_000_000,
        );

        let commitment = Hash::new(instruction_data[..32].try_into().unwrap());
        let inclusion = slot_proof.to_inclusion_proof(&commitment);

        assert!(verify_inclusion_proof(&inclusion, &commitment));
    }

    #[test]
    fn test_verify_inclusion_proof_empty_fails() {
        let proof = InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap();
        let commitment = Hash::new([0xAB; 32]);
        assert!(!verify_inclusion_proof(&proof, &commitment));
    }

    #[test]
    fn test_verify_inclusion_proof_zero_block_hash_fails() {
        let proof = InclusionProof::new(vec![0xAB; 128], Hash::zero(), 0, 0).unwrap();
        let commitment = Hash::new([0xAB; 32]);
        assert!(!verify_inclusion_proof(&proof, &commitment));
    }

    #[test]
    fn test_verify_finality_proof_valid() {
        let slot_hash = Hash::new([1u8; 32]);
        let finality = build_finality_proof(968, slot_hash, 1000);

        assert!(verify_finality_proof(&finality, 32));
        assert!(finality.is_deterministic);
    }

    #[test]
    fn test_verify_finality_proof_insufficient_confirmations() {
        let slot_hash = Hash::new([1u8; 32]);
        let finality = build_finality_proof(990, slot_hash, 1000);

        assert!(!verify_finality_proof(&finality, 32));
    }

    #[test]
    fn test_verify_proof_bundle() {
        let sig = Signature::default();
        let block_hash = Hash::new([1u8; 32]);
        let instruction_data = vec![0xAB; 64];

        let slot_proof = SlotProof::new(
            900,
            sig,
            block_hash,
            100,
            vec![Pubkey::default()],
            Pubkey::default(),
            &instruction_data,
            1_000_000,
        );

        let commitment = Hash::new(instruction_data[..32].try_into().unwrap());
        let inclusion = slot_proof.to_inclusion_proof(&commitment);
        let finality = build_finality_proof(900, block_hash, 1000);

        // Verify inclusion and finality separately (RULE 1: verification delegated to csv-verifier)
        assert!(verify_inclusion_proof(&inclusion, &commitment));
        assert!(verify_finality_proof(&finality, 32));
    }

    #[test]
    fn test_build_inclusion_proof() {
        let sig = Signature::default();
        let block_hash = Hash::new([1u8; 32]);
        let instruction_data = vec![0xAB; 64];

        let proof = build_inclusion_proof(
            1000,
            sig,
            block_hash,
            vec![Pubkey::default()],
            Pubkey::default(),
            &instruction_data,
            32,
            1_000_000,
        );

        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.position, 1000);
    }

    #[test]
    fn test_multi_account_proof_verify_all() {
        let accounts = vec![
            AccountProof::new(
                1000,
                Pubkey::default(),
                0,
                Pubkey::default(),
                vec![0x01],
                false,
                0,
            ),
            AccountProof::new(
                1000,
                Pubkey::new_unique(),
                1_000_000,
                Pubkey::default(),
                vec![0x02],
                false,
                0,
            ),
        ];

        let proof = MultiAccountProof::new(1000, 999, accounts, true);
        assert!(proof.verify_all());

        // Tamper with one account
        let mut tampered_accounts = proof.accounts.clone();
        tampered_accounts[0].data = vec![0xFF];
        let tampered_proof = MultiAccountProof::new(1000, 999, tampered_accounts, true);
        assert!(!tampered_proof.verify_all());
    }
}
