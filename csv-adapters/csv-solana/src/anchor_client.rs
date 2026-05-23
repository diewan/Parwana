//! Typed Anchor instruction builders for CSV Seal program
//!
//! This module provides strongly-typed instruction builders for the deployed
//! csv-seal Anchor program, using proper discriminators and account structures.

use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use std::str::FromStr;

/// CSV Seal program ID (from deployed Anchor program)
pub const CSV_SEAL_PROGRAM_ID: &str = "CCMF6BvAyTPNJAPtGMVJAR652Hv9VPy9NmVdgC9969dj";

/// Anchor instruction discriminators (first 8 bytes of sha256("global:instruction_name"))
pub mod discriminators {
    use sha2::{Digest, Sha256};

    pub fn initialize_registry() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:initialize_registry");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn create_seal() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:create_seal");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn consume_seal() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:consume_seal");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn lock_sanad() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:lock_sanad");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn mint_sanad() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:mint_sanad");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn refund_sanad() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:refund_sanad");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn register_nullifier() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:register_nullifier");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn record_sanad_metadata() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:record_sanad_metadata");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }

    pub fn transfer_sanad() -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(b"global:transfer_sanad");
        let hash = hasher.finalize();
        hash[..8].try_into().unwrap()
    }
}

/// PDA derivation helpers
pub mod pdas {
    use solana_sdk::pubkey::Pubkey;

    /// Derive the sanad account PDA: ["sanad", owner, sanad_id]
    pub fn sanad_account(program_id: &Pubkey, owner: &Pubkey, sanad_id: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"sanad", owner.as_ref(), sanad_id], program_id)
    }

    /// Derive the lock registry PDA: ["lock_registry"]
    pub fn lock_registry(program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"lock_registry"], program_id)
    }

    /// Derive the lock account PDA: ["lock", sanad_id]
    pub fn lock_account(program_id: &Pubkey, sanad_id: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"lock", sanad_id], program_id)
    }

    /// Derive the refund sanad account PDA: ["sanad", claimant, sanad_id, "refund"]
    pub fn refund_sanad_account(program_id: &Pubkey, claimant: &Pubkey, sanad_id: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"sanad", claimant.as_ref(), sanad_id, b"refund"], program_id)
    }
}

/// Instruction builders
pub struct InstructionBuilder {
    program_id: Pubkey,
}

impl InstructionBuilder {
    /// Create a new instruction builder with the CSV Seal program ID
    pub fn new() -> Self {
        Self {
            program_id: Pubkey::from_str(CSV_SEAL_PROGRAM_ID)
                .expect("Invalid CSV Seal program ID"),
        }
    }

    /// Create with custom program ID (for testing with different deployments)
    pub fn with_program_id(program_id: Pubkey) -> Self {
        Self { program_id }
    }

    /// Build initialize_registry instruction
    pub fn initialize_registry(
        &self,
        registry: Pubkey,
        authority: Pubkey,
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::initialize_registry());

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(authority, true),
                // AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
            ],
        )
    }

    /// Build create_seal instruction
    pub fn create_seal(
        &self,
        sanad_account: Pubkey,
        owner: Pubkey,
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        state_root: [u8; 32],
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::create_seal());
        data.extend_from_slice(&sanad_id);
        data.extend_from_slice(&commitment);
        data.extend_from_slice(&state_root);

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(owner, true),
                // AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
            ],
        )
    }

    /// Build consume_seal instruction
    pub fn consume_seal(
        &self,
        sanad_account: Pubkey,
        consumer: Pubkey,
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::consume_seal());

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(consumer, true),
            ],
        )
    }

    /// Build lock_sanad instruction
    pub fn lock_sanad(
        &self,
        sanad_account: Pubkey,
        registry: Pubkey,
        lock_account: Pubkey,
        owner: Pubkey,
        recent_blockhashes: Pubkey,
        destination_chain: u8,
        destination_owner: [u8; 32],
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::lock_sanad());
        data.push(destination_chain);
        data.extend_from_slice(&destination_owner);

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new(registry, false),
                AccountMeta::new(lock_account, false),
                AccountMeta::new(owner, true),
                AccountMeta::new_readonly(recent_blockhashes, false),
                // AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
            ],
        )
    }

    /// Build mint_sanad instruction
    pub fn mint_sanad(
        &self,
        sanad_account: Pubkey,
        owner: Pubkey,
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        state_root: [u8; 32],
        source_chain: u8,
        source_seal_ref: [u8; 32],
        proof: Vec<u8>,
        proof_root: [u8; 32],
        leaf_position: u64,
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::mint_sanad());
        data.extend_from_slice(&sanad_id);
        data.extend_from_slice(&commitment);
        data.extend_from_slice(&state_root);
        data.push(source_chain);
        data.extend_from_slice(&source_seal_ref);
        data.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        data.extend_from_slice(&proof);
        data.extend_from_slice(&proof_root);
        data.extend_from_slice(&leaf_position.to_le_bytes());

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(owner, true),
                // AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
            ],
        )
    }

    /// Build refund_sanad instruction
    pub fn refund_sanad(
        &self,
        registry: Pubkey,
        original_sanad: Pubkey,
        lock_account: Pubkey,
        new_sanad_account: Pubkey,
        claimant: Pubkey,
        state_root: [u8; 32],
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::refund_sanad());
        data.extend_from_slice(&state_root);

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(original_sanad, false),
                AccountMeta::new(lock_account, false),
                AccountMeta::new(new_sanad_account, false),
                AccountMeta::new(claimant, true),
                // AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(Pubkey::from([0u8; 32]), false),
            ],
        )
    }

    /// Build register_nullifier instruction
    pub fn register_nullifier(
        &self,
        sanad_account: Pubkey,
        authority: Pubkey,
        nullifier: [u8; 32],
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::register_nullifier());
        data.extend_from_slice(&nullifier);

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(authority, true),
            ],
        )
    }

    /// Build record_sanad_metadata instruction
    pub fn record_sanad_metadata(
        &self,
        sanad_account: Pubkey,
        authority: Pubkey,
        asset_class: u8,
        asset_id: [u8; 32],
        metadata_hash: [u8; 32],
        proof_system: u8,
        proof_root: [u8; 32],
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::record_sanad_metadata());
        data.push(asset_class);
        data.extend_from_slice(&asset_id);
        data.extend_from_slice(&metadata_hash);
        data.push(proof_system);
        data.extend_from_slice(&proof_root);

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(authority, true),
            ],
        )
    }

    /// Build transfer_sanad instruction
    pub fn transfer_sanad(
        &self,
        sanad_account: Pubkey,
        current_owner: Pubkey,
        new_owner: Pubkey,
    ) -> Instruction {
        let mut data = Vec::new();
        data.extend_from_slice(&discriminators::transfer_sanad());
        data.extend_from_slice(new_owner.as_ref());

        Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(current_owner, true),
            ],
        )
    }
}

impl Default for InstructionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminators_length() {
        assert_eq!(discriminators::initialize_registry().len(), 8);
        assert_eq!(discriminators::create_seal().len(), 8);
        assert_eq!(discriminators::consume_seal().len(), 8);
        assert_eq!(discriminators::lock_sanad().len(), 8);
        assert_eq!(discriminators::mint_sanad().len(), 8);
        assert_eq!(discriminators::refund_sanad().len(), 8);
        assert_eq!(discriminators::register_nullifier().len(), 8);
        assert_eq!(discriminators::record_sanad_metadata().len(), 8);
        assert_eq!(discriminators::transfer_sanad().len(), 8);
    }

    #[test]
    fn test_discriminators_unique() {
        let disc1 = discriminators::create_seal();
        let disc2 = discriminators::consume_seal();
        let disc3 = discriminators::lock_sanad();
        
        assert_ne!(disc1, disc2);
        assert_ne!(disc2, disc3);
        assert_ne!(disc1, disc3);
    }

    #[test]
    fn test_instruction_builder_creation() {
        let builder = InstructionBuilder::new();
        assert_eq!(builder.program_id.to_string(), CSV_SEAL_PROGRAM_ID);
    }

    #[test]
    fn test_create_seal_instruction() {
        let builder = InstructionBuilder::new();
        let sanad_account = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let sanad_id = [1u8; 32];
        let commitment = [2u8; 32];
        let state_root = [3u8; 32];

        let ix = builder.create_seal(sanad_account, owner, sanad_id, commitment, state_root);
        
        assert_eq!(ix.program_id.to_string(), CSV_SEAL_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.data.len(), 8 + 32 + 32 + 32); // discriminator + 3x32-byte fields
    }

    #[test]
    fn test_mint_sanad_instruction_with_proof() {
        let builder = InstructionBuilder::new();
        let sanad_account = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let sanad_id = [1u8; 32];
        let commitment = [2u8; 32];
        let state_root = [3u8; 32];
        let source_chain = 1u8;
        let source_seal_ref = [4u8; 32];
        let proof = vec![5u8; 64];
        let proof_root = [6u8; 32];
        let leaf_position = 0u64;

        let ix = builder.mint_sanad(
            sanad_account,
            owner,
            sanad_id,
            commitment,
            state_root,
            source_chain,
            source_seal_ref,
            proof.clone(),
            proof_root,
            leaf_position,
        );
        
        assert_eq!(ix.accounts.len(), 3);
        // discriminator + sanad_id + commitment + state_root + source_chain + source_seal_ref + proof_len + proof + proof_root + leaf_position
        assert_eq!(ix.data.len(), 8 + 32 + 32 + 32 + 1 + 32 + 4 + 64 + 32 + 8);
    }
}
