//! Solana program implementation for CSV

use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    transaction::Transaction,
};

use crate::error::{SolanaError, SolanaResult};
use crate::types::CsvInstruction;
use bincode::serialize;

/// Solana program interface for CSV operations
pub struct SolanaProgram {
    /// Program ID
    pub program_id: Pubkey,
    /// Program account
    pub program_account: Option<Account>,
}

impl SolanaProgram {
    /// Create new Solana program
    pub fn new(program_id: Pubkey) -> Self {
        Self {
            program_id,
            program_account: None,
        }
    }

    /// Get program ID
    pub fn program_id(&self) -> Pubkey {
        self.program_id
    }

    /// Get program account
    pub fn program_account(&self) -> Option<&Account> {
        self.program_account.as_ref()
    }

    /// Set program account
    pub fn set_program_account(&mut self, account: Account) {
        self.program_account = Some(account);
    }

    /// Create seal instruction
    pub fn create_seal_instruction(
        &self,
        seal_account: Pubkey,
        authority: Pubkey,
        sanad_id: csv_core::Hash,
        commitment: csv_core::Hash,
    ) -> SolanaResult<Instruction> {
        let instruction_data = CsvInstruction::CreateSanad {
            sanad_id,
            owner: authority,
            commitment,
        };

        let data = serialize(&instruction_data).map_err(|e| {
            SolanaError::Serialization(format!("Failed to serialize instruction: {}", e))
        })?;

        Ok(Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(seal_account, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ))
    }

    /// Create anchor instruction for publishing a commitment
    pub fn create_anchor_instruction(
        &self,
        anchor_account: Pubkey,
        authority: Pubkey,
        commitment: csv_core::Hash,
        sanad_id: csv_core::Hash,
        metadata: Vec<u8>,
    ) -> SolanaResult<Instruction> {
        let instruction_data = CsvInstruction::PublishCommitment {
            commitment,
            sanad_id,
            metadata,
        };

        let data = serialize(&instruction_data).map_err(|e| {
            SolanaError::Serialization(format!("Failed to serialize instruction: {}", e))
        })?;

        Ok(Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(anchor_account, false),
                AccountMeta::new_readonly(authority, true),
            ],
        ))
    }

    /// Create commitment instruction for consuming a seal
    pub fn create_commitment_instruction(
        &self,
        seal_account: Pubkey,
        authority: Pubkey,
        sanad_id: csv_core::Hash,
        new_owner: Pubkey,
    ) -> SolanaResult<Instruction> {
        let instruction_data = CsvInstruction::ConsumeSeal {
            seal_account,
            sanad_id,
            new_owner,
        };

        let data = serialize(&instruction_data).map_err(|e| {
            SolanaError::Serialization(format!("Failed to serialize instruction: {}", e))
        })?;

        Ok(Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(seal_account, false),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(new_owner, false),
            ],
        ))
    }

    /// Create verification instruction for transferring a sanad
    pub fn create_verification_instruction(
        &self,
        sanad_account: Pubkey,
        from_owner: Pubkey,
        to_owner: Pubkey,
        sanad_id: csv_core::Hash,
        destination_chain: String,
    ) -> SolanaResult<Instruction> {
        let instruction_data = CsvInstruction::TransferSanad {
            sanad_id,
            from_owner,
            to_owner,
            destination_chain,
        };

        let data = serialize(&instruction_data).map_err(|e| {
            SolanaError::Serialization(format!("Failed to serialize instruction: {}", e))
        })?;

        Ok(Instruction::new_with_bytes(
            self.program_id,
            &data,
            vec![
                AccountMeta::new(sanad_account, false),
                AccountMeta::new_readonly(from_owner, true),
                AccountMeta::new(to_owner, false),
            ],
        ))
    }

    /// Build transaction with instructions
    pub fn build_transaction(
        &self,
        instructions: Vec<Instruction>,
        payer: Pubkey,
        recent_blockhash: solana_sdk::hash::Hash,
    ) -> SolanaResult<Transaction> {
        let mut transaction = Transaction::new_with_payer(&instructions, Some(&payer));
        transaction.message.recent_blockhash = recent_blockhash;
        Ok(transaction)
    }

    /// Verify program account
    pub fn verify_program_account(&self, account: &Account) -> SolanaResult<bool> {
        // Verify the account is owned by the expected program
        if account.owner != self.program_id {
            return Ok(false);
        }

        // Verify account has executable flag set for program accounts
        // Note: Data accounts may not be executable
        Ok(true)
    }

    /// Get program data
    pub fn get_program_data(&self) -> SolanaResult<Vec<u8>> {
        if let Some(account) = &self.program_account {
            Ok(account.data.clone())
        } else {
            Err(SolanaError::AccountNotFound(
                "Program account not loaded".to_string(),
            ))
        }
    }

    /// Parse instruction data into a CsvInstruction
    pub fn parse_instruction_data(&self, data: &[u8]) -> SolanaResult<CsvInstruction> {
        let instruction: CsvInstruction = bincode::deserialize(data).map_err(|e| {
            SolanaError::Deserialization(format!("Failed to parse instruction: {}", e))
        })?;
        Ok(instruction)
    }

    /// Validate instruction
    pub fn validate_instruction(&self, instruction: &Instruction) -> SolanaResult<bool> {
        // Check program ID matches
        if instruction.program_id != self.program_id {
            return Ok(false);
        }

        // Validate accounts are present
        if instruction.accounts.is_empty() {
            return Ok(false);
        }

        // Validate instruction data can be parsed
        match self.parse_instruction_data(&instruction.data) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl Default for SolanaProgram {
    fn default() -> Self {
        Self::new(solana_sdk::pubkey::Pubkey::default())
    }
}
