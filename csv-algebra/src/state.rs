use alloc::boxed::Box;
use crate::proof::CanonicalProof;
use crate::finality::FinalityEvidence;
use crate::transfer::SealId;

/// Marker trait — zero runtime cost, compile-time only
pub trait TransferState: sealed::Sealed {}
mod sealed { 
    pub trait Sealed {} 
}

// ── State structs ─────────────────────────────────────────────────────────────

/// Source chain lock confirmed. No proof yet.
#[must_use = "TransferState must be driven to completion or rollback"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    pub seal_id: SealId,
    pub source_chain: u32,
    pub dest_chain:   u32,
}

/// Proof construction underway.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBuilding {
    pub locked: Locked,
    pub attempt: u8,
}

/// Proof submitted, finality window pending.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwaitingFinality {
    pub proof: CanonicalProof,
    pub required_confirmations: u64,
}

/// Finality confirmed, verifier accepted proof.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofValidated {
    pub proof:    CanonicalProof,
    pub evidence: FinalityEvidence,
}

/// Mint transaction submitted to destination chain.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minting {
    pub validated: ProofValidated,
    pub mint_tx:   [u8; 32],
}

/// Terminal state: success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    pub mint_tx:   [u8; 32],
    pub seal_id:   SealId,
}

/// Terminal state: reorg or failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolledBack {
    pub reason: RollbackReason,
    pub seal_id: SealId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackReason { 
    Reorg, 
    ProofInvalid, 
    FinalityTimeout, 
    MintFailed 
}

// ── Sealed impls ──────────────────────────────────────────────────────────────

impl sealed::Sealed for Locked          {}
impl sealed::Sealed for ProofBuilding   {}
impl sealed::Sealed for AwaitingFinality{}
impl sealed::Sealed for ProofValidated  {}
impl sealed::Sealed for Minting         {}
impl sealed::Sealed for Completed      {}
impl sealed::Sealed for RolledBack     {}

impl TransferState for Locked          {}
impl TransferState for ProofBuilding   {}
impl TransferState for AwaitingFinality{}
impl TransferState for ProofValidated  {}
impl TransferState for Minting         {}
impl TransferState for Completed      {}
impl TransferState for RolledBack     {}

// ── Transitions ───────────────────────────────────────────────────────────────
// Each transition consumes self. The type system enforces the DAG.
// You CANNOT call .validate_proof() on a Minting — it won't compile.

impl Locked {
    /// Begin proof construction.
    pub fn begin_proof(self) -> ProofBuilding {
        ProofBuilding { locked: self, attempt: 0 }
    }

    /// Source chain reorganized before proof started.
    pub fn reorg(self) -> RolledBack {
        RolledBack { reason: RollbackReason::Reorg, seal_id: self.seal_id }
    }
}

impl ProofBuilding {
    /// Proof constructed, submit and await finality.
    pub fn submit_proof(self, proof: CanonicalProof, required: u64) -> AwaitingFinality {
        AwaitingFinality { proof, required_confirmations: required }
    }

    /// Proof construction failed — retry or abandon.
    pub fn fail(self) -> RolledBack {
        RolledBack { reason: RollbackReason::ProofInvalid, seal_id: self.locked.seal_id }
    }
}

impl AwaitingFinality {
    /// Verifier accepted proof + finality evidence.
    pub fn accept(self, evidence: FinalityEvidence) -> ProofValidated {
        ProofValidated { proof: self.proof, evidence }
    }

    /// Finality window expired.
    pub fn timeout(self) -> RolledBack {
        RolledBack { reason: RollbackReason::FinalityTimeout, seal_id: SealId([0u8; 32]) }
    }
}

impl ProofValidated {
    /// Submit mint transaction to destination chain.
    pub fn mint(self, tx: [u8; 32]) -> Minting {
        Minting { validated: self, mint_tx: tx }
    }
}

impl Minting {
    /// Mint confirmed on destination chain.
    pub fn confirm(self) -> Completed {
        Completed { mint_tx: self.mint_tx, seal_id: self.validated.proof.block_hash().into() }
    }

    /// Mint transaction failed.
    pub fn fail(self) -> RolledBack {
        RolledBack { reason: RollbackReason::MintFailed, seal_id: SealId([0u8; 32]) }
    }
}
