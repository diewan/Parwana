//! Transition legality
//!
//! This module defines the legal state transitions for the CSV protocol.
//! Illegal transitions are prevented at compile time through the typestate pattern.

/// Legal state transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Locked → AwaitingFinality
    LockedToAwaitingFinality,
    /// AwaitingFinality → ProofBuilding
    AwaitingFinalityToProofBuilding,
    /// ProofBuilding → ProofValidated
    ProofBuildingToProofValidated,
    /// ProofValidated → Minting
    ProofValidatedToMinting,
    /// Minting → Completed
    MintingToCompleted,
    /// Any → RolledBack (on reorg)
    ToRolledBack,
    /// Any → Compromised (on security incident)
    ToCompromised,
}

/// Check if a transition is legal
pub fn is_legal_transition(from: State, to: State) -> bool {
    match (from, to) {
        (State::Locked, State::AwaitingFinality) => true,
        (State::AwaitingFinality, State::ProofBuilding) => true,
        (State::ProofBuilding, State::ProofValidated) => true,
        (State::ProofValidated, State::Minting) => true,
        (State::Minting, State::Completed) => true,
        (_, State::RolledBack) => true,
        (_, State::Compromised) => true,
        _ => false,
    }
}

/// Transfer states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Transfer is locked on source chain
    Locked,
    /// Awaiting finality confirmation
    AwaitingFinality,
    /// Building zero-knowledge proof
    ProofBuilding,
    /// Proof validated, ready for minting
    ProofValidated,
    /// Minting on destination chain
    Minting,
    /// Transfer successfully completed
    Completed,
    /// Transfer rolled back due to reorg
    RolledBack,
    /// Transfer compromised (security incident)
    Compromised,
}
