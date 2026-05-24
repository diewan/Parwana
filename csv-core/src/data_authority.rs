//! Data authority tags — prevent explorer-authoritative state interpretation.
//!
//! The explorer must never be authoritative for runtime state. All explorer
//! data must carry a data authority tag so that operators can visually
//! distinguish runtime-derived truth from observed or inferred data.

use serde::{Deserialize, Serialize};

/// Authority behind a piece of data in the explorer or any observational system.
///
/// The UI MUST visibly distinguish these levels. Operators must never treat
/// `ChainObserved` or `ExplorerInferred` as authoritative for finality
/// decisions or transfer completion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataAuthority {
    /// Data was emitted by the runtime (single source of truth).
    /// This is the ONLY authoritative source for:
    /// - transfer completion status
    /// - replay validity
    /// - rollback decisions
    RuntimeDerived,
    /// Data was observed from the chain directly via RPC without
    /// runtime mediation. May include unconfirmed or reorg-able state.
    ChainObserved,
    /// Data was inferred or aggregated from other data by the
    /// explorer/indexer. NOT authoritative.
    ExplorerInferred,
}

impl DataAuthority {
    /// Returns true if this authority level is runtime-derived (trusted).
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::RuntimeDerived)
    }

    /// Returns the human-readable label for this authority level.
    pub fn label(&self) -> &'static str {
        match self {
            Self::RuntimeDerived => "runtime",
            Self::ChainObserved => "chain",
            Self::ExplorerInferred => "inferred",
        }
    }
}
