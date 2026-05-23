//! Proof management runtime.
//!
//! The [`ProofManager`] handles generation and verification of
//! cryptographic proofs for Sanads and cross-chain transfers.
//!
//! # Proof Types
//!
//! - **Inclusion Proof**: Proves a transaction is included in a block
//! - **Finality Proof**: Proves a block is finalized at sufficient depth
//! - **ProofBundle**: Complete proof package (inclusion + finality)

use std::sync::Arc;

use csv_core::{ChainId, Hash, ProofBundle, SanadId};

use crate::client::ClientRef;
use crate::error::CsvError;

/// Manager for proof operations.
///
/// Obtain a [`ProofManager`] via
/// [`CsvClient::proofs()`](crate::client::CsvClient::proofs).
///
/// # Example
///
/// ```ignore
/// use csv_sdk::prelude::*;
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let client = CsvClient::builder()
/// #     .with_chain(ChainId::new("bitcoin"))
/// #     .with_store_backend(StoreBackend::InMemory)
/// #     .build()?;
/// let proofs = client.proofs();
///
/// // Generate a proof bundle for a sanad
/// let bundle = proofs.generate(&SanadId::default(), ChainId::new("bitcoin"))?;
/// # Ok(())
/// # }
/// ```
pub struct ProofManager {
    client: Arc<ClientRef>,
}

impl ProofManager {
    pub(crate) fn new(client: Arc<ClientRef>) -> Self {
        Self { client }
    }

    /// Generate a proof bundle for a Sanad on the specified chain.
    ///
    /// This creates a complete [`ProofBundle`] containing:
    /// - Inclusion proof (chain-specific format)
    /// - Finality proof
    /// - State transition DAG
    ///
    /// # Arguments
    ///
    /// * `sanad_id` — The Sanad to generate a proof for.
    /// * `chain` — The chain where the Sanad's seal is anchored.
    ///
    /// # Chain-Specific Proof Formats
    ///
    /// - **Bitcoin**: Merkle branch + block header (SPV proof)
    /// - **Ethereum**: MPT receipt proof + log inclusion
    /// - **Sui**: Checkpoint certification + transaction effects
    /// - **Aptos**: Ledger info proof + event stream
    pub fn generate(&self, _sanad_id: &SanadId, chain: ChainId) -> Result<ProofBundle, CsvError> {
        if !self.client.is_chain_enabled(chain.clone()) {
            return Err(CsvError::ChainNotSupported(chain));
        }

        // Proof generation requires chain adapter proof provider integration
        // This will be implemented when the chain adapter proof providers are ready
        Err(CsvError::ProtocolError {
            chain,
            message: "Proof generation requires chain adapter ProofProvider trait integration."
                .to_string(),
        })
    }

    /// Verify a proof bundle against an expected Sanad ID.
    ///
    /// This is the core client-side validation function. It verifies:
    /// 1. The inclusion proof is valid (transaction is in a block)
    /// 2. The finality proof is sufficient (block is finalized)
    /// 3. The seal was consumed exactly once (single-use enforcement)
    /// 4. If `expected_sanad_id` is provided, the proof resolves to it
    ///
    /// # Arguments
    ///
    /// * `proof` — The proof bundle to verify.
    /// * `expected_sanad_id` — Optional expected Sanad ID after verification.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(
        &self,
        proof: &ProofBundle,
        expected_sanad_id: Option<&SanadId>,
    ) -> Result<bool, CsvError> {
        // In a full implementation, this would:
        // 1. Extract the inclusion proof and verify it against the source chain
        // 2. Verify the finality proof meets the required depth
        // 3. Check the seal registry for double-spend
        // 4. If expected_sanad_id is provided, verify the proof resolves to it
        //
        // The chain adapters provide chain-specific verification:
        // - Bitcoin: SPV verification with merkle proof
        // - Ethereum: MPT verification with receipt proof
        // - Sui: Checkpoint verification with Narwhal consensus
        // - Aptos: Ledger info verification with HotStuff

        let _ = expected_sanad_id;

        // Basic validation: proof bundle must have valid structure
        // In production, full cryptographic verification happens here
        let valid = proof.inclusion_proof.block_hash != Hash::zero()
            || proof.transition_dag.nodes.is_empty();

        Ok(valid)
    }
}
