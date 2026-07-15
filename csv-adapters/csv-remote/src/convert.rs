//! Port ⇄ wire conversions for remote dispatch.
//!
//! The runtime port types live in `csv-chain-ports` (a higher layer than
//! `csv-wire`, which must not depend on it), so the mapping between the two
//! lives here — in one place, used by both the client [`crate::RemoteChainAdapter`]
//! and the [`crate::host`] endpoint so the two ends can never drift.

use csv_chain_ports::{
    CrossChainTransfer, DestinationMaterialization, LockResult, MintResult, SealRegistryStatus,
    SettlementResult, TxFinality,
};
use csv_hash::Hash;
use csv_wire::remote::{
    RemoteLockResult, RemoteMaterialization, RemoteMintResult, RemoteSealRegistryStatus,
    RemoteSettlementResult, RemoteTransfer, RemoteTxFinality,
};

/// Convert a runtime transfer into its wire form.
pub fn transfer_to_wire(transfer: &CrossChainTransfer) -> RemoteTransfer {
    RemoteTransfer {
        id: transfer.id.clone(),
        source_chain: transfer.source_chain.clone(),
        destination_chain: transfer.destination_chain.clone(),
        lock_tx_hash: transfer.lock_tx_hash.clone(),
        lock_output_index: transfer.lock_output_index,
        sanad_id: transfer.sanad_id.0,
        transition_id: transfer.transition_id.clone(),
    }
}

/// Convert a wire transfer back into the runtime port type.
pub fn transfer_from_wire(transfer: &RemoteTransfer) -> CrossChainTransfer {
    CrossChainTransfer {
        id: transfer.id.clone(),
        source_chain: transfer.source_chain.clone(),
        destination_chain: transfer.destination_chain.clone(),
        lock_tx_hash: transfer.lock_tx_hash.clone(),
        lock_output_index: transfer.lock_output_index,
        sanad_id: Hash::new(transfer.sanad_id),
        transition_id: transfer.transition_id.clone(),
    }
}

/// Convert a lock result into its wire form.
pub fn lock_result_to_wire(result: &LockResult) -> RemoteLockResult {
    RemoteLockResult {
        tx_hash: result.tx_hash.clone(),
        block_height: result.block_height,
    }
}

/// Convert a wire lock result back into the runtime port type.
pub fn lock_result_from_wire(result: &RemoteLockResult) -> LockResult {
    LockResult {
        tx_hash: result.tx_hash.clone(),
        block_height: result.block_height,
    }
}

fn materialization_to_wire(m: &DestinationMaterialization) -> RemoteMaterialization {
    RemoteMaterialization {
        chain_id: m.chain_id.clone(),
        object_id: m.object_id.clone(),
        seal_ref: m.seal_ref.clone(),
        registry_ref: m.registry_ref.clone(),
        commitment: m.commitment,
        owner: m.owner.clone(),
    }
}

fn materialization_from_wire(m: &RemoteMaterialization) -> DestinationMaterialization {
    DestinationMaterialization {
        chain_id: m.chain_id.clone(),
        object_id: m.object_id.clone(),
        seal_ref: m.seal_ref.clone(),
        registry_ref: m.registry_ref.clone(),
        commitment: m.commitment,
        owner: m.owner.clone(),
    }
}

/// Convert a mint result into its wire form.
pub fn mint_result_to_wire(result: &MintResult) -> RemoteMintResult {
    RemoteMintResult {
        tx_hash: result.tx_hash.clone(),
        block_height: result.block_height,
        materialization: materialization_to_wire(&result.materialization),
    }
}

/// Convert a wire mint result back into the runtime port type.
pub fn mint_result_from_wire(result: &RemoteMintResult) -> MintResult {
    MintResult {
        tx_hash: result.tx_hash.clone(),
        block_height: result.block_height,
        materialization: materialization_from_wire(&result.materialization),
    }
}

/// Convert a transaction-finality reading into its wire form.
pub fn tx_finality_to_wire(finality: &TxFinality) -> RemoteTxFinality {
    RemoteTxFinality {
        block_height: finality.block_height,
        confirmations: finality.confirmations,
        observed_tip_height: finality.observed_tip_height,
    }
}

/// Convert a wire finality reading back into the runtime port type.
///
/// `observed_tip_height` is copied verbatim (never reconstructed): a `None` on
/// the wire stays `None`, so the client finality gate cannot mistake it for a
/// depth measured against a real tip.
pub fn tx_finality_from_wire(finality: &RemoteTxFinality) -> TxFinality {
    TxFinality {
        block_height: finality.block_height,
        confirmations: finality.confirmations,
        observed_tip_height: finality.observed_tip_height,
    }
}

/// Convert a seal-registry status into its wire form.
pub fn seal_status_to_wire(status: &SealRegistryStatus) -> RemoteSealRegistryStatus {
    match status {
        SealRegistryStatus::Available => RemoteSealRegistryStatus::Available,
        SealRegistryStatus::Consumed => RemoteSealRegistryStatus::Consumed,
        SealRegistryStatus::Locked => RemoteSealRegistryStatus::Locked,
    }
}

/// Convert a wire seal-registry status back into the runtime port type.
pub fn seal_status_from_wire(status: RemoteSealRegistryStatus) -> SealRegistryStatus {
    match status {
        RemoteSealRegistryStatus::Available => SealRegistryStatus::Available,
        RemoteSealRegistryStatus::Consumed => SealRegistryStatus::Consumed,
        RemoteSealRegistryStatus::Locked => SealRegistryStatus::Locked,
    }
}

/// Convert a settlement result into its wire form.
pub fn settlement_to_wire(result: &SettlementResult) -> RemoteSettlementResult {
    RemoteSettlementResult {
        tx_hash: result.tx_hash.clone(),
        block_height: result.block_height,
    }
}

/// Convert a wire settlement result back into the runtime port type.
pub fn settlement_from_wire(result: &RemoteSettlementResult) -> SettlementResult {
    SettlementResult {
        tx_hash: result.tx_hash.clone(),
        block_height: result.block_height,
    }
}
