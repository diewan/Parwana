//! The application contract, and the mapping from runtime artifacts onto it.
//!
//! The contract types themselves live in `csv-wire` (the transport-representation
//! authority) and are re-exported here. What this module adds is the *only*
//! sanctioned way to build them: functions that read a runtime artifact and copy
//! its fields across.
//!
//! Applications call these. They do not construct contract artifacts from
//! whatever they happen to know locally, because the point of the contract is
//! that every field on it traces back to something the runtime observed. A
//! wallet, a CLI, and a web front end that all go through here cannot drift,
//! and none of them can present a completion the runtime never reported.
//!
//! # What this module refuses to do
//!
//! - Infer finality from a confirmation count without the tip it was measured against.
//! - Report an assurance the canonical verifier did not return.
//! - Offer a next action the transfer's mode cannot honor.
//!
//! Each of those is enforced by the contract's own `validate`, which every
//! constructor here runs before returning.

use std::time::{SystemTime, UNIX_EPOCH};

pub use csv_wire::app::{
    APP_CONTRACT_SCHEMA_VERSION, AcceptBody, ArtifactKind, ComponentHealth, ContractArtifact,
    ContractError, ContractHeader, FinalityEvidence, IntentOperation, IntentValue, InvoiceBody,
    MAX_INTENT_TTL_SECS, MaterializationWire, MaterializeBody, NextAction, ReceiptBody,
    RecoveryPlan, RecoveryReason, RuntimeHealthReport, RuntimeHealthState, SendBody, SigningIntent,
    TransferEvent, TransferMode, TransferPhase, TransferReceipt, VerificationAssuranceWire,
    VerificationRecord, decode, encode,
};

use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;
use csv_observability::runtime_health::RuntimeHealth;
use csv_protocol::verification_levels::VerificationLevel;
use csv_runtime::FinalityObservation;
use csv_wire::primitives::{HashWire, SanadIdWire};

use crate::error::CsvError;
use crate::transfers::TransferOutcome;

impl From<ContractError> for CsvError {
    fn from(err: ContractError) -> Self {
        CsvError::RuntimeError(format!("application contract violation: {err}"))
    }
}

/// Unix seconds now. Contract artifacts are stamped with the moment they were built.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map the canonical verifier's level onto the wire.
///
/// A total mapping — there is no "unknown" fallback, because a level the verifier
/// did not return is a level no application may display.
pub fn assurance_from_level(level: VerificationLevel) -> VerificationAssuranceWire {
    match level {
        VerificationLevel::StructuralOnly => VerificationAssuranceWire::StructuralOnly,
        VerificationLevel::MerkleVerified => VerificationAssuranceWire::MerkleVerified,
        VerificationLevel::FullyVerified => VerificationAssuranceWire::FullyVerified,
        VerificationLevel::ConsensusVerified => VerificationAssuranceWire::ConsensusVerified,
    }
}

/// Map a runtime finality observation onto wire evidence.
///
/// The two variants are kept apart deliberately: only an adapter that actually
/// read a chain tip produces [`FinalityEvidence::ObservedTip`]. An adapter whose
/// chain reports deterministic finality produces
/// [`FinalityEvidence::ChainReported`], and no tip is invented for it.
pub fn finality_evidence(observation: &FinalityObservation) -> FinalityEvidence {
    match observation.observed_tip_height {
        Some(observed_tip_height) => FinalityEvidence::ObservedTip {
            confirming_block_height: observation.confirming_block_height,
            observed_tip_height,
            confirmations: observation.confirmations,
            required_confirmations: observation.required_confirmations,
        },
        None => FinalityEvidence::ChainReported {
            confirming_block_height: observation.confirming_block_height,
            confirmations: observation.confirmations,
            required_confirmations: observation.required_confirmations,
        },
    }
}

/// Map an optional runtime observation, stating explicitly when there was none.
///
/// The `None` case is a journal-reconstructed record, and it says so. It is never
/// rendered as a zero-confirmation observation, which would look like a live read
/// that found nothing.
fn finality_evidence_opt(observation: Option<&FinalityObservation>) -> FinalityEvidence {
    match observation {
        Some(o) => finality_evidence(o),
        None => FinalityEvidence::JournalRecovered,
    }
}

/// Build the materialize receipt for a completed runtime transfer.
///
/// Every field comes from the runtime's own [`csv_runtime::TransferReceipt`].
///
/// # Errors
///
/// Returns [`CsvError`] if the resulting artifact fails contract validation — for
/// example if the runtime reported a mint whose proof was only structurally
/// checked, which the contract refuses to receipt as a completed transfer.
pub fn materialize_receipt(
    receipt: &csv_runtime::TransferReceipt,
    sanad_id: &SanadId,
    source_chain: &ChainId,
    destination_chain: &ChainId,
) -> Result<TransferReceipt, CsvError> {
    let verification = match receipt.assurance {
        Some(level) => VerificationRecord::Verified {
            assurance: assurance_from_level(level),
        },
        // The runtime completed this transfer in an earlier execution and this
        // receipt was reconstructed from its journal. The journal is the authority
        // for that earlier verification; this receipt does not restate it as its own.
        None => VerificationRecord::JournalRecorded,
    };

    let body = MaterializeBody {
        transfer_id: receipt.transfer_id.clone(),
        replay_id: HashWire::from(receipt.replay_id),
        sanad_id: SanadIdWire::from(csv_hash::SanadId::new(*sanad_id.as_bytes())),
        source_chain: source_chain.to_string(),
        destination_chain: destination_chain.to_string(),
        lock_tx_hash: receipt.lock_tx_hash.clone(),
        mint_tx_hash: receipt.mint_tx_hash.clone(),
        finality: finality_evidence_opt(receipt.finality.as_ref()),
        verification,
        materialization: Some(materialization(&receipt.materialization)),
    };

    let artifact = TransferReceipt::new(
        ReceiptBody::Materialize(Box::new(body)),
        // A completed materialize is terminal for the transfer itself; what remains
        // is reading what the runtime recorded, never re-driving it.
        vec![NextAction::Status, NextAction::SettlementStatus],
        now_secs(),
    );
    artifact.validate()?;
    Ok(artifact)
}

/// Build an application receipt from the SDK's faithful projection of a
/// runtime completion. This conversion belongs at the SDK boundary, not in an
/// application: the SDK receipt is populated exclusively from the runtime
/// coordinator result.
pub fn materialize_sdk_receipt(
    receipt: &crate::transfers::TransferReceipt,
    sanad_id: &SanadId,
    source_chain: &ChainId,
    destination_chain: &ChainId,
) -> Result<TransferReceipt, CsvError> {
    let runtime_receipt = csv_runtime::TransferReceipt {
        transfer_id: receipt.transfer_id.clone(),
        replay_id: receipt.replay_id,
        lock_tx_hash: receipt.lock_tx_hash.clone(),
        mint_tx_hash: receipt.mint_tx_hash.clone(),
        materialization: receipt.materialization.clone(),
        finality: receipt.finality.clone(),
        assurance: receipt.assurance,
    };
    materialize_receipt(&runtime_receipt, sanad_id, source_chain, destination_chain)
}

/// Map destination materialization metadata onto the wire.
fn materialization(m: &csv_adapter_core::DestinationMaterialization) -> MaterializationWire {
    MaterializationWire {
        chain_id: m.chain_id.clone(),
        object_id: m.object_id.clone(),
        seal_ref: m.seal_ref.clone(),
        registry_ref: m.registry_ref.clone(),
        commitment: m.commitment.map(hex::encode),
        owner: m.owner.as_ref().map(hex::encode),
    }
}

/// Build the receipt for a completed interactive off-chain send.
///
/// `consignment` is the exact artifact handed to the recipient; the receipt binds
/// its canonical digest, so a receipt cannot be paired with a different envelope
/// than the one actually delivered.
///
/// The permitted next actions deliberately exclude resume and retry: an off-chain
/// send has no destination phase, and the contract rejects a receipt that claims
/// otherwise.
///
/// # Errors
///
/// Returns [`CsvError`] if the consignment cannot be digested or the artifact
/// fails contract validation.
pub fn send_receipt(
    transfer_id: &str,
    sanad_id: &SanadId,
    source_chain: &ChainId,
    source_seal: &csv_hash::seal::SealPoint,
    destination_seal: &csv_hash::seal::SealPoint,
    invoice_id: &[u8],
    consignment: &[u8],
) -> Result<TransferReceipt, CsvError> {
    let body = SendBody {
        transfer_id: transfer_id.to_string(),
        sanad_id: SanadIdWire::from(csv_hash::SanadId::new(*sanad_id.as_bytes())),
        source_chain: source_chain.to_string(),
        source_seal: csv_wire::SealPointWire::from(source_seal.clone()),
        destination_seal: csv_wire::SealPointWire::from(destination_seal.clone()),
        invoice_id: invoice_id.to_vec(),
        consignment_digest: consignment_digest(consignment)?,
    };

    let artifact = TransferReceipt::new(
        ReceiptBody::Send(body),
        vec![NextAction::DeliverConsignment, NextAction::Status],
        now_secs(),
    );
    artifact.validate()?;
    Ok(artifact)
}

/// Domain-separated canonical digest of a consignment's bytes.
fn consignment_digest(consignment: &[u8]) -> Result<Vec<u8>, CsvError> {
    csv_codec::canonical_hash("csv.app.consignment.v1", &consignment.to_vec())
        .map_err(|e| CsvError::RuntimeError(format!("failed to digest consignment: {e}")))
}

/// Build the lifecycle event for a single advance of a materialize transfer.
///
/// A `Pending` outcome becomes an `AwaitingFinality` event carrying the tip the
/// depth was measured against — not a bare `2/6`, which says nothing about whether
/// anyone looked at the chain.
///
/// # Errors
///
/// Returns [`CsvError`] if the event fails contract validation.
pub fn materialize_event(
    outcome: &TransferOutcome,
    sanad_id: &SanadId,
    source_chain: &ChainId,
) -> Result<TransferEvent, CsvError> {
    let sanad = SanadIdWire::from(csv_hash::SanadId::new(*sanad_id.as_bytes()));

    let (transfer_id, replay_id, phase, next_actions) = match outcome {
        TransferOutcome::Completed(receipt) => (
            receipt.transfer_id.clone(),
            Some(HashWire::from(receipt.replay_id)),
            TransferPhase::Settled {
                mint_tx_hash: receipt.mint_tx_hash.clone(),
            },
            vec![NextAction::Status, NextAction::SettlementStatus],
        ),
        TransferOutcome::Pending {
            transfer_id,
            finality,
            ..
        } => (
            transfer_id.clone(),
            None,
            TransferPhase::AwaitingFinality {
                evidence: finality_evidence(finality),
            },
            vec![NextAction::Resume, NextAction::Status],
        ),
    };

    let event = TransferEvent::new(
        TransferMode::Materialize,
        transfer_id,
        replay_id,
        sanad,
        source_chain.to_string(),
        phase,
        next_actions,
        now_secs(),
    );
    event.validate()?;
    Ok(event)
}

/// Build the recovery plan for a transfer the runtime left awaiting finality.
///
/// # Errors
///
/// Returns [`CsvError`] if the plan fails contract validation.
pub fn awaiting_finality_plan(
    transfer_id: &str,
    observation: &FinalityObservation,
) -> Result<RecoveryPlan, CsvError> {
    let plan = RecoveryPlan::new(
        transfer_id.to_string(),
        TransferMode::Materialize,
        RecoveryReason::AwaitingFinality {
            confirmations: observation.confirmations,
            required_confirmations: observation.required_confirmations,
        },
        vec![NextAction::Resume, NextAction::Status],
        now_secs(),
    );
    plan.validate()?;
    Ok(plan)
}

/// Build a runtime health report from the runtime's own health monitor output.
///
/// # Errors
///
/// Returns [`CsvError`] if the report fails contract validation — notably if it
/// would call the runtime healthy while naming a failing component.
pub fn health_report(
    health: &RuntimeHealth,
    checks: &[csv_runtime::runtime_mode::HealthCheck],
) -> Result<RuntimeHealthReport, CsvError> {
    let state = match health {
        RuntimeHealth::Healthy => RuntimeHealthState::Healthy,
        RuntimeHealth::Degraded { reason } => RuntimeHealthState::Degraded {
            reason: format!("{reason:?}"),
        },
        RuntimeHealth::Unsafe => RuntimeHealthState::Unsafe,
    };

    let components = checks
        .iter()
        .map(|check| ComponentHealth {
            component: check.component.clone(),
            healthy: check.healthy,
            detail: check.error.clone(),
        })
        .collect();

    let report = RuntimeHealthReport::new(state, components, now_secs());
    report.validate()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(confirmations: u64, tip: Option<u64>) -> FinalityObservation {
        FinalityObservation {
            confirming_block_height: 100,
            confirmations,
            required_confirmations: 6,
            observed_tip_height: tip,
        }
    }

    #[test]
    fn observed_tip_survives_the_mapping() {
        let evidence = finality_evidence(&observation(6, Some(106)));
        match evidence {
            FinalityEvidence::ObservedTip {
                observed_tip_height,
                confirmations,
                ..
            } => {
                assert_eq!(observed_tip_height, 106);
                assert_eq!(confirmations, 6);
            }
            other => panic!("expected an observed tip, got {other:?}"),
        }
        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn an_unread_tip_is_never_invented() {
        // A deterministic-finality chain read no tip. The mapping must not
        // reconstruct one from `height + confirmations`.
        let evidence = finality_evidence(&observation(u64::MAX, None));
        assert!(
            matches!(evidence, FinalityEvidence::ChainReported { .. }),
            "a chain that reported finality without a tip must not yield ObservedTip"
        );
    }

    #[test]
    fn a_missing_observation_maps_to_journal_recovered() {
        assert_eq!(
            finality_evidence_opt(None),
            FinalityEvidence::JournalRecovered
        );
        assert!(
            !finality_evidence_opt(None).is_final(),
            "an absent observation must never read as final"
        );
    }

    #[test]
    fn verification_levels_map_faithfully() {
        assert_eq!(
            assurance_from_level(VerificationLevel::StructuralOnly),
            VerificationAssuranceWire::StructuralOnly
        );
        assert_eq!(
            assurance_from_level(VerificationLevel::ConsensusVerified),
            VerificationAssuranceWire::ConsensusVerified
        );
        assert!(
            !assurance_from_level(VerificationLevel::StructuralOnly).is_cryptographic(),
            "a structural-only check must never present as cryptographic success"
        );
    }

    #[test]
    fn a_structurally_verified_mint_is_refused_by_the_contract() {
        // If the runtime ever handed back a completed mint whose proof was only
        // structurally checked, the SDK refuses to build a receipt for it rather
        // than rendering it as a success.
        let receipt = csv_runtime::TransferReceipt {
            transfer_id: "t-1".to_string(),
            replay_id: csv_hash::Hash::new([0x22; 32]),
            lock_tx_hash: "aa".repeat(32),
            mint_tx_hash: "bb".repeat(32),
            materialization: csv_adapter_core::DestinationMaterialization::unavailable("sui"),
            finality: Some(observation(6, Some(106))),
            assurance: Some(VerificationLevel::StructuralOnly),
        };

        let result = materialize_receipt(
            &receipt,
            &SanadId::new([0x11; 32]),
            &ChainId::new("bitcoin"),
            &ChainId::new("sui"),
        );
        assert!(
            result.is_err(),
            "structural-only mint must not be receipted"
        );
    }

    #[test]
    fn a_fully_verified_mint_receipts_with_its_runtime_ids() {
        let receipt = csv_runtime::TransferReceipt {
            transfer_id: "t-1".to_string(),
            replay_id: csv_hash::Hash::new([0x22; 32]),
            lock_tx_hash: "aa".repeat(32),
            mint_tx_hash: "bb".repeat(32),
            materialization: csv_adapter_core::DestinationMaterialization::unavailable("sui"),
            finality: Some(observation(6, Some(106))),
            assurance: Some(VerificationLevel::ConsensusVerified),
        };

        let artifact = materialize_receipt(
            &receipt,
            &SanadId::new([0x11; 32]),
            &ChainId::new("bitcoin"),
            &ChainId::new("sui"),
        )
        .expect("a consensus-verified mint receipts");

        assert_eq!(artifact.mode(), TransferMode::Materialize);
        assert_eq!(artifact.transfer_id(), Some("t-1"));
        assert_eq!(
            artifact.replay_id().map(|h| h.bytes.clone()),
            Some(hex::encode([0x22u8; 32]))
        );

        // Round-trips through the canonical encoding both applications share.
        let bytes = encode(&artifact).expect("encodes");
        let back: TransferReceipt = decode(&bytes).expect("decodes");
        assert_eq!(back, artifact);
    }

    #[test]
    fn a_pending_advance_becomes_an_awaiting_finality_event_with_the_tip() {
        let outcome = TransferOutcome::Pending {
            transfer_id: "t-1".to_string(),
            lock_tx_hash: "aa".repeat(32),
            finality: observation(2, Some(102)),
        };

        let event = materialize_event(
            &outcome,
            &SanadId::new([0x11; 32]),
            &ChainId::new("bitcoin"),
        )
        .expect("pending advance yields an event");

        match &event.phase {
            TransferPhase::AwaitingFinality {
                evidence:
                    FinalityEvidence::ObservedTip {
                        observed_tip_height,
                        confirmations,
                        required_confirmations,
                        ..
                    },
            } => {
                assert_eq!(*observed_tip_height, 102);
                assert_eq!(*confirmations, 2);
                assert_eq!(*required_confirmations, 6);
            }
            other => panic!("expected awaiting-finality with an observed tip, got {other:?}"),
        }
        assert!(event.next_actions.contains(&NextAction::Resume));
    }

    #[test]
    fn a_health_report_naming_a_failing_component_cannot_claim_health() {
        use csv_observability::runtime_health::DegradedReason;
        use csv_runtime::runtime_mode::HealthCheck;

        let checks = vec![HealthCheck {
            component: "replay_db".to_string(),
            healthy: false,
            error: Some("unreachable".to_string()),
            timestamp: SystemTime::now(),
        }];

        assert!(
            health_report(&RuntimeHealth::Healthy, &checks).is_err(),
            "a failing component must not be downgraded into an overall-healthy report"
        );

        let degraded = RuntimeHealth::Degraded {
            reason: DegradedReason::ReplayRegistryUnavailable,
        };
        let report = health_report(&degraded, &checks).expect("degraded report is buildable");
        assert!(report.is_operational());
        assert!(
            !health_report(&RuntimeHealth::Unsafe, &checks)
                .expect("unsafe report is buildable")
                .is_operational()
        );
    }
}
