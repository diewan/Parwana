//! Terminal rendering of application-contract artifacts.
//!
//! The CLI is the reference presentation: it shows the runtime lifecycle by
//! rendering the same typed artifacts `csv-wallet` renders, rather than by
//! formatting runtime internals its own way. Everything printed here is read off
//! a `csv_sdk::contract` artifact that the runtime produced and that already
//! passed the contract's own validation.
//!
//! Terminal formatting is deliberately *not* part of the contract. It lives here,
//! on the presentation side, and nothing downstream parses it.

use csv_sdk::contract::{
    FinalityEvidence, NextAction, ReceiptBody, RecoveryPlan, RecoveryReason, RuntimeHealthReport,
    RuntimeHealthState, SigningIntent, TransferEvent, TransferPhase, TransferReceipt,
    VerificationAssuranceWire, VerificationRecord,
};

use crate::output;

/// Render a transfer receipt.
pub fn transfer_receipt(receipt: &TransferReceipt) {
    match &receipt.body {
        ReceiptBody::Send(b) => {
            output::success("Interactive off-chain send completed");
            output::kv("Transfer ID", &b.transfer_id);
            output::kv("Sanad", &b.sanad_id.bytes);
            output::kv("Source Chain", &b.source_chain);
            output::kv("Source Seal", &b.source_seal.id);
            output::kv("Destination Seal", &b.destination_seal.id);
            output::kv("Invoice ID", &hex::encode(&b.invoice_id));
            output::kv("Consignment Digest", &hex::encode(&b.consignment_digest));
        }
        ReceiptBody::Invoice(b) => {
            output::success("Invoice issued");
            output::kv("Invoice ID", &hex::encode(&b.invoice_id));
            output::kv("Destination Chain", &b.destination_chain);
            output::kv("Bound Seal", &b.bound_seal.id);
            output::kv("Schema", &b.schema);
            output::kv("Nonce", &b.nonce.to_string());
        }
        ReceiptBody::Accept(b) => {
            output::success("Consignment accepted and ownership recorded");
            output::kv("Sanad", &b.sanad_id.bytes);
            output::kv("Destination Chain", &b.destination_chain);
            output::kv("Destination Seal", &b.destination_seal.id);
            assurance(b.assurance);
            finality(&b.finality);
        }
        ReceiptBody::Materialize(b) => {
            if b.mint_tx_hash.is_empty() {
                output::info(&format!(
                    "Transfer {} locked; not yet minted.",
                    b.transfer_id
                ));
            } else {
                output::success(&format!(
                    "Transfer {} completed. Sanad locked on source chain and minted on destination chain.",
                    b.transfer_id
                ));
            }
            output::kv("Transfer ID", &b.transfer_id);
            output::kv("Replay ID", &b.replay_id.bytes);
            output::kv("Sanad", &b.sanad_id.bytes);
            output::kv("Source Chain", &b.source_chain);
            output::kv("Destination Chain", &b.destination_chain);
            output::kv("Lock Tx Hash", &b.lock_tx_hash);
            if !b.mint_tx_hash.is_empty() {
                output::kv("Mint Tx Hash", &b.mint_tx_hash);
            }
            verification(&b.verification);
            finality(&b.finality);
            if let Some(m) = &b.materialization {
                materialization(m);
            }
        }
    }
    next_actions(&receipt.next_actions);
}

/// Render a transfer lifecycle event.
pub fn transfer_event(event: &TransferEvent) {
    match &event.phase {
        TransferPhase::Admitted => output::info("Admitted by the runtime."),
        TransferPhase::SealOwnershipVerified { seal_id } => {
            output::success("Seal ownership verified");
            output::kv("Seal", seal_id);
        }
        TransferPhase::Locked { lock_tx_hash } => {
            output::success("Source seal consumed by an on-chain lock");
            output::kv("Lock Tx Hash", lock_tx_hash);
        }
        TransferPhase::AwaitingFinality { evidence } => {
            output::info(&format!(
                "Transfer {} locked — awaiting finality.",
                event.transfer_id
            ));
            finality(evidence);
        }
        TransferPhase::FinalityReached { evidence } => {
            output::success("Source lock reached the required finality depth");
            finality(evidence);
        }
        TransferPhase::ProofBuilt { proof_hash } => {
            output::success("Inclusion and finality proof built");
            output::kv("Proof Hash", &hex::encode(proof_hash));
        }
        TransferPhase::ProofVerified { assurance: a } => {
            output::success("Canonical verifier accepted the proof bundle");
            assurance(*a);
        }
        TransferPhase::SubmittedToDestination { destination_chain } => {
            output::info(&format!("Proof submitted to {destination_chain}."));
        }
        TransferPhase::Settled { mint_tx_hash } => {
            output::success("Destination chain confirmed the materialization");
            output::kv("Mint Tx Hash", mint_tx_hash);
        }
        TransferPhase::RecoveryRequired { reason } => {
            output::warning(&format!("Transfer needs recovery: {reason}"));
        }
        TransferPhase::Failed { code, message } => {
            output::error(&format!("Transfer failed [{code}]: {message}"));
        }
    }
    output::kv("Transfer ID", &event.transfer_id);
    next_actions(&event.next_actions);
}

/// Render a recovery plan.
pub fn recovery_plan(plan: &RecoveryPlan) {
    match &plan.reason {
        RecoveryReason::AwaitingFinality {
            confirmations,
            required_confirmations,
        } => output::info(&format!(
            "Transfer {} is awaiting finality ({confirmations}/{required_confirmations} confirmations).",
            plan.transfer_id
        )),
        RecoveryReason::FailedAtPhase { phase, error } => output::warning(&format!(
            "Transfer {} failed at {phase}: {error}",
            plan.transfer_id
        )),
        RecoveryReason::Interrupted { phase } => output::warning(&format!(
            "Transfer {} was interrupted at {phase}.",
            plan.transfer_id
        )),
    }
    next_actions(&plan.permitted_actions);
}

/// Show the user what a signature will actually authorize, before it is produced.
///
/// This is the whole point of a typed intent: the sentence printed here is bound
/// into the intent's digest alongside the payload, so it cannot be shown for one
/// operation and used for another.
pub fn signing_intent(intent: &SigningIntent) {
    output::header("Signature Requested");
    output::kv("Operation", &format!("{:?}", intent.operation));
    output::kv("Chain", &format!("{} ({})", intent.chain, intent.network));
    output::kv("Sanad", &intent.sanad_id.bytes);
    output::kv("Seal", &intent.seal.id);
    output::kv("Recipient", &intent.recipient);
    output::kv(
        "Value",
        &format!("{} {}", intent.value.amount, intent.value.unit),
    );
    output::kv("Payload Digest", &hex::encode(&intent.payload_digest));
    output::kv(
        "Expires",
        &format!(
            "{}s from issue (unix {})",
            intent.expires_at.saturating_sub(intent.created_at),
            intent.expires_at
        ),
    );
    output::warning(&intent.summary);
}

/// Render a runtime health report.
pub fn health_report(report: &RuntimeHealthReport) {
    match &report.state {
        RuntimeHealthState::Healthy => output::success("Runtime health: healthy"),
        RuntimeHealthState::Degraded { reason } => {
            output::warning(&format!("Runtime health: degraded ({reason})"))
        }
        // Never softened into a warning: the runtime will not execute authority
        // operations in this state, and the operator needs to know that.
        RuntimeHealthState::Unsafe => {
            output::danger("Runtime health: UNSAFE — authority operations will not proceed")
        }
    }
    for component in &report.components {
        let status = if component.healthy { "ok" } else { "FAILING" };
        let detail = component
            .detail
            .as_deref()
            .map(|d| format!(" — {d}"))
            .unwrap_or_default();
        output::kv(&component.component, &format!("{status}{detail}"));
    }
}

/// Render the source-lock finality evidence, always naming its provenance.
fn finality(evidence: &FinalityEvidence) {
    match evidence {
        FinalityEvidence::ObservedTip {
            confirming_block_height,
            observed_tip_height,
            confirmations,
            required_confirmations,
        } => {
            output::kv(
                "Finality",
                &format!("{confirmations}/{required_confirmations} confirmations"),
            );
            // The tip is the point: a depth without the tip it was measured against
            // is not evidence that anyone looked at the chain.
            output::kv(
                "Observed Tip",
                &format!(
                    "height {observed_tip_height} (lock confirmed in block {confirming_block_height})"
                ),
            );
        }
        FinalityEvidence::ChainReported {
            confirming_block_height,
            confirmations,
            required_confirmations,
        } => {
            output::kv(
                "Finality",
                &format!(
                    "{confirmations}/{required_confirmations} confirmations, reported by the chain \
                     (deterministic finality; no tip height read)"
                ),
            );
            output::kv("Confirming Block", &confirming_block_height.to_string());
        }
        FinalityEvidence::JournalRecovered => {
            output::kv(
                "Finality",
                "recovered from the runtime journal — not re-observed on this path",
            );
        }
    }
}

/// Render what the verifier established, and when.
fn verification(record: &VerificationRecord) {
    match record {
        VerificationRecord::Verified { assurance: a } => assurance(*a),
        VerificationRecord::JournalRecorded => output::kv(
            "Verification",
            "recorded in the runtime journal by an earlier execution — not re-verified here",
        ),
        VerificationRecord::NotYetVerified => output::kv("Verification", "not yet performed"),
    }
}

/// Render a verification assurance level.
///
/// A structural-only result is printed as a warning, never as a success: it is a
/// parse, not a proof.
fn assurance(level: VerificationAssuranceWire) {
    let label = match level {
        VerificationAssuranceWire::StructuralOnly => {
            "structural only — NOT cryptographically verified"
        }
        VerificationAssuranceWire::MerkleVerified => "merkle inclusion verified",
        VerificationAssuranceWire::FullyVerified => "fully verified (cryptographic)",
        VerificationAssuranceWire::ConsensusVerified => {
            "consensus verified (cryptographic + finality threshold met)"
        }
    };
    if level.is_cryptographic() {
        output::kv("Verification", label);
    } else {
        output::warning(&format!("Verification: {label}"));
    }
}

/// Render destination materialization metadata.
fn materialization(m: &csv_sdk::contract::MaterializationWire) {
    output::kv("Destination Chain", &m.chain_id);
    if let Some(object_id) = &m.object_id {
        output::kv("Destination Object", object_id);
    }
    if let Some(seal_ref) = &m.seal_ref {
        output::kv("Destination Seal", seal_ref);
    }
    if let Some(registry_ref) = &m.registry_ref {
        output::kv("Destination Registry", registry_ref);
    }
    if let Some(commitment) = &m.commitment {
        output::kv("Destination Commitment", commitment);
    }
    if let Some(owner) = &m.owner {
        output::kv("Destination Owner", owner);
    }
}

/// Render the actions the runtime will honor next.
///
/// The CLI offers exactly these, so a user is never pointed at a command the
/// runtime would reject — an off-chain send, for instance, never suggests `resume`.
fn next_actions(actions: &[NextAction]) {
    if actions.is_empty() {
        return;
    }
    let rendered: Vec<&str> = actions
        .iter()
        .map(|action| match action {
            NextAction::DeliverInvoice => "deliver the invoice blob to the sender (off-band)",
            NextAction::DeliverConsignment => "deliver the consignment to the recipient (off-band)",
            NextAction::Accept => "csv cross-chain accept <consignment>",
            NextAction::Resume => "csv cross-chain resume <transfer-id>",
            NextAction::Retry => "csv cross-chain retry <transfer-id>",
            NextAction::Status => "csv cross-chain status <transfer-id>",
            NextAction::SettlementStatus => "csv cross-chain settlement-status <sanad-id>",
        })
        .collect();
    output::kv("Next", &rendered.join("\n                            "));
}
