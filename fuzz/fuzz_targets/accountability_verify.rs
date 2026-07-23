#![no_main]

use csv_accountability::{EvidenceNodeId, ExecutionOutcome};
use csv_accountability_verify::{
    AlgorithmStatus, AuthenticityStatus, ReplayStatus, RevocationStatus, VerificationInput, verify,
};
use csv_testkit::AccountabilityFixture;
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let mut fixture = AccountabilityFixture::valid();
    if let Some(selector) = data.first() {
        match selector % 6 {
            0 => fixture.context.evaluation_time = fixture.mandate.expires_at,
            1 => fixture.intent.request_nonce[0] ^= 1,
            2 => fixture.executor = b"executor:other".to_vec(),
            3 => {
                fixture.receipt.outcome = ExecutionOutcome::Unknown;
                fixture.receipt.completed_at = None;
                fixture.receipt.result_commitment = None;
            }
            4 => fixture.evidence.reverse(),
            _ => {}
        }
    }

    // Exercise bounded collection handling without deriving allocation sizes
    // directly from the fuzzer input length.
    let requested_nodes = data
        .get(1..3)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
        .unwrap_or(0)
        .min(csv_accountability::MAX_EVIDENCE_NODES + 1);
    if requested_nodes > fixture.evidence.len() {
        let template = fixture.evidence[0].1.clone();
        for index in fixture.evidence.len()..requested_nodes {
            let mut node = template.clone();
            node.content_digest = csv_hash_free_digest(index);
            if let Ok(id) = node.id() {
                fixture.evidence.push((id, node));
            }
        }
        fixture.evidence.sort_by_key(|(id, _)| *id);
    }

    let authenticity: Vec<(EvidenceNodeId, AuthenticityStatus)> = fixture
        .evidence
        .iter()
        .filter(|(_, node)| node.authenticity.is_some())
        .map(|(id, _)| (*id, AuthenticityStatus::Verified))
        .collect();
    let replay_status = match data.get(3).copied().unwrap_or_default() % 3 {
        0 => ReplayStatus::Fresh,
        1 => ReplayStatus::Replayed,
        _ => ReplayStatus::Unknown,
    };

    let _ = verify(
        &fixture.context,
        VerificationInput {
            intent: &fixture.intent,
            mandate: &fixture.mandate,
            attempt: &fixture.attempt,
            receipt: &fixture.receipt,
            evidence: &fixture.evidence,
            evidence_authenticity: &authenticity,
            expected_executor: &fixture.executor,
            revocation_status: RevocationStatus::NotRevoked,
            algorithm_status: AlgorithmStatus::Allowed,
            replay_status,
            single_use_anchor: None,
            preservation_envelopes: &[],
            preservation_authenticity: &[],
            preservation_algorithm_statuses: &[],
        },
    );
});

fn csv_hash_free_digest(index: usize) -> [u8; 32] {
    let mut digest = [1_u8; 32];
    digest[..core::mem::size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
    digest
}
