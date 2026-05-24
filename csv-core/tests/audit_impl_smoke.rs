#![cfg(any())]
use chrono::Utc;
use csv_core::{
    proof_provenance::ProofProvenance, replay_record::ReplayState, trust_package::TrustPackage,
};

#[test]
fn smoke_types_exist() {
    let _ = TrustPackage {
        chain_id: csv_core::ChainId::new("test"),
        trusted_checkpoint: csv_core::Hash::zero(),
        checkpoint_height: 0,
        validator_commitment: vec![],
        generated_at: Utc::now(),
        expires_at: Utc::now(),
        package_signature: vec![],
        signature_scheme: csv_core::SignatureScheme::default(),
        generation_epoch: 0,
        revoked: false,
    };

    let _ = ProofProvenance {
        fetched_from: vec!["http://node".to_string()],
        observed_at: Utc::now(),
        rpc_quorum_hash: csv_core::Hash::zero(),
        runtime_version: "0.0".to_string(),
        adapter_version: "0.0".to_string(),
        trust_package_hash: None,
    };

    let _ = ReplayState::Pending;
}
