//! RPC-006: the shipped deployment manifest must verify from a fresh checkout,
//! and tampering with it must fail closed.

use std::path::PathBuf;

use csv_protocol::manifest_signature::{
    ManifestSignatureSidecar, ManifestVerificationError, load_verified_manifest_from_dir,
    verify_manifest,
};

fn deployments_dir() -> PathBuf {
    // csv-protocol/ -> workspace root -> deployments/
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("csv-protocol lives below the workspace root")
        .join("deployments")
}

#[test]
fn shipped_manifest_verifies_against_pinned_signer() {
    let dir = deployments_dir();
    let verified = load_verified_manifest_from_dir(&dir, false)
        .expect("shipped manifest must verify from a fresh checkout");
    assert_eq!(
        verified.signer_id.as_deref(),
        Some("csv-testnet-operator-2026-07")
    );
}

#[test]
fn tampered_shipped_manifest_fails_closed() {
    let dir = deployments_dir();
    let json = std::fs::read_to_string(dir.join("deployment-manifest.json")).unwrap();
    let sidecar: ManifestSignatureSidecar = serde_json::from_str(
        &std::fs::read_to_string(dir.join("deployment-manifest.sig.json")).unwrap(),
    )
    .unwrap();

    // Substitute an attacker contract address; the pinned signature must reject it.
    let tampered = json.replace(
        "0xba3838a7105b0131d418ac344bf999f420b12938",
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    assert_ne!(
        tampered, json,
        "tamper string must actually change the manifest"
    );
    assert!(matches!(
        verify_manifest(&tampered, &sidecar),
        Err(ManifestVerificationError::InvalidSignature(_))
    ));
}

#[test]
fn ethereum_block_discrepancy_is_reconciled() {
    let dir = deployments_dir();
    let json = std::fs::read_to_string(dir.join("deployment-manifest.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let eth = &value["deployments"]["ethereum"];
    let top = eth["deployment_block"].as_str().unwrap();
    let contract = eth["contracts"][0]["block_number"].as_str().unwrap();
    assert_eq!(
        top, contract,
        "top-level deployment_block must match the CSVSeal contract block_number"
    );
    assert_eq!(top, "11225104");
}
