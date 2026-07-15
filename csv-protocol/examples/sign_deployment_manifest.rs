//! Operator-side deployment-manifest signing tool (RPC-006).
//!
//! Produces `deployments/deployment-manifest.sig.json` — a detached Ed25519
//! signature over the canonical CBOR of `deployments/deployment-manifest.json`.
//!
//! The signing key is an OFFLINE operator credential. It must never be committed
//! to the repository, CI, or containers. Provide it as raw 32-byte hex:
//!
//! ```bash
//! # Sign with an existing offline key (64 hex chars = 32-byte Ed25519 seed):
//! CSV_MANIFEST_SIGNING_KEY=<hex32> \
//!   cargo run -p csv-protocol --example sign_deployment_manifest -- \
//!     --signer-id csv-testnet-operator-2026-07
//!
//! # Generate a fresh key (prints the seed once to STDERR — store it offline,
//! # pin the printed public key in TRUSTED_MANIFEST_SIGNERS), then sign:
//! cargo run -p csv-protocol --example sign_deployment_manifest -- \
//!   --signer-id csv-testnet-operator-2026-07 --generate
//! ```
//!
//! After signing, pin the printed public key in
//! `csv-protocol/src/manifest_signature.rs::TRUSTED_MANIFEST_SIGNERS` and commit
//! the sidecar. `cargo test -p csv-protocol manifest` must then pass from a
//! fresh checkout.

use std::path::PathBuf;

use csv_protocol::manifest_signature::sign_manifest;
use ed25519_dalek::SigningKey;

fn main() {
    let mut signer_id = "csv-testnet-operator-2026-07".to_string();
    let mut generate = false;
    let mut manifest_dir = PathBuf::from("deployments");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--signer-id" => signer_id = args.next().expect("--signer-id needs a value"),
            "--generate" => generate = true,
            "--dir" => manifest_dir = PathBuf::from(args.next().expect("--dir needs a value")),
            other => panic!("unknown argument: {other}"),
        }
    }

    let seed: [u8; 32] = if generate {
        // Bootstrap mode: generate an EPHEMERAL testnet anchor key, sign once,
        // and drop it. The seed is deliberately NEVER printed or persisted — it
        // must not be materialized into logs, transcripts, or files. Future
        // re-signing uses an operator-held offline key via
        // CSV_MANIFEST_SIGNING_KEY (see rotation procedure in the README).
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        seed
    } else {
        let hex_seed = std::env::var("CSV_MANIFEST_SIGNING_KEY")
            .expect("set CSV_MANIFEST_SIGNING_KEY=<64 hex chars> or pass --generate");
        let bytes = hex::decode(hex_seed.trim()).expect("signing key must be hex");
        bytes.try_into().expect("signing key must be 32 bytes")
    };

    let signing_key = SigningKey::from_bytes(&seed);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let manifest_path = manifest_dir.join("deployment-manifest.json");
    let manifest_json =
        std::fs::read_to_string(&manifest_path).expect("deployment manifest must be readable");

    let signed_at = "2026-07-15T00:00:00Z".to_string();
    let sidecar = sign_manifest(&manifest_json, &signer_id, &seed, Some(signed_at))
        .expect("signing must succeed");

    let sidecar_path = manifest_dir.join("deployment-manifest.sig.json");
    let sidecar_json =
        serde_json::to_string_pretty(&sidecar).expect("sidecar must serialize") + "\n";
    std::fs::write(&sidecar_path, sidecar_json).expect("sidecar must be writable");

    eprintln!("signer_id  = {signer_id}");
    eprintln!("public_key = {public_key_hex}");
    eprintln!("wrote {}", sidecar_path.display());
    println!("{public_key_hex}");
}
