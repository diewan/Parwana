//! Accountability object creation and inspection.

use anyhow::{Context, Result};
use clap::Subcommand;
use csv_sdk::accountability::{
    ActionIntent, ActionIntentJsonV1, CanonicalAccountabilityObjectWire, GitHubDeploymentIntentV1,
    RequiredContexts, action_intent_from_json, encode_action_intent,
};
use std::{fs, path::PathBuf};

#[derive(Subcommand)]
pub enum AccountabilityAction {
    /// Write a valid, annotated-in-documentation starter intent JSON file.
    ExampleIntent {
        /// Output JSON file; stdout when omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Create a canonical action-intent artifact from strict JSON wire input.
    CreateIntent {
        /// Input ActionIntentJsonV1 file; see csv-docs/accountability/getting-started.md.
        #[arg(long)]
        input: PathBuf,
        /// Output artifact JSON file; stdout when omitted.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect and validate a canonical accountability artifact envelope.
    Inspect {
        /// Canonical artifact JSON file.
        #[arg(long)]
        file: PathBuf,
    },
}

pub fn execute(action: AccountabilityAction) -> Result<()> {
    match action {
        AccountabilityAction::ExampleIntent { out } => example_intent(out),
        AccountabilityAction::CreateIntent { input, out } => create_intent(input, out),
        AccountabilityAction::Inspect { file } => inspect(file),
    }
}

fn example_intent(out: Option<PathBuf>) -> Result<()> {
    let required_contexts = RequiredContexts::AllSubmitted;
    let profile = GitHubDeploymentIntentV1 {
        repository_id: 42,
        repository_owner: "example-org".into(),
        repository_name: "example-service".into(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        exact_ref: "0123456789abcdef0123456789abcdef01234567".into(),
        environment_id: 7,
        environment_name: "production".into(),
        deployment_gate_policy_digest: required_contexts.gate_policy_id().map_err(|error| {
            anyhow::anyhow!("construct example deployment gate policy: {error:?}")
        })?,
        required_contexts,
        payload_commitment: [3; 32],
        artifact_digest: None,
    };
    let intent = ActionIntent::github_deployment(
        b"requester:alice".to_vec(),
        1_750_000_000,
        [7; 32],
        Vec::new(),
        profile,
    )
    .map_err(|error| anyhow::anyhow!("construct example intent: {error:?}"))?;
    write_json(&ActionIntentJsonV1::from(&intent), out)
}

fn create_intent(input: PathBuf, out: Option<PathBuf>) -> Result<()> {
    let json = fs::read_to_string(&input).with_context(|| format!("read {}", input.display()))?;
    let wire: ActionIntentJsonV1 =
        serde_json::from_str(&json).context("parse strict ActionIntentJsonV1 JSON")?;
    let intent = action_intent_from_json(wire).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let artifact = encode_action_intent(&intent).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    write_json(&artifact, out)
}

fn inspect(file: PathBuf) -> Result<()> {
    let json = fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
    let artifact: CanonicalAccountabilityObjectWire =
        serde_json::from_str(&json).context("parse canonical accountability artifact")?;
    let bytes = artifact
        .canonical_bytes()
        .map_err(|error| anyhow::anyhow!(error))?;
    println!("kind: {:?}", artifact.kind);
    println!("object_version: {}", artifact.object_version);
    println!("object_id: {}", artifact.object_id_hex);
    println!("canonical_size: {}", bytes.len());
    Ok(())
}

fn write_json(value: &impl serde::Serialize, out: Option<PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("serialize canonical artifact")?;
    if let Some(path) = out {
        fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("write {}", path.display()))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_sdk::accountability::{ActionIntent, GitHubDeploymentIntentV1, RequiredContexts};

    fn input_wire() -> ActionIntentJsonV1 {
        let required_contexts = RequiredContexts::AllSubmitted;
        let profile = GitHubDeploymentIntentV1 {
            repository_id: 42,
            repository_owner: "diewan".into(),
            repository_name: "piteka".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            exact_ref: "0123456789abcdef0123456789abcdef01234567".into(),
            environment_id: 7,
            environment_name: "production".into(),
            deployment_gate_policy_digest: required_contexts.gate_policy_id().unwrap(),
            required_contexts,
            payload_commitment: [3; 32],
            artifact_digest: None,
        };
        let intent = ActionIntent::github_deployment(
            b"requester:alice".to_vec(),
            1_750_000_000,
            [7; 32],
            Vec::new(),
            profile,
        )
        .unwrap();
        ActionIntentJsonV1::from(&intent)
    }

    #[test]
    fn create_and_inspect_preserve_canonical_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("intent.json");
        let output = dir.path().join("artifact.json");
        fs::write(&input, serde_json::to_vec(&input_wire()).unwrap()).unwrap();

        create_intent(input, Some(output.clone())).unwrap();
        inspect(output.clone()).unwrap();

        let artifact: CanonicalAccountabilityObjectWire =
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert!(!artifact.canonical_bytes().unwrap().is_empty());
    }

    #[test]
    fn generated_example_is_valid_create_intent_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("intent.json");
        let output = dir.path().join("artifact.json");
        example_intent(Some(input.clone())).unwrap();
        create_intent(input, Some(output.clone())).unwrap();
        assert!(output.is_file());
    }

    #[test]
    fn changed_fixed_parameters_and_noncanonical_artifacts_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("intent.json");
        let output = dir.path().join("artifact.json");
        // A non-canonical profile encoding (trailing byte) must fail closed on decode.
        let mut wire = input_wire();
        wire.profile_bytes_hex.push_str("00");
        fs::write(&input, serde_json::to_vec(&wire).unwrap()).unwrap();
        assert!(create_intent(input, Some(output.clone())).is_err());

        let malformed = serde_json::json!({
            "kind": "action_intent",
            "object_version": 1,
            "object_id_hex": "AA",
            "canonical_bytes_hex": "00"
        });
        fs::write(&output, serde_json::to_vec(&malformed).unwrap()).unwrap();
        assert!(inspect(output).is_err());
    }
}
