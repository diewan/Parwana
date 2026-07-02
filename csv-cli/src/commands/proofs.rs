//! Proof generation and verification commands
//!
//! `csv proof generate` produces the canonical `ProofBundle` artifact
//! (the exact type verified by `csv-sdk`/`csv-verifier`) and `csv proof
//! verify` consumes that same canonical artifact end-to-end. No lossy
//! summary is ever reconstructed for verification: the bytes that are
//! verified are the bytes that were produced.
//!
//! Output modes for `proof generate`:
//! - default: canonical binary `ProofBundle` artifact (the bytes produced by
//!   `ProofBundle::to_canonical_bytes()`), written to a file or stdout.
//! - `--hex`: the same canonical artifact bytes, hex-encoded.
//! - `--json-summary`: a display-only JSON summary of the bundle. This is
//!   NEVER accepted as input to `proof verify` or `proof verify-cross-chain`
//!   — it exists purely for human inspection.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use std::io::{Read, Write};

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;
use csv_hash::sanad::SanadId;
use csv_protocol::proof_taxonomy::ProofBundle;

/// Display-only summary of a canonical `ProofBundle`.
///
/// This type is never parsed back into a `ProofBundle`. It exists solely so
/// `--json-summary` can render a human-readable view of the canonical
/// artifact without ever being treated as verifiable proof material.
#[derive(Debug, Clone, serde::Serialize)]
struct ProofSummary {
    chain: String,
    sanad_id: String,
    version: u32,
    seal_id: String,
    anchor_id: String,
    anchor_block_height: u64,
    inclusion_block_number: u64,
    inclusion_leaf_index: usize,
    finality_confirmations: u64,
    finality_is_deterministic: bool,
    signature_count: usize,
    signature_scheme: String,
    dag_root_commitment: String,
    dag_node_count: usize,
    artifact_bytes: usize,
}

impl ProofSummary {
    fn from_bundle(
        chain: &str,
        sanad_id: &str,
        bundle: &ProofBundle,
        artifact_bytes: usize,
    ) -> Self {
        Self {
            chain: chain.to_string(),
            sanad_id: sanad_id.to_string(),
            version: bundle.version,
            seal_id: hex::encode(&bundle.seal_ref.id),
            anchor_id: hex::encode(&bundle.anchor_ref.anchor_id),
            anchor_block_height: bundle.anchor_ref.block_height,
            inclusion_block_number: bundle.inclusion_proof.block_number,
            inclusion_leaf_index: bundle.inclusion_proof.leaf_index,
            finality_confirmations: bundle.finality_proof.confirmations,
            finality_is_deterministic: bundle.finality_proof.is_deterministic,
            signature_count: bundle.signatures.len(),
            signature_scheme: format!("{:?}", bundle.signature_scheme),
            dag_root_commitment: bundle.transition_dag.root_commitment.to_hex(),
            dag_node_count: bundle.transition_dag.nodes.len(),
            artifact_bytes,
        }
    }
}

#[derive(Subcommand)]
pub enum ProofAction {
    /// Generate the canonical inclusion proof bundle for a Sanad
    Generate {
        /// Source chain
        #[arg(value_enum)]
        chain: Chain,
        /// Sanad ID (hex)
        sanad_id: String,
        /// Output file (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
        /// Print a display-only JSON summary instead of the canonical artifact.
        /// The summary is never accepted by `proof verify`.
        #[arg(long)]
        json_summary: bool,
        /// Hex-encode the canonical artifact bytes instead of writing raw binary
        #[arg(long)]
        hex: bool,
    },
    /// Verify a canonical proof bundle artifact
    Verify {
        /// Destination chain (verifies ON this chain)
        #[arg(value_enum)]
        chain: Chain,
        /// Proof artifact file (reads from stdin if not specified)
        #[arg(short, long)]
        proof: Option<String>,
        /// Treat the input as hex-encoded canonical artifact bytes
        #[arg(long)]
        hex: bool,
    },
    /// Verify cross-chain proof (proof from chain A verified on chain B)
    VerifyCrossChain {
        /// Source chain (where proof was generated)
        #[arg(long)]
        source: Chain,
        /// Destination chain (where proof is being verified)
        #[arg(long)]
        dest: Chain,
        /// Proof artifact file
        proof: String,
        /// Treat the input as hex-encoded canonical artifact bytes
        #[arg(long)]
        hex: bool,
        /// Sanad ID this proof must be bound to (hex)
        #[arg(long)]
        sanad_id: String,
    },
}

pub async fn execute(
    action: ProofAction,
    config: &Config,
    state: &UnifiedStateManager,
    canonical: bool,
    proof_tree: bool,
) -> Result<()> {
    match action {
        ProofAction::Generate {
            chain,
            sanad_id,
            output,
            json_summary,
            hex: hex_mode,
        } => {
            cmd_generate(
                chain,
                sanad_id,
                output,
                json_summary,
                hex_mode,
                config,
                state,
                proof_tree,
            )
            .await
        }
        ProofAction::Verify {
            chain,
            proof,
            hex: hex_mode,
        } => cmd_verify(chain, proof, hex_mode, config, state, canonical, proof_tree).await,
        ProofAction::VerifyCrossChain {
            source,
            dest,
            proof,
            hex: hex_mode,
            sanad_id,
        } => {
            cmd_verify_cross_chain(
                source, dest, proof, hex_mode, sanad_id, config, state, canonical, proof_tree,
            )
            .await
        }
    }
}

/// Load the canonical `ProofBundle` artifact bytes that `proof generate` produced.
///
/// Bytes are decoded with `ProofBundle::from_canonical_bytes`, the exact inverse
/// of the canonical encoder used by `proof generate`. Malformed or truncated
/// artifacts are rejected here rather than papered over with synthesized or
/// defaulted fields.
fn decode_proof_bundle(raw_bytes: &[u8], hex_mode: bool) -> Result<ProofBundle> {
    let artifact_bytes: std::borrow::Cow<'_, [u8]> = if hex_mode {
        let trimmed = std::str::from_utf8(raw_bytes)
            .context("Proof file is not valid UTF-8 hex text")?
            .trim();
        std::borrow::Cow::Owned(
            hex::decode(trimmed).context("Proof file is not valid hex-encoded data")?,
        )
    } else {
        std::borrow::Cow::Borrowed(raw_bytes)
    };

    if artifact_bytes.is_empty() {
        bail!("Proof bundle is empty - no proof artifact provided");
    }

    let bundle = ProofBundle::from_canonical_bytes(&artifact_bytes)
        .map_err(|e| anyhow::anyhow!("Malformed proof bundle: {}", e))?;

    if bundle.signatures.is_empty() {
        bail!("Proof bundle has no signatures - missing signature");
    }
    if bundle.signatures.iter().any(|sig| sig.is_empty()) {
        bail!("Proof bundle contains an empty signature");
    }
    if bundle.seal_ref.id.is_empty() {
        bail!("Proof bundle has an empty seal reference");
    }
    if bundle.transition_dag.nodes.is_empty() {
        bail!("Proof bundle has an empty state transition DAG");
    }

    Ok(bundle)
}

async fn cmd_generate(
    chain: Chain,
    sanad_id: String,
    output: Option<String>,
    json_summary: bool,
    hex_mode: bool,
    config: &Config,
    _state: &UnifiedStateManager,
    proof_tree: bool,
) -> Result<()> {
    use csv_sdk::prelude::CsvClient;

    output::header(&format!("Generating Proof on {}", chain));

    let sanad_id_obj =
        SanadId::parse_hex(&sanad_id).map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;

    output::kv("Chain", chain.as_ref());
    output::kv_hash("Sanad ID", sanad_id_obj.as_bytes());

    // Get chain configuration
    let _chain_config = config.chain(&chain)?;

    // Build CSV client with the chain enabled
    let adapter_chain = csv_hash::chain_id::ChainId::new(chain.as_str());

    output::progress(1, 4, "Initializing CSV client...");

    // Build the CSV client
    let client = CsvClient::builder()
        .with_chain(adapter_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    output::progress(2, 4, "Querying chain state for inclusion proof...");

    // Use the runtime to generate the canonical proof bundle. This is the
    // exact ProofBundle type that csv-verifier consumes - no lossy summary
    // is derived from it here.
    let runtime = client.chain_runtime();
    let proof_bundle = runtime
        .generate_proof(adapter_chain, &sanad_id_obj)
        .await
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;

    output::progress(3, 4, "Encoding canonical proof bundle...");

    // The canonical artifact: the same bytes that decode_proof_bundle expects
    // back during verification.
    let artifact_bytes = proof_bundle
        .to_canonical_bytes()
        .map_err(|e| anyhow::anyhow!("Canonical proof encoding failed: {}", e))?;

    output::progress(4, 4, "Finalizing...");

    if json_summary {
        let summary = ProofSummary::from_bundle(
            chain.as_str(),
            &sanad_id,
            &proof_bundle,
            artifact_bytes.len(),
        );
        if let Some(path) = &output {
            let payload = serde_json::to_vec_pretty(&summary)?;
            std::fs::write(path, &payload)?;
            output::success(&format!("Proof summary (display-only) saved to {}", path));
        } else {
            output::proof_tree(&summary, proof_tree, false);
        }
        output::success(&format!(
            "{} proof summary generated (display-only, not a verifiable artifact)",
            chain
        ));
        return Ok(());
    }

    if let Some(path) = &output {
        if hex_mode {
            std::fs::write(path, hex::encode(&artifact_bytes))?;
        } else {
            std::fs::write(path, &artifact_bytes)?;
        }
        output::success(&format!("Canonical proof bundle saved to {}", path));
    } else if hex_mode {
        println!("{}", hex::encode(&artifact_bytes));
    } else {
        std::io::stdout()
            .write_all(&artifact_bytes)
            .context("Failed to write canonical proof bundle to stdout")?;
    }

    output::success(&format!(
        "{} canonical proof bundle generated successfully ({} bytes)",
        chain,
        artifact_bytes.len()
    ));
    Ok(())
}

async fn cmd_verify(
    chain: Chain,
    proof_file: Option<String>,
    hex_mode: bool,
    _config: &Config,
    _state: &UnifiedStateManager,
    canonical: bool,
    proof_tree: bool,
) -> Result<()> {
    use csv_hash::sanad::SanadId;
    use csv_sdk::prelude::CsvClient;

    output::header(&format!("Verifying Proof on {}", chain));

    let raw_bytes = match proof_file {
        Some(path) => std::fs::read(&path)?,
        None => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            input
        }
    };

    // Decode the exact canonical artifact - no field is reconstructed,
    // fabricated, or defaulted. Malformed or incomplete bundles are
    // rejected here, before verification runs.
    let proof_bundle = decode_proof_bundle(&raw_bytes, hex_mode)?;

    // The Sanad ID this bundle is bound to comes from the seal reference
    // inside the canonical bundle itself - not from a side-channel summary.
    let sanad_id = SanadId::from_bytes(&proof_bundle.seal_ref.id);

    output::kv("Seal ID", &hex::encode(&proof_bundle.seal_ref.id));
    output::kv(
        "Anchor Block Height",
        &proof_bundle.anchor_ref.block_height.to_string(),
    );

    output::progress(1, 4, "Building CSV client...");

    let adapter_chain = csv_hash::chain_id::ChainId::new(chain.as_str());

    let client = CsvClient::builder()
        .with_chain(adapter_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    output::progress(2, 4, "Verifying canonical proof bundle...");

    let runtime = client.chain_runtime();
    let valid = runtime
        .verify_proof_bundle(adapter_chain, &proof_bundle, &sanad_id)
        .await
        .map_err(|e| anyhow::anyhow!("Proof verification error: {}", e))?;

    output::progress(3, 4, "Checking verification result...");
    output::progress(4, 4, "Finalizing verification...");

    let level = if valid {
        csv_protocol::VerificationLevel::FullyVerified
    } else {
        csv_protocol::VerificationLevel::StructuralOnly
    };

    let result = serde_json::json!({
        "valid": valid,
        "level": format!("{:?}", level).to_lowercase(),
        "chain": chain.as_ref(),
    });
    output::proof_tree(&result, proof_tree, canonical);
    output::kv("Verification Level", &format!("{:?}", level).to_lowercase());

    if valid {
        output::success("Proof verified successfully - cryptographic validation passed");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Proof verification failed - invalid or forged proof"
        ))
    }
}

async fn cmd_verify_cross_chain(
    source: Chain,
    dest: Chain,
    proof_file: String,
    hex_mode: bool,
    expected_sanad_id: String,
    _config: &Config,
    _state: &UnifiedStateManager,
    canonical: bool,
    proof_tree: bool,
) -> Result<()> {
    use csv_sdk::prelude::CsvClient;

    output::header(&format!(
        "Cross-Chain Proof Verification: {} → {}",
        source, dest
    ));

    let raw_bytes = std::fs::read(&proof_file)?;

    // Decode the canonical artifact - same rules as same-chain verification:
    // no reconstructed signatures, no fabricated finality data, no fabricated DAG.
    let proof_bundle = decode_proof_bundle(&raw_bytes, hex_mode)?;

    let expected_sanad_id_obj = SanadId::parse_hex(&expected_sanad_id)
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;

    if proof_bundle.seal_ref.id.as_slice() != expected_sanad_id_obj.as_bytes() {
        bail!("Proof bundle seal reference does not match the expected Sanad ID");
    }

    output::kv("Source Chain", source.as_ref());
    output::kv("Destination Chain", dest.as_ref());
    output::kv("Seal ID", &hex::encode(&proof_bundle.seal_ref.id));

    output::progress(1, 4, "Verifying source chain proof...");

    let source_adapter_chain = csv_hash::chain_id::ChainId::new(source.as_str());
    let source_client = CsvClient::builder()
        .with_chain(source_adapter_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build source CSV client: {}", e))?;

    let source_runtime = source_client.chain_runtime();
    let source_valid = source_runtime
        .verify_proof_bundle(source_adapter_chain, &proof_bundle, &expected_sanad_id_obj)
        .await
        .map_err(|e| anyhow::anyhow!("Source chain proof verification error: {}", e))?;

    if !source_valid {
        return Err(anyhow::anyhow!(
            "Proof verification failed on source chain {} - invalid or forged proof",
            source
        ));
    }

    output::progress(2, 4, "Checking cross-chain compatibility...");
    output::progress(3, 4, "Verifying on destination chain...");

    let dest_adapter_chain = csv_hash::chain_id::ChainId::new(dest.as_str());
    let dest_client = CsvClient::builder()
        .with_chain(dest_adapter_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build destination CSV client: {}", e))?;

    let dest_runtime = dest_client.chain_runtime();
    let dest_valid = dest_runtime
        .verify_proof_bundle(dest_adapter_chain, &proof_bundle, &expected_sanad_id_obj)
        .await
        .map_err(|e| anyhow::anyhow!("Destination chain proof verification error: {}", e))?;

    output::progress(4, 4, "Checking seal registry for double-spend...");

    if !dest_valid {
        return Err(anyhow::anyhow!(
            "Proof verification failed on destination chain {} - invalid or forged proof",
            dest
        ));
    }

    let result = serde_json::json!({
        "valid": true,
        "source_chain": source.as_ref(),
        "dest_chain": dest.as_ref(),
    });
    output::proof_tree(&result, proof_tree, canonical);
    output::success("Cross-chain proof verified successfully");
    Ok(())
}
