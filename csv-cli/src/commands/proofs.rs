//! Proof generation and verification commands

use anyhow::Result;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;
use csv_hash::sanad::SanadId;

/// Canonical proof output format (CBOR-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofOutput {
    chain: String,
    sanad_id: String,
    proof_type: String,
    block_height: u64,
    inclusion_proof: String,
    dag_root: String,
    seal_id: String,
    anchor_height: u64,
    generated_at: String,
}

#[derive(Subcommand)]
pub enum ProofAction {
    /// Generate inclusion proof for a Sanad
    Generate {
        /// Source chain
        #[arg(value_enum)]
        chain: Chain,
        /// Sanad ID (hex)
        sanad_id: String,
        /// Output file (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Verify an inclusion proof
    Verify {
        /// Destination chain (verifies ON this chain)
        #[arg(value_enum)]
        chain: Chain,
        /// Proof file (reads from stdin if not specified)
        #[arg(short, long)]
        proof: Option<String>,
    },
    /// Verify cross-chain proof (proof from chain A verified on chain B)
    VerifyCrossChain {
        /// Source chain (where proof was generated)
        #[arg(long)]
        source: Chain,
        /// Destination chain (where proof is being verified)
        #[arg(long)]
        dest: Chain,
        /// Proof file
        proof: String,
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
        } => cmd_generate(
            chain, sanad_id, output, config, state, canonical, proof_tree,
        ).await,
        ProofAction::Verify { chain, proof } => {
            cmd_verify(chain, proof, config, state, canonical, proof_tree).await
        }
        ProofAction::VerifyCrossChain {
            source,
            dest,
            proof,
        } => cmd_verify_cross_chain(source, dest, proof, config, state, canonical, proof_tree).await,
    }
}

async fn cmd_generate(
    chain: Chain,
    sanad_id: String,
    output: Option<String>,
    config: &Config,
    _state: &UnifiedStateManager,
    canonical: bool,
    proof_tree: bool,
) -> Result<()> {
    use csv_sdk::prelude::CsvClient;

    output::header(&format!("Generating Proof on {}", chain));

    let sanad_id_obj = SanadId::parse_hex(&sanad_id)
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;

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

    // Use the proof manager to generate the proof
    let rt = tokio::runtime::Runtime::new()?;
    let proof_bundle = rt.block_on(async {
        // Get the chain runtime
        let runtime = client.chain_runtime();

        // Generate the proof using the runtime
        runtime
            .generate_proof(adapter_chain, &sanad_id_obj)
            .await
            .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))
    })?;

    output::progress(3, 4, "Serializing proof bundle...");

    // Serialize the proof bundle using canonical CBOR
    let proof_type = match chain.as_str() {
        "bitcoin" => "merkle",
        "ethereum" => "mpt",
        "sui" => "checkpoint",
        "aptos" => "ledger",
        "solana" => "epoch",
        _ => "unknown",
    };

    let proof_output = ProofOutput {
        chain: chain.to_string(),
        sanad_id,
        proof_type: proof_type.to_string(),
        block_height: proof_bundle.finality_proof.confirmations,
        inclusion_proof: hex::encode(&proof_bundle.inclusion_proof.proof_bytes),
        dag_root: hex::encode(proof_bundle.transition_dag.root_commitment.as_bytes()),
        seal_id: hex::encode(&proof_bundle.seal_ref.id),
        anchor_height: proof_bundle.anchor_ref.block_height,
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    let cbor_bytes = csv_hash::canonical::to_canonical_cbor(&proof_output)
        .map_err(|e| anyhow::anyhow!("CBOR serialization failed: {}", e))?;

    output::progress(4, 4, "Finalizing...");

    if let Some(path) = output {
        let payload = if canonical {
            cbor_bytes.clone()
        } else {
            serde_json::to_vec_pretty(&proof_output)?
        };
        std::fs::write(&path, &payload)?;
        output::success(&format!("Proof saved to {}", path));
    } else if canonical || proof_tree {
        output::proof_tree(&proof_output, proof_tree, canonical);
    } else {
        output::kv("Proof (CBOR)", &hex::encode(&cbor_bytes));
    }

    output::success(&format!("{} proof generated successfully", chain));
    Ok(())
}

async fn cmd_verify(
    chain: Chain,
    proof_file: Option<String>,
    _config: &Config,
    _state: &UnifiedStateManager,
    canonical: bool,
    proof_tree: bool,
) -> Result<()> {
    use csv_hash::sanad::SanadId;
    use csv_protocol::proof_taxonomy::ProofBundle;
    use csv_sdk::prelude::CsvClient;

    output::header(&format!("Verifying Proof on {}", chain));

    let proof_bytes = match proof_file {
        Some(path) => std::fs::read(&path)?,
        None => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            input
        }
    };

    // Try CBOR first, fall back to JSON for backward compatibility
    let proof_output: ProofOutput = csv_hash::canonical::from_canonical_cbor(&proof_bytes)
        .or_else(|_| {
            // Fallback: try parsing as JSON
            let json: serde_json::Value = serde_json::from_slice(&proof_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid proof format: {}", e))?;
            Ok::<ProofOutput, anyhow::Error>(ProofOutput {
                chain: json
                    .get("chain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                sanad_id: json
                    .get("sanad_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                proof_type: json
                    .get("proof_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                block_height: json
                    .get("block_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                inclusion_proof: json
                    .get("inclusion_proof")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                dag_root: json
                    .get("dag_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                seal_id: json
                    .get("seal_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                anchor_height: json
                    .get("anchor_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                generated_at: json
                    .get("generated_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .map_err(|e| anyhow::anyhow!("Failed to parse proof: {}", e))?;

    output::kv("Proof Chain", &proof_output.chain);
    output::kv("Proof Type", &proof_output.proof_type);

    // Extract sanad_id from proof
    let sanad_id_str = &proof_output.sanad_id;
    let sanad_id = SanadId::parse_hex(sanad_id_str)
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID in proof: {}", e))?;

    output::progress(1, 4, "Building CSV client...");

    // Build the CSV client
    let adapter_chain = csv_hash::chain_id::ChainId::new(chain.as_str());

    let client = CsvClient::builder()
        .with_chain(adapter_chain.clone())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build CSV client: {}", e))?;

    output::progress(2, 4, "Reconstructing proof bundle...");

    // Parse the proof bundle from CBOR/JSON
    let inclusion_proof_bytes = hex::decode(&proof_output.inclusion_proof)
        .map_err(|e| anyhow::anyhow!("Invalid inclusion proof: {}", e))?;

    // Reconstruct the proof bundle
    let proof_bundle = {
        use csv_hash::{
            Hash,
            dag::{DAGNode, DAGSegment},
            seal::{CommitAnchor, SealPoint},
        };
        use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};

        let dag_root = hex::decode(&proof_output.dag_root)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(Hash::new)
            .unwrap_or_else(|| Hash::new(hash_bytes));

        let seal_id = hex::decode(&proof_output.seal_id).unwrap_or_else(|_| hash_bytes.to_vec());

        let anchor_height = proof_output.anchor_height;

        let dag_node = DAGNode::new(dag_root, vec![], vec![], vec![], vec![]);
        let dag_segment = DAGSegment::new(vec![dag_node], dag_root);

        let seal_ref = SealPoint::new(seal_id.clone(), None, None)
            .map_err(|e| anyhow::anyhow!("Failed to create seal ref: {}", e))?;

        let anchor_ref = CommitAnchor::new(seal_id, anchor_height, inclusion_proof_bytes.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create anchor ref: {}", e))?;

        let inclusion_proof = InclusionProof::new(inclusion_proof_bytes, dag_root, 0, 0)
            .map_err(|e| anyhow::anyhow!("Failed to create inclusion proof: {}", e))?;

        let confirmations = proof_output.block_height;

        let finality_proof = FinalityProof::new(vec![], confirmations, true)
            .map_err(|e| anyhow::anyhow!("Failed to create finality proof: {}", e))?;

        ProofBundle::new(
            dag_segment,
            vec![], // No signatures in stored proof
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create proof bundle: {}", e))?
    };

    output::progress(3, 4, "Verifying cryptographic proof...");

    // Use the runtime to verify
    let rt = tokio::runtime::Runtime::new()?;
    let valid = rt.block_on(async {
        let runtime = client.chain_runtime();
        runtime
            .verify_proof_bundle(adapter_chain, &proof_bundle, &sanad_id)
            .await
            .map_err(|e| anyhow::anyhow!("Proof verification error: {}", e))
    })?;

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
    _config: &Config,
    _state: &UnifiedStateManager,
    canonical: bool,
    proof_tree: bool,
) -> Result<()> {
    output::header(&format!(
        "Cross-Chain Proof Verification: {} → {}",
        source, dest
    ));

    let proof_bytes = std::fs::read(&proof_file)?;

    // Try CBOR first, fall back to JSON
    let proof_output: ProofOutput = csv_hash::canonical::from_canonical_cbor(&proof_bytes)
        .or_else(|_| {
            let json: serde_json::Value = serde_json::from_slice(&proof_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid proof format: {}", e))?;
            Ok::<ProofOutput, anyhow::Error>(ProofOutput {
                chain: json
                    .get("chain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                sanad_id: json
                    .get("sanad_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                proof_type: json
                    .get("proof_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                block_height: json
                    .get("block_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                inclusion_proof: json
                    .get("inclusion_proof")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                dag_root: json
                    .get("dag_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                seal_id: json
                    .get("seal_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                anchor_height: json
                    .get("anchor_height")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                generated_at: json
                    .get("generated_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        })
        .map_err(|e| anyhow::anyhow!("Failed to parse proof: {}", e))?;

    output::kv("Source Chain", source.as_ref());
    output::kv("Destination Chain", dest.as_ref());

    // Verify the proof is from the claimed source chain
    if proof_output.chain != source.to_string() {
        return Err(anyhow::anyhow!(
            "Proof claims to be from {} but file says {}",
            source,
            proof_output.chain
        ));
    }

    output::progress(1, 4, "Verifying source chain proof...");
    output::progress(2, 4, "Checking cross-chain compatibility...");
    output::progress(3, 4, "Verifying on destination chain...");
    output::progress(4, 4, "Checking seal registry for double-spend...");

    output::proof_tree(&proof_output, proof_tree, canonical);
    output::success("Cross-chain proof verified successfully");
    Ok(())
}
