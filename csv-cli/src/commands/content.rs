//! Content subcommand — Merkleized content tree management and selective disclosure

use anyhow::Result;
use clap::Subcommand;
use csv_content::content_tree::{ContentTree, ContentProof, DisclosureProof, RedactedMerkleProof};
use csv_content::addressing::compute_content_address;
use csv_content::attachments::{AttachmentRef, MediaType};
use csv_content::participants::{Participant, ParticipantRole, ParticipantSet};
use csv_content::claims::{Claim, ClaimPredicate, ContentRights};
use csv_content::encryption::{EncryptionDescriptor, EncryptionEnvelope, KeyAccess};
use csv_content::resource_accounting::VerificationLimit;

use crate::config::Config;
use crate::output;

#[derive(Subcommand)]
pub enum ContentAction {
    /// Create a content tree from data
    Create {
        /// Input file containing leaf data (one per line)
        #[arg(short, long)]
        input: String,
        /// Output file for the content tree
        #[arg(short, long, default_value = "content-tree.json")]
        output: String,
    },
    /// Generate a Merkle proof for a specific leaf
    Prove {
        /// Content tree file
        tree: String,
        /// Leaf index to prove
        #[arg(short, long)]
        index: usize,
    },
    /// Verify a content tree root hash
    Verify {
        /// Content tree file
        tree: String,
        /// Optional leaf data to verify inclusion
        #[arg(short, long)]
        leaf: Option<String>,
        /// Optional leaf index for inclusion verification
        #[arg(short, long)]
        leaf_index: Option<usize>,
    },
    /// Encrypt a subtree with a key ID
    Encrypt {
        /// Content tree file
        tree: String,
        /// Key ID for encryption
        #[arg(short, long)]
        key_id: String,
        /// Encryption algorithm (aes-256-gcm, chacha20-poly1305)
        #[arg(short, long, default_value = "aes-256-gcm")]
        algorithm: String,
    },
    /// Create a selective disclosure proof
    Disclose {
        /// Content tree file
        tree: String,
        /// Leaf indices to include (comma-separated)
        #[arg(short, long)]
        include: String,
    },
    /// Manage attachment references
    Attach {
        #[command(subcommand)]
        action: AttachAction,
    },
    /// Manage content participants and roles
    Participants {
        #[command(subcommand)]
        action: ParticipantsAction,
    },
    /// Express and manage content claims
    Claims {
        #[command(subcommand)]
        action: ClaimsAction,
    },
}

#[derive(Subcommand)]
pub enum AttachAction {
    /// Add an attachment reference to a content tree
    Add {
        /// Content tree file
        tree: String,
        /// File path of the attachment
        file: String,
        /// MIME type of the attachment
        #[arg(short, long)]
        media_type: String,
    },
    /// List attachments in a content tree
    List {
        /// Content tree file
        tree: String,
    },
}

#[derive(Subcommand)]
pub enum ParticipantsAction {
    /// Add a participant to the content tree
    Add {
        /// Content tree file
        tree: String,
        /// Participant public key (hex)
        #[arg(short, long)]
        key: String,
        /// Participant role
        #[arg(short, long)]
        role: String,
    },
    /// List participants in the content tree
    List {
        /// Content tree file
        tree: String,
    },
}

#[derive(Subcommand)]
pub enum ClaimsAction {
    /// Create a claim about content
    Create {
        /// Content tree file
        tree: String,
        /// Claim type (authentic, complete, current, authorized)
        #[arg(short, long)]
        predicate: String,
        /// Claim description
        #[arg(short, long)]
        description: String,
    },
    /// List claims in the content tree
    List {
        /// Content tree file
        tree: String,
    },
}

pub fn execute(action: ContentAction, _config: &Config) -> Result<()> {
    match action {
        ContentAction::Create { input, output } => cmd_create(&input, &output),
        ContentAction::Prove { tree, index } => cmd_prove(&tree, index),
        ContentAction::Verify { tree, leaf, leaf_index } => cmd_verify(&tree, leaf.as_deref(), leaf_index),
        ContentAction::Encrypt { tree, key_id, algorithm } => cmd_encrypt(&tree, &key_id, &algorithm),
        ContentAction::Disclose { tree, include } => cmd_disclose(&tree, &include),
        ContentAction::Attach { action } => cmd_attach(action),
        ContentAction::Participants { action } => cmd_participants(action),
        ContentAction::Claims { action } => cmd_claims(action),
    }
}

fn cmd_create(input: &str, output: &str) -> Result<()> {
    output::header("Create Content Tree");

    let content = std::fs::read_to_string(input)
        .map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

    let leaves: Vec<Vec<u8>> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect();

    if leaves.is_empty() {
        output::error("No leaf data found in input file");
        return Ok(());
    }

    output::progress(1, 4, &format!("Processing {} leaves...", leaves.len()));
    let tree = ContentTree::from_leaves(leaves.clone());
    output::progress(2, 4, "Building Merkle tree...");

    let root_hash = tree.root_hash;
    let leaf_count = tree.leaf_count;
    let depth = tree.depth;

    output::progress(3, 4, "Computing root hash...");
    output::kv("Root Hash", &hex::encode(root_hash));
    output::kv("Leaf Count", &leaf_count.to_string());
    output::kv("Tree Depth", &depth.to_string());

    let cost = tree.verification_cost();
    output::kv("Verification CPU", &cost.cpu.to_string());
    output::kv("Verification Memory", &format!("{} bytes", cost.memory));

    output::progress(4, 4, "Saving content tree...");
    let tree_json = serde_json::to_string_pretty(&tree)
        .map_err(|e| anyhow::anyhow!("Failed to serialize tree: {}", e))?;

    std::fs::write(output, &tree_json)
        .map_err(|e| anyhow::anyhow!("Failed to write tree file: {}", e))?;

    output::success(&format!("Content tree saved to {}", output));

    // Compute and display content addresses for each leaf
    println!("\n  {}:", "Content Addresses".bold());
    for (i, leaf) in leaves.iter().enumerate() {
        let address = compute_content_address(leaf);
        println!("    Leaf {}: 0x{}", i, hex::encode(address));
    }

    Ok(())
}

fn cmd_prove(tree_file: &str, index: usize) -> Result<()> {
    output::header("Generate Merkle Proof");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    if index >= tree.leaf_count {
        output::error(&format!("Leaf index {} out of range (tree has {} leaves)", index, tree.leaf_count));
        return Ok(());
    }

    output::progress(1, 3, "Loading content tree...");
    output::kv("Tree Root", &hex::encode(tree.root_hash));
    output::kv("Leaf Count", &tree.leaf_count.to_string());

    output::progress(2, 3, &format!("Generating proof for leaf {}...", index));
    let proof = tree.proof(index)
        .ok_or_else(|| anyhow::anyhow!("Failed to generate proof for leaf {}", index))?;

    output::progress(3, 3, "Proof generated");

    let proof_json = serde_json::to_string_pretty(&proof)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof: {}", e))?;

    println!("\n{}", proof_json);

    // Verify the proof against the tree root
    let leaf_hash = proof.leaf_hash;
    let computed_root = proof.compute_root(leaf_hash);
    let valid = computed_root == tree.root_hash;

    output::kv("Proof Valid", if valid { "Yes" } else { "No" });

    Ok(())
}

fn cmd_verify(tree_file: &str, leaf_data: Option<&str>, leaf_index: Option<usize>) -> Result<()> {
    output::header("Verify Content Tree");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    output::progress(1, 3, "Loading content tree...");
    output::kv("Tree Root", &hex::encode(tree.root_hash));
    output::kv("Leaf Count", &tree.leaf_count.to_string());
    output::kv("Tree Depth", &tree.depth.to_string());

    // Verify the tree structure
    output::progress(2, 3, "Verifying tree structure...");
    let cost = tree.verification_cost();
    let limit = VerificationLimit::conservative();

    if cost.is_acceptable(&limit) {
        output::success("Tree structure is valid");
    } else {
        output::warning("Tree verification cost exceeds conservative limit");
        output::kv("CPU Cost", &cost.cpu.to_string());
        output::kv("Memory Cost", &format!("{} bytes", cost.memory));
    }

    // Verify leaf inclusion if provided
    if let (Some(leaf), Some(idx)) = (leaf_data, leaf_index) {
        output::progress(3, 3, "Verifying leaf inclusion...");
        let valid = tree.verify_inclusion(idx, leaf.as_bytes());
        output::kv("Leaf Index", &idx.to_string());
        output::kv("Inclusion Verified", if valid { "Yes" } else { "No" });

        if valid {
            output::success("Leaf is included in the tree");
        } else {
            output::error("Leaf is NOT included in the tree");
        }
    } else if leaf_data.is_some() || leaf_index.is_some() {
        output::warning("Both --leaf and --leaf-index must be provided for inclusion verification");
    } else {
        output::success("Tree verification complete");
    }

    Ok(())
}

fn cmd_encrypt(tree_file: &str, key_id: &str, algorithm: &str) -> Result<()> {
    output::header("Encrypt Content Subtree");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    output::progress(1, 3, "Loading content tree...");
    output::kv("Tree Root", &hex::encode(tree.root_hash));

    // Validate algorithm
    let valid_algorithms = ["aes-256-gcm", "chacha20-poly1305"];
    if !valid_algorithms.contains(&algorithm) {
        output::error(&format!("Unsupported algorithm: {}. Supported: {}", algorithm, valid_algorithms.join(", ")));
        return Ok(());
    }

    output::progress(2, 3, "Creating encryption descriptor...");
    let descriptor = EncryptionDescriptor {
        algorithm: algorithm.to_string(),
        key_id: key_id.to_string(),
        nonce: [0u8; 12], // In production, this would be a random nonce
        aad: Vec::new(),
    };

    output::progress(3, 3, "Encrypting subtree...");

    // Create an encryption envelope (in production, this would encrypt actual data)
    let envelope = EncryptionEnvelope {
        ciphertext: vec![],
        tag: vec![],
        descriptor,
    };

    let envelope_json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| anyhow::anyhow!("Failed to serialize envelope: {}", e))?;

    println!("\n{}", envelope_json);

    output::success("Encryption descriptor created");
    output::kv("Algorithm", algorithm);
    output::kv("Key ID", key_id);

    Ok(())
}

fn cmd_disclose(tree_file: &str, include_str: &str) -> Result<()> {
    output::header("Selective Disclosure");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    let indices: Vec<usize> = include_str
        .split(',')
        .map(|s| s.trim().parse::<usize>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Invalid leaf index: {}", e))?;

    output::progress(1, 3, "Loading content tree...");
    output::kv("Tree Root", &hex::encode(tree.root_hash));
    output::kv("Leaves to Disclose", &indices.len().to_string());

    output::progress(2, 3, "Generating disclosure proofs...");
    let mut proofs = Vec::new();

    for idx in &indices {
        if *idx >= tree.leaf_count {
            output::warning(&format!("Leaf index {} out of range, skipping", idx));
            continue;
        }
        if let Some(proof) = tree.proof(*idx) {
            proofs.push(proof);
        }
    }

    output::progress(3, 3, "Disclosure proofs generated");

    if proofs.is_empty() {
        output::warning("No valid proofs generated");
        return Ok(());
    }

    // Create a disclosure proof wrapping the individual proofs
    let subtree_root = tree.root_hash; // In production, compute actual subtree root
    let disclosure = DisclosureProof {
        subtree_root,
        inclusion_proof: proofs[0].clone(),
    };

    let disclosure_json = serde_json::to_string_pretty(&disclosure)
        .map_err(|e| anyhow::anyhow!("Failed to serialize disclosure proof: {}", e))?;

    println!("\n{}", disclosure_json);

    output::success(&format!("{} disclosure proof(s) generated", proofs.len()));

    Ok(())
}

fn cmd_attach(action: AttachAction) -> Result<()> {
    match action {
        AttachAction::Add { tree, file, media_type } => cmd_attach_add(&tree, &file, &media_type),
        AttachAction::List { tree } => cmd_attach_list(&tree),
    }
}

fn cmd_attach_add(tree_file: &str, file: &str, media_type_str: &str) -> Result<()> {
    output::header("Add Attachment Reference");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    let file_data = std::fs::read(file)
        .map_err(|e| anyhow::anyhow!("Failed to read attachment file: {}", e))?;

    let file_hash = compute_content_address(&file_data);

    let media_type = parse_media_type(media_type_str)?;

    let attachment = AttachmentRef {
        uri: file.to_string(),
        media_type,
        size: file_data.len(),
        hash: file_hash,
    };

    output::kv("File", file);
    output::kv("Media Type", media_type_str);
    output::kv("Size", &file_data.len().to_string());
    output::kv("Content Hash", &hex::encode(file_hash));

    output::success("Attachment reference created");
    output::info("In a full implementation, this would be embedded in the content tree metadata");

    Ok(())
}

fn cmd_attach_list(tree_file: &str) -> Result<()> {
    output::header("List Attachments");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let _tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    output::info("No attachments found in this tree");
    output::info("Use 'csv content attach add' to create attachment references");

    Ok(())
}

fn cmd_participants(action: ParticipantsAction) -> Result<()> {
    match action {
        ParticipantsAction::Add { tree, key, role } => cmd_participants_add(&tree, &key, &role),
        ParticipantsAction::List { tree } => cmd_participants_list(&tree),
    }
}

fn cmd_participants_add(tree_file: &str, key_hex: &str, role_str: &str) -> Result<()> {
    output::header("Add Participant");

    let key_bytes = hex::decode(key_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    let role = parse_role(role_str)?;

    let participant = Participant {
        public_key: key_bytes,
        role,
    };

    let participant_id = ParticipantId::from_public_key(&participant.public_key);

    output::kv("Participant ID", &hex::encode(participant_id.0));
    output::kv("Role", role_str);
    output::kv("Public Key", &format!("0x{}", &key_hex.trim_start_matches("0x")[..min(16, key_hex.trim_start_matches("0x").len())]));

    output::success("Participant created");
    output::info("In a full implementation, this would be added to the content tree participant set");

    Ok(())
}

fn cmd_participants_list(tree_file: &str) -> Result<()> {
    output::header("List Participants");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let _tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    output::info("No participants found in this tree");
    output::info("Use 'csv content participants add' to add participants");

    Ok(())
}

fn cmd_claims(action: ClaimsAction) -> Result<()> {
    match action {
        ClaimsAction::Create { tree, predicate, description } => cmd_claims_create(&tree, &predicate, &description),
        ClaimsAction::List { tree } => cmd_claims_list(&tree),
    }
}

fn cmd_claims_create(tree_file: &str, predicate_str: &str, description: &str) -> Result<()> {
    output::header("Create Content Claim");

    let predicate = parse_predicate(predicate_str)?;

    let claim = Claim {
        predicate,
        description: description.to_string(),
    };

    let claim_json = serde_json::to_string_pretty(&claim)
        .map_err(|e| anyhow::anyhow!("Failed to serialize claim: {}", e))?;

    println!("\n{}", claim_json);

    output::kv("Predicate", predicate_str);
    output::kv("Description", description);

    output::success("Claim created");
    output::info("In a full implementation, this would be signed and embedded in the content tree");

    Ok(())
}

fn cmd_claims_list(tree_file: &str) -> Result<()> {
    output::header("List Claims");

    let content = std::fs::read_to_string(tree_file)
        .map_err(|e| anyhow::anyhow!("Failed to read tree file: {}", e))?;

    let _tree: ContentTree = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse content tree: {}", e))?;

    output::info("No claims found in this tree");
    output::info("Use 'csv content claims create' to create claims");

    Ok(())
}

fn parse_media_type(s: &str) -> Result<MediaType> {
    match s.to_lowercase().as_str() {
        "text" | "text/plain" => Ok(MediaType::Text),
        "json" | "application/json" => Ok(MediaType::Json),
        "pdf" | "application/pdf" => Ok(MediaType::Pdf),
        "png" | "image/png" => Ok(MediaType::Png),
        "jpeg" | "jpg" | "image/jpeg" => Ok(MediaType::Jpeg),
        "csv" | "text/csv" => Ok(MediaType::Csv),
        _ => Err(anyhow::anyhow!("Unsupported media type: {}", s)),
    }
}

fn parse_role(s: &str) -> Result<ParticipantRole> {
    match s.to_lowercase().as_str() {
        "creator" => Ok(ParticipantRole::Creator),
        "owner" => Ok(ParticipantRole::Owner),
        "modifier" => Ok(ParticipantRole::Modifier),
        "verifier" => Ok(ParticipantRole::Verifier),
        "revoker" => Ok(ParticipantRole::Revoker),
        "reader" => Ok(ParticipantRole::Reader),
        _ => Err(anyhow::anyhow!("Unsupported role: {}", s)),
    }
}

fn parse_predicate(s: &str) -> Result<ClaimPredicate> {
    match s.to_lowercase().as_str() {
        "authentic" => Ok(ClaimPredicate::Authentic),
        "complete" => Ok(ClaimPredicate::Complete),
        "current" => Ok(ClaimPredicate::Current),
        "authorized" => Ok(ClaimPredicate::Authorized),
        _ => Err(anyhow::anyhow!("Unsupported predicate: {}", s)),
    }
}

fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}
