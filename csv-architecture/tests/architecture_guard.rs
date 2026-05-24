use std::fs;
use std::path::{Path, PathBuf};

const AUTHORITY_CRATE_MANIFESTS: &[&str] = &[
    "csv-runtime/Cargo.toml",
    "csv-cli/Cargo.toml",
    "csv-core/Cargo.toml",
    "csv-protocol/Cargo.toml",
];

const ADAPTER_DEP_MARKERS: &[&str] = &[
    "../csv-adapters/",
    "csv-adapters/",
    "csv-bitcoin =",
    "csv-ethereum =",
    "csv-solana =",
    "csv-sui =",
    "csv-aptos =",
    "csv-celestia =",
];

const RUNTIME_NESTING_PATTERNS: &[&str] = &[
    "tokio::runtime::Builder::new_current_thread()",
    "Handle::current()",
    ".block_on(",
    "rt.block_on(",
];

const SILENT_CRYPTO_DEFAULT_PATTERNS: &[&str] = &[
    "bytes.len().min(32)",
    "copy_from_slice(&bytes[..copy_len])",
    "unwrap_or([0u8; 32])",
    "unwrap_or(\"0x0\")",
    ".unwrap_or_default()",
];

#[test]
fn authority_crates_do_not_depend_on_chain_adapters() {
    let root = workspace_root();
    for manifest in AUTHORITY_CRATE_MANIFESTS {
        let content = fs::read_to_string(root.join(manifest)).unwrap();
        let active_content = strip_toml_comments(&content);
        for marker in ADAPTER_DEP_MARKERS {
            assert!(
                !active_content.contains(marker),
                "{manifest} must not depend on chain adapter marker `{marker}`"
            );
        }
    }
}

#[test]
fn runtime_crate_does_not_construct_or_nest_tokio_runtimes() {
    let root = workspace_root();
    let findings = scan_files(&root.join("csv-runtime/src"), RUNTIME_NESTING_PATTERNS);
    assert!(
        findings.is_empty(),
        "csv-runtime must be executor-agnostic; forbidden runtime nesting found:\n{}",
        findings.join("\n")
    );
}

#[test]
fn aptos_node_has_no_silent_cryptographic_defaults() {
    let root = workspace_root();
    let node = fs::read_to_string(root.join("csv-adapters/csv-aptos/src/node.rs")).unwrap();
    for pattern in SILENT_CRYPTO_DEFAULT_PATTERNS {
        assert!(
            !node.contains(pattern),
            "Aptos production RPC parser must fail closed; found `{pattern}`"
        );
    }
}

#[test]
fn architecture_debt_ratchet_does_not_grow() {
    let root = workspace_root();

    let runtime_nesting = scan_files(&root.join("csv-adapters"), RUNTIME_NESTING_PATTERNS);
    assert!(
        runtime_nesting.len() <= 70,
        "runtime nesting debt increased; remove adapter-local block_on/new_current_thread or update the architecture intentionally:\n{}",
        runtime_nesting.join("\n")
    );

    let silent_crypto_defaults = scan_files(
        &root,
        &[
            "bytes.len().min(32)",
            "copy_from_slice(&bytes[..copy_len])",
            "unwrap_or([0u8; 32])",
            "unwrap_or(\"0x0\")",
            "hex::decode(hex).unwrap_or_default()",
            "hex::decode(commit_str).unwrap_or_default()",
        ],
    );
    assert!(
        silent_crypto_defaults.len() <= 30,
        "silent cryptographic default debt increased; malformed chain data must fail closed:\n{}",
        silent_crypto_defaults.join("\n")
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("architecture crate lives under workspace root")
        .to_path_buf()
}

fn strip_toml_comments(content: &str) -> String {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn scan_files(root: &Path, patterns: &[&str]) -> Vec<String> {
    let mut findings = Vec::new();
    scan_files_inner(root, patterns, &mut findings);
    findings.sort();
    findings
}

fn scan_files_inner(path: &Path, patterns: &[&str], findings: &mut Vec<String>) {
    if skip_path(path) {
        return;
    }

    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            scan_files_inner(&entry.path(), patterns, findings);
        }
        return;
    }

    if !matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("rs" | "toml")
    ) {
        return;
    }

    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for pattern in patterns {
            if line.contains(pattern) {
                findings.push(format!("{}:{}: {}", path.display(), idx + 1, line.trim()));
                break;
            }
        }
    }
}

fn skip_path(path: &Path) -> bool {
    path.components().any(|component| {
        let text = component.as_os_str().to_string_lossy();
        matches!(
            text.as_ref(),
            "target" | ".git" | "third_party" | "csv-architecture"
        )
    })
}
