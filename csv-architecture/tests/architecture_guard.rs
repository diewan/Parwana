use std::fs;
use std::path::{Path, PathBuf};

const AUTHORITY_CRATE_MANIFESTS: &[&str] = &[
    "csv-runtime/Cargo.toml",
    "csv-cli/Cargo.toml",
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
fn sdk_cannot_bypass_runtime_transfer_authority() {
    let findings = scan_files(
        &workspace_root().join("csv-sdk/src"),
        &[".mint_sanad(", ".lock_sanad(", "mint_sanad_on_chain"],
    );
    assert!(
        findings.is_empty(),
        "csv-sdk must delegate cross-chain mutation authority to csv-runtime:\n{}",
        findings.join("\n")
    );
}

#[test]
fn retired_csv_core_cannot_reenter_workspace_dependencies() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(workspace_root().join("Cargo.toml"))
        .exec()
        .expect("cargo metadata must succeed");
    let violations: Vec<_> = metadata
        .packages
        .iter()
        .filter_map(|package| {
            package
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "csv-core")
                .then(|| package.name.clone())
        })
        .collect();
    assert!(
        violations.is_empty(),
        "retired csv-core dependency is forbidden; migrate these crates: {}",
        violations.join(", ")
    );
    assert!(
        !metadata
            .workspace_members
            .iter()
            .any(|id| id.repr.contains("csv-core")),
        "csv-core must remain excluded from the workspace"
    );

    let source_violations: Vec<_> = metadata
        .workspace_packages()
        .iter()
        .flat_map(|package| {
            let crate_root = package
                .manifest_path
                .parent()
                .expect("workspace package manifest must have a directory");
            scan_files(
                crate_root.join("src").as_std_path(),
                &["use csv_core::", "csv_core::"],
            )
        })
        .collect();
    assert!(
        source_violations.is_empty(),
        "production source must not import retired csv-core:\n{}",
        source_violations.join("\n")
    );
}

#[test]
fn nothing_new_depends_on_csv_core() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(workspace_root().join("Cargo.toml"))
        .exec()
        .expect("cargo metadata must succeed");

    for package in &metadata.packages {
        for dep in &package.dependencies {
            if dep.name == "csv-core" {
                panic!(
                    "{} must not depend on csv-core; migrate to csv-protocol/csv-verifier/csv-storage",
                    package.name
                );
            }
        }
    }

    let root = workspace_root();
    let source_dirs = [
        "csv-runtime/src",
        "csv-sdk/src",
        "csv-cli/src",
        "csv-protocol/src",
        "csv-verifier/src",
        "csv-storage/src",
        "csv-coordinator/src",
        "csv-admission/src",
    ];
    for src_dir in &source_dirs {
        let findings = scan_files(&root.join(src_dir), &["csv_core::", "use csv_core"]);
        assert!(
            findings.is_empty(),
            "{} must not import csv_core:\n{}",
            src_dir,
            findings.join("\n")
        );
    }
}

#[test]
fn recovery_paths_have_assertive_coverage() {
    let root = workspace_root();
    let runtime_tests =
        fs::read_to_string(root.join("csv-runtime/src/transfer_coordinator.rs")).unwrap();
    for required_test in [
        "lock_confirmed_recovery_regenerates_proof_and_completes",
        "awaiting_finality_recovery_rechecks_finality_and_completes",
        "proof_building_recovery_regenerates_proof_and_completes",
        "proof_validated_recovery_uses_persisted_payload_and_completes",
        "proof_validated_recovery_rejects_missing_payload",
        "proof_validated_recovery_rejects_malformed_payload",
        "proof_validated_recovery_rejects_tampered_payload_digest",
    ] {
        assert!(
            runtime_tests.contains(required_test),
            "required recovery test `{required_test}` is missing"
        );
    }

    let legacy_tests = root.join("csv-runtime/tests");
    let permissive_assertions = scan_files(
        &legacy_tests,
        &[
            "result.is_err() || matches!(result, Ok(_))",
            "This test is a placeholder",
        ],
    );
    assert!(
        permissive_assertions.is_empty(),
        "recovery tests must assert a deterministic outcome:\n{}",
        permissive_assertions.join("\n")
    );
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
