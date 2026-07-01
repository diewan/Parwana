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

const FORBIDDEN_PLACEHOLDER_PATTERNS: &[&str] = &[
    "todo!()",
    "todo! (",
    "unimplemented!()",
    "unimplemented! (",
];

const FORBIDDEN_PANIC_PATTERNS: &[&str] = &[
    "panic!()",
    "panic! (",
    "unreachable!()",
    "unreachable! (",
];

const FORBIDDEN_UNWRAP_PATTERNS: &[&str] = &[
    ".unwrap()",
    ".unwrap (",
    ".expect(",
    ".expect (",
];

const FORBIDDEN_ZERO_HASH_PATTERNS: &[&str] = &[
    "Hash::new([0u8; 32])",
];

// Natural-language log/comment signatures of the runtime mock-fallback antipattern
// fixed under PROD-FAILCLOSED-001 (adapter constructors silently substituting a
// mock RPC/seal protocol when the real one fails to construct). These are checked
// against full file contents, including files that also contain unit tests, since
// that is exactly where this bug previously lived (chain adapter `ops.rs` files).
const PRODUCTION_MOCK_FALLBACK_PATTERNS: &[&str] = &[
    "Fallback to mock",
    "fallback to mock",
    "falling back to mock",
    "using mock",
    "warning and continue",
];

const SERDE_JSON_SERIALIZATION_CALLS: &[&str] = &[
    "serde_json::to_vec",
    "serde_json::to_string",
    "serde_json::to_writer",
];

const RUNTIME_MINT_AUTHORITY_PATTERNS: &[&str] =
    &[".mint_sanad(", ".lock_sanad(", "mint_sanad_on_chain"];

const EMPTY_PROOF_VECTOR_PATTERNS: &[&str] = &[
    "leaves: vec![]",
    "leaf_hashes: vec![]",
    "proof_path: vec![]",
    "siblings: vec![]",
    "inclusion_path: vec![]",
];

#[test]
fn authority_crates_do_not_depend_on_chain_adapters() {
    let root = workspace_root();
    for manifest in AUTHORITY_CRATE_MANIFESTS {
        let content = fs::read_to_string(root.join(manifest)).unwrap();
        let active_content = strip_toml_comments(&content);
        for marker in ADAPTER_DEP_MARKERS {
            // Allow csv-adapter-core as it's a shared library, not a chain-specific adapter
            if (*marker == "../csv-adapters/" || *marker == "csv-adapters/") && active_content.contains("csv-adapter-core") {
                // Check if it's specifically csv-adapter-core (allowed) or other adapters (not allowed)
                if active_content.contains("csv-adapter-core") && !active_content.contains("csv-bitcoin")
                    && !active_content.contains("csv-ethereum") && !active_content.contains("csv-solana")
                    && !active_content.contains("csv-sui") && !active_content.contains("csv-aptos")
                    && !active_content.contains("csv-celestia")
                {
                    continue; // csv-adapter-core is allowed
                }
            }
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

#[test]
fn production_code_has_no_todo_or_unimplemented() {
    let root = workspace_root();
    let production_dirs = [
        "csv-runtime/src",
        "csv-sdk/src",
        "csv-cli/src",
        "csv-protocol/src",
        "csv-verifier/src",
        "csv-storage/src",
        "csv-coordinator/src",
        "csv-admission/src",
        "csv-hash/src",
        "csv-proof/src",
        "csv-content/src",
        "csv-codec/src",
        "csv-wire/src",
        "csv-algebra/src",
        "csv-schema/src",
    ];

    for src_dir in &production_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        let findings = scan_files(&dir_path, FORBIDDEN_PLACEHOLDER_PATTERNS);
        assert!(
            findings.is_empty(),
            "{} must not contain todo!() or unimplemented!() in production code:\n{}",
            src_dir,
            findings.join("\n")
        );
    }
}

#[test]
fn production_code_has_no_panics() {
    let root = workspace_root();
    let production_dirs = [
        "csv-runtime/src",
        "csv-sdk/src",
        "csv-cli/src",
        "csv-protocol/src",
        "csv-verifier/src",
        "csv-storage/src",
        "csv-coordinator/src",
        "csv-admission/src",
        "csv-proof/src",
        "csv-content/src",
        "csv-codec/src",
        "csv-wire/src",
        "csv-algebra/src",
        "csv-schema/src",
    ];

    for src_dir in &production_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        let findings = scan_files(&dir_path, FORBIDDEN_PANIC_PATTERNS);
        assert!(
            findings.is_empty(),
            "{} must not contain panic!() in production code:\n{}",
            src_dir,
            findings.join("\n")
        );
    }
}

#[test]
fn critical_paths_have_no_unwrap_or_expect() {
    let root = workspace_root();
    let critical_dirs = [
        "csv-runtime/src",
        "csv-protocol/src",
        "csv-verifier/src",
        "csv-hash/src",
        "csv-proof/src",
        "csv-codec/src",
    ];

    for src_dir in &critical_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        let findings = scan_files(&dir_path, FORBIDDEN_UNWRAP_PATTERNS);
        assert!(
            findings.is_empty(),
            "{} (critical path) must not contain .unwrap() or .expect() in production code:\n{}",
            src_dir,
            findings.join("\n")
        );
    }
}

#[test]
fn production_code_has_no_zero_hashes() {
    let root = workspace_root();
    let production_dirs = [
        "csv-runtime/src",
        "csv-sdk/src",
        "csv-cli/src",
        "csv-protocol/src",
        "csv-verifier/src",
        "csv-hash/src",
        "csv-proof/src",
    ];

    for src_dir in &production_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        let findings = scan_files(&dir_path, FORBIDDEN_ZERO_HASH_PATTERNS);
        assert!(
            findings.is_empty(),
            "{} must not contain zero hash patterns in production code:\n{}",
            src_dir,
            findings.join("\n")
        );
    }
}

#[test]
fn cli_does_not_import_chain_adapters_directly() {
    let root = workspace_root();
    let cli_src = root.join("csv-cli/src");
    if !cli_src.exists() {
        return;
    }

    let adapter_imports = scan_files(
        &cli_src,
        &[
            "use csv_adapters::csv_bitcoin",
            "use csv_adapters::csv_ethereum",
            "use csv_adapters::csv_solana",
            "use csv_adapters::csv_sui",
            "use csv_adapters::csv_aptos",
            "use csv_adapters::csv_celestia",
            "csv_bitcoin::",
            "csv_ethereum::",
            "csv_solana::",
            "csv_sui::",
            "csv_aptos::",
            "csv_celestia::",
        ],
    );
    assert!(
        adapter_imports.is_empty(),
        "csv-cli must not import chain adapters directly; use csv-runtime instead:\n{}",
        adapter_imports.join("\n")
    );
}

#[test]
fn runtime_does_not_import_concrete_adapters_directly() {
    let root = workspace_root();
    let runtime_src = root.join("csv-runtime/src");
    if !runtime_src.exists() {
        return;
    }

    let adapter_imports = scan_files(
        &runtime_src,
        &[
            "use csv_adapters::csv_bitcoin",
            "use csv_adapters::csv_ethereum",
            "use csv_adapters::csv_solana",
            "use csv_adapters::csv_sui",
            "use csv_adapters::csv_aptos",
            "use csv_adapters::csv_celestia",
            "csv_bitcoin::",
            "csv_ethereum::",
            "csv_solana::",
            "csv_sui::",
            "csv_aptos::",
            "csv_celestia::",
        ],
    );
    assert!(
        adapter_imports.is_empty(),
        "csv-runtime must not import concrete chain adapters directly; use trait objects:\n{}",
        adapter_imports.join("\n")
    );
}

#[test]
fn cli_cannot_bypass_runtime_transfer_authority() {
    let root = workspace_root();
    let cli_src = root.join("csv-cli/src");
    if !cli_src.exists() {
        return;
    }
    let findings = scan_files(&cli_src, RUNTIME_MINT_AUTHORITY_PATTERNS);
    assert!(
        findings.is_empty(),
        "csv-cli must delegate cross-chain mutation authority to csv-runtime's TransferCoordinator:\n{}",
        findings.join("\n")
    );
}

#[test]
fn canonical_hashing_paths_do_not_use_serde_json_serialization() {
    let root = workspace_root();
    let canonical_dirs = ["csv-hash/src", "csv-codec/src"];

    for src_dir in &canonical_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        let findings = scan_files(&dir_path, SERDE_JSON_SERIALIZATION_CALLS);
        assert!(
            findings.is_empty(),
            "{} performs canonical hashing and must not serialize via serde_json (non-deterministic across versions):\n{}",
            src_dir,
            findings.join("\n")
        );
    }
}

#[test]
fn production_adapters_have_no_mock_fallback_on_construction_failure() {
    let root = workspace_root();
    let findings =
        scan_files_excluding_test_blocks(&root.join("csv-adapters"), PRODUCTION_MOCK_FALLBACK_PATTERNS);
    assert!(
        findings.is_empty(),
        "chain adapter constructors must fail closed with a typed error, not fall back to a mock RPC/seal protocol on error (see PROD-FAILCLOSED-001):\n{}",
        findings.join("\n")
    );
}

#[test]
fn validation_functions_do_not_return_placeholder_ok() {
    let root = workspace_root();
    let production_dirs = ["csv-verifier/src", "csv-protocol/src", "csv-runtime/src"];

    let mut findings = Vec::new();
    for src_dir in &production_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        collect_placeholder_stub_findings(&dir_path, &mut findings);
    }
    findings.sort();
    assert!(
        findings.is_empty(),
        "verification/validation functions must not be placeholder stubs that unconditionally return Ok(true)/Ok(()):\n{}",
        findings.join("\n")
    );
}

fn collect_placeholder_stub_findings(path: &Path, findings: &mut Vec<String>) {
    if skip_path(path) {
        return;
    }
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            collect_placeholder_stub_findings(&entry.path(), findings);
        }
        return;
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        return;
    }
    let path_str = path.to_string_lossy();
    if path_str.contains("/tests/") || path_str.contains("\\tests\\") {
        return;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = content.lines().collect();
    let is_test_line = test_attributed_line_mask(&lines);

    let mut idx = 0;
    while idx < lines.len() {
        if is_test_line[idx] {
            idx += 1;
            continue;
        }
        let line = lines[idx];
        let is_candidate_fn = line.contains("fn ")
            && (line.contains("verify") || line.contains("validate") || line.contains("is_valid"))
            && line.contains('{');
        if !is_candidate_fn {
            idx += 1;
            continue;
        }

        let mut depth: i64 =
            line.matches('{').count() as i64 - line.matches('}').count() as i64;
        let mut body_stmts: Vec<&str> = Vec::new();
        let mut j = idx + 1;
        while j < lines.len() && depth > 0 {
            let body_line = lines[j];
            depth += body_line.matches('{').count() as i64 - body_line.matches('}').count() as i64;
            let trimmed = body_line.trim();
            if !trimmed.is_empty() && trimmed != "}" && !trimmed.starts_with("//") {
                body_stmts.push(trimmed);
            }
            j += 1;
        }

        if body_stmts.len() == 1 && (body_stmts[0] == "Ok(true)" || body_stmts[0] == "Ok(())") {
            findings.push(format!(
                "{}:{}: validation function body is a placeholder `{}`",
                path.display(),
                idx + 1,
                body_stmts[0]
            ));
        }
        idx = j.max(idx + 1);
    }
}

/// Marks each line as belonging to a `#[cfg(test)]`- or `#[test]`-attributed
/// item (function, module, impl, or use/const statement), using brace-depth
/// tracking from the attribute line. This lets guard checks scan production
/// files that also contain unit tests without flagging test-only code, e.g.
/// edge-case fixtures that legitimately construct empty vectors.
fn test_attributed_line_mask(lines: &[&str]) -> Vec<bool> {
    let mut mask = vec![false; lines.len()];
    let mut idx = 0;
    while idx < lines.len() {
        let trimmed = lines[idx].trim_start();
        if !(trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[test]")) {
            idx += 1;
            continue;
        }

        let start = idx;
        let mut j = idx;
        // Consume any stacked attributes directly above the item.
        while j < lines.len() && lines[j].trim_start().starts_with('#') {
            j += 1;
        }

        if j >= lines.len() {
            for m in mask.iter_mut().skip(start) {
                *m = true;
            }
            break;
        }

        if lines[j].contains('{') {
            let mut depth: i64 = 0;
            loop {
                depth += lines[j].matches('{').count() as i64;
                depth -= lines[j].matches('}').count() as i64;
                j += 1;
                if depth <= 0 || j >= lines.len() {
                    break;
                }
            }
            for m in mask.iter_mut().take(j).skip(start) {
                *m = true;
            }
            idx = j;
        } else {
            // No-brace item (e.g. `use foo;` or `const X: T = Y;`).
            for m in mask.iter_mut().take(j + 1).skip(start) {
                *m = true;
            }
            idx = j + 1;
        }
    }
    mask
}

fn scan_files_excluding_test_blocks(root: &Path, patterns: &[&str]) -> Vec<String> {
    let mut findings = Vec::new();
    scan_excluding_test_blocks_inner(root, patterns, &mut findings);
    findings.sort();
    findings
}

fn scan_excluding_test_blocks_inner(path: &Path, patterns: &[&str], findings: &mut Vec<String>) {
    if skip_path(path) {
        return;
    }
    if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            scan_excluding_test_blocks_inner(&entry.path(), patterns, findings);
        }
        return;
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
        return;
    }
    let path_str = path.to_string_lossy();
    if path_str.contains("/tests/") || path_str.contains("\\tests\\") {
        return;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = content.lines().collect();
    let is_test_line = test_attributed_line_mask(&lines);

    for (idx, line) in lines.iter().enumerate() {
        if is_test_line[idx] {
            continue;
        }
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

#[test]
fn proof_construction_has_no_empty_placeholder_vectors() {
    let root = workspace_root();
    let production_dirs = [
        "csv-proof/src",
        "csv-protocol/src",
        "csv-runtime/src",
        "csv-adapters",
    ];

    let mut findings = Vec::new();
    for src_dir in &production_dirs {
        let dir_path = root.join(src_dir);
        if !dir_path.exists() {
            continue;
        }
        findings.extend(scan_files_excluding_test_blocks(
            &dir_path,
            EMPTY_PROOF_VECTOR_PATTERNS,
        ));
    }
    findings.sort();
    assert!(
        findings.is_empty(),
        "proof construction must not fabricate empty inclusion/finality proof vectors:\n{}",
        findings.join("\n")
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

    // Skip test files and directories
    let path_str = path.to_string_lossy();
    if path_str.contains("/tests/") || path_str.contains("\\tests\\") {
        return;
    }

    let Ok(content) = fs::read_to_string(path) else {
        return;
    };

    // Skip entire files that contain test modules
    if content.contains("#[cfg(test)]") || content.contains("#[test]") {
        return;
    }

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();

        // Skip comments
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
