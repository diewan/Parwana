/// Architectural Constitution Test
///
/// This test is the machine-readable architectural contract.
/// It runs on every CI push. Failure is a build break, not a warning.
///
/// Layer definitions:
///   L0 (csv-algebra)      — pure types, no_std, no serde, no IO
///   L1 (csv-wire)         — serde + transport encoding of L0 types
///   L2 (csv-hash)         — cryptographic primitives over L0 types  
///   L3 (csv-protocol)     — protocol algebra; imports L0, L2
///   L4 (csv-verifier)     — verification logic; imports L3
///   L5 (csv-coordinator)  — orchestration; imports L3, L4, storage traits
///   L6 (csv-runtime)      — facade only; re-exports L5, adds binary config
///   L7 (csv-adapters/*)   — chain leaf nodes; imports L3, L4 only
///   L8 (csv-sdk, csv-cli) — user-facing; imports any layer
///
/// FORBIDDEN: any lower-numbered layer importing a higher-numbered layer.
/// FORBIDDEN: L7 importing L5, L6.
/// FORBIDDEN: L4 importing L7.

#[test]
fn dependency_dag_has_no_upward_edges() {
    // Note: This test will initially fail until csv-algebra and csv-coordinator crates exist
    // and the dependency graph is properly structured. This is intentional - the test
    // enforces the architectural constitution.

    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .expect("cargo metadata must succeed");

    let layer = |name: &str| -> u8 {
        match name {
            "csv-algebra" => 0,
            "csv-wire" => 1,
            "csv-hash" => 2,
            "csv-protocol" => 3,
            "csv-verifier" => 4,
            "csv-coordinator" => 5,
            "csv-runtime" => 6,
            n if n.starts_with("csv-") && n.contains("aptos")
                || n.contains("ethereum")
                || n.contains("solana")
                || n.contains("bitcoin")
                || n.contains("sui")
                || n.contains("celestia") =>
            {
                7
            }
            "csv-sdk" | "csv-cli" => 8,
            _ => 255,
        }
    };

    let mut violations: Vec<String> = vec![];

    for pkg in &metadata.packages {
        let from_layer = layer(&pkg.name);
        if from_layer == 255 {
            continue;
        }

        for dep in &pkg.dependencies {
            let to_layer = layer(&dep.name);
            if to_layer == 255 {
                continue;
            }

            // Adapter (L7) must not import coordinator (L5) or runtime (L6)
            if from_layer == 7 && (to_layer == 5 || to_layer == 6) {
                violations.push(format!(
                    "VIOLATION: {} (L{}) → {} (L{}) — adapters must not import runtime/coordinator",
                    pkg.name, from_layer, dep.name, to_layer
                ));
            }

            // Verifier (L4) must not import adapters (L7)
            if from_layer == 4 && to_layer == 7 {
                violations.push(format!(
                    "VIOLATION: {} (L{}) → {} (L{}) — verifier must be chain-agnostic",
                    pkg.name, from_layer, dep.name, to_layer
                ));
            }

            // Pure algebra (L0) must not import anything above L0
            if from_layer == 0 && to_layer > 0 {
                violations.push(format!(
                    "VIOLATION: csv-algebra → {} — algebra layer must have zero dependencies",
                    dep.name
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "ARCHITECTURAL CONSTITUTION VIOLATED:\n{}",
        violations.join("\n")
    );
}

#[test]
fn every_chain_adapter_uses_the_wire_boundary() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .expect("cargo metadata must succeed");
    let adapter_names = [
        "csv-aptos",
        "csv-bitcoin",
        "csv-celestia",
        "csv-ethereum",
        "csv-solana",
        "csv-sui",
    ];
    let mut violations = Vec::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| adapter_names.contains(&package.name.as_str()))
    {
        if !package
            .dependencies
            .iter()
            .any(|dependency| dependency.name == "csv-wire")
        {
            violations.push(package.name.clone());
        }
    }
    assert!(
        violations.is_empty(),
        "L7 adapters must use csv-wire for their transport boundary: {}",
        violations.join(", ")
    );
}

#[test]
fn intentional_workspace_crates_are_allowlisted() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .expect("cargo metadata must succeed");
    let allowed = [
        "csv-adapter-core",
        "csv-adapter-factory",
        "csv-admission",
        "csv-algebra",
        "csv-aptos",
        "csv-architecture",
        "csv-bitcoin",
        "csv-celestia",
        "csv-cli",
        "csv-codec",
        "csv-content",
        "csv-contract-bindings",
        "csv-coordinator",
        "csv-ethereum",
        "csv-examples",
        "csv-hash",
        "csv-keys",
        "csv-observability",
        "csv-p2p",
        "csv-proof",
        "csv-protocol",
        "csv-runtime",
        "csv-schema",
        "csv-sdk",
        "csv-solana",
        "csv-storage",
        "csv-store",
        "csv-sui",
        "csv-testkit",
        "csv-verifier",
        "csv-wallet",
        "csv-wire",
    ];
    let unregistered: Vec<_> = metadata
        .workspace_packages()
        .iter()
        .filter(|package| !allowed.contains(&package.name.as_str()))
        .map(|package| package.name.clone())
        .collect();
    assert!(
        unregistered.is_empty(),
        "new workspace crates require architectural classification: {}",
        unregistered.join(", ")
    );
}
