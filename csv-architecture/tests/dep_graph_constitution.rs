/// Architectural Constitution Test
///
/// This test is the machine-readable architectural contract.
/// It runs on every CI push. Failure is a build break, not a warning.
///
/// Boundary definitions:
///   csv-algebra           — pure types, no_std, no serde, no IO
///   csv-wire              — serde + transport boundary
///   csv-hash/protocol     — cryptographic and protocol primitives
///   csv-verifier          — chain-agnostic verification
///   csv-coordinator       — orchestration and feature-gated adapter assembly
///   csv-runtime           — transfer authority over chain-agnostic interfaces
///   csv-adapters/*        — concrete chain implementations
///   csv-sdk/csv-cli       — user-facing facade and application
///
/// FORBIDDEN: adapters importing coordinator/runtime.
/// FORBIDDEN: verifier importing concrete adapters.
/// FORBIDDEN: algebra importing another workspace crate.
use std::collections::HashMap;
use std::fs;

#[test]
fn forbidden_dependency_edges_are_absent() {
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

        if pkg.name == "csv-algebra" && !pkg.dependencies.is_empty() {
            violations.push(format!(
                "VIOLATION: csv-algebra has dependencies [{}] — algebra must remain dependency-free",
                pkg.dependencies
                    .iter()
                    .map(|dependency| dependency.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
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

#[test]
fn workspace_release_metadata_is_coherent() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path("./Cargo.toml")
        .exec()
        .expect("cargo metadata must succeed");
    let workspace_packages: HashMap<_, _> = metadata
        .workspace_packages()
        .iter()
        .map(|package| (package.name.as_str(), *package))
        .collect();
    let release_version = &workspace_packages
        .get("csv-protocol")
        .expect("csv-protocol must remain a workspace package")
        .version;
    let rust_version = workspace_packages
        .get("csv-protocol")
        .and_then(|package| package.rust_version.as_ref())
        .expect("csv-protocol must declare the workspace MSRV");
    let mut violations = Vec::new();

    for package in metadata.workspace_packages() {
        if package.version != *release_version {
            violations.push(format!(
                "{} has version {}, expected workspace release version {}",
                package.name, package.version, release_version
            ));
        }
        if package.rust_version.as_ref() != Some(rust_version) {
            violations.push(format!(
                "{} has rust-version {:?}, expected {}",
                package.name, package.rust_version, rust_version
            ));
        }

        for dependency in &package.dependencies {
            let Some(internal_package) = workspace_packages.get(dependency.name.as_str()) else {
                continue;
            };
            if dependency.path.is_none() {
                violations.push(format!(
                    "{} -> {} must retain a local path for workspace development",
                    package.name, dependency.name
                ));
            }
            if dependency.req.to_string() == "*" {
                violations.push(format!(
                    "{} -> {} must declare a registry version alongside its local path",
                    package.name, dependency.name
                ));
            }
            if !dependency.req.matches(&internal_package.version) {
                violations.push(format!(
                    "{} -> {} requires {}, which does not include workspace version {}",
                    package.name, dependency.name, dependency.req, internal_package.version
                ));
            }
        }
    }

    let toolchain = fs::read_to_string(metadata.workspace_root.join("rust-toolchain.toml"))
        .expect("workspace rust-toolchain.toml must be readable");
    let expected_channel = format!(
        "channel = \"{}.{}\"",
        rust_version.major, rust_version.minor
    );
    if !toolchain
        .lines()
        .any(|line| line.trim() == expected_channel)
    {
        violations.push(format!(
            "rust-toolchain.toml must pin the workspace rust-version {rust_version}"
        ));
    }

    assert!(
        violations.is_empty(),
        "WORKSPACE RELEASE METADATA VIOLATED:\n{}",
        violations.join("\n")
    );
}
