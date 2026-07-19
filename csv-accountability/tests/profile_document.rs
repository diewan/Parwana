use std::{collections::BTreeSet, fs, path::Path};

const PROFILE: &str = include_str!("../../csv-docs/PROTOCOL_INVARIANTS.md");
const EXPECTED_INVARIANTS: usize = 15;

#[test]
fn every_accountability_invariant_has_a_live_automated_test_mapping() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate must have a workspace parent");
    let mut ids = BTreeSet::new();

    for line in PROFILE.lines().filter(|line| line.starts_with("| `ACC-")) {
        let cells: Vec<_> = line.split('|').map(str::trim).collect();
        assert_eq!(
            cells.len(),
            5,
            "malformed accountability invariant row: {line}"
        );

        let id = cells[1].trim_matches('`');
        assert!(ids.insert(id), "duplicate accountability invariant: {id}");

        let mappings: Vec<_> = cells[3]
            .split(';')
            .map(str::trim)
            .map(|mapping| mapping.trim_matches('`'))
            .filter(|mapping| !mapping.is_empty())
            .collect();
        assert!(!mappings.is_empty(), "{id} has no automated test mapping");

        for mapping in mappings {
            let (relative_path, test_name) = mapping
                .rsplit_once("::")
                .unwrap_or_else(|| panic!("invalid test mapping for {id}: {mapping}"));
            assert!(
                relative_path.ends_with(".rs"),
                "mapping is not Rust test source: {mapping}"
            );

            let source_path = workspace.join(relative_path);
            let source = fs::read_to_string(&source_path)
                .unwrap_or_else(|error| panic!("stale mapping {mapping}: {error}"));
            let function_marker = format!("fn {test_name}(");
            assert!(
                source.contains(&function_marker),
                "stale mapping {mapping}: {test_name} is absent from {}",
                source_path.display()
            );
            let prefix = &source[..source
                .find(&function_marker)
                .expect("marker existence was checked")];
            let attribute_window = &prefix[prefix.len().saturating_sub(160)..];
            assert!(
                attribute_window.contains("#[test]") || attribute_window.contains("#[cfg(test)]"),
                "mapping does not identify an automated test: {mapping}"
            );
        }
    }

    assert_eq!(
        ids.len(),
        EXPECTED_INVARIANTS,
        "Accountability Profile must enumerate ACC-01 through ACC-15"
    );
    for number in 1..=EXPECTED_INVARIANTS {
        let id = format!("ACC-{number:02}");
        assert!(
            ids.contains(id.as_str()),
            "missing accountability invariant {id}"
        );
    }
}

#[test]
fn profile_preserves_authority_and_evidence_limitations() {
    let normalized_profile = PROFILE.split_whitespace().collect::<Vec<_>>().join(" ");
    let required_clauses = [
        "### What Evidence Never Proves",
        "does not prove that every statement",
        "does not prove that an action was authorized",
        "Evidence reconstructed after an event never becomes a mandate",
        "does not prove success when the external outcome is `Unknown`",
        "Missing evidence does not prove non-occurrence",
        "does not prove that undisclosed branches are absent",
        "does not prove provenance",
        "does not automatically prove the corresponding claim",
        "does not grant authority",
        "does not replace canonical evidence",
        "does not prove that the selected policies",
        "does not prove every off-chain statement is true",
    ];

    for clause in required_clauses {
        assert!(
            normalized_profile.contains(clause),
            "missing normative negative clause: {clause}"
        );
    }
}
