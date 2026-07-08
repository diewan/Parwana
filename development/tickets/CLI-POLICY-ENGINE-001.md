---
id: CLI-POLICY-ENGINE-001
title: "--disclosure-policy and --proof-policy flags parse then unconditionally error"
theme: "sanad create disclosure/proof policy UX"
crate: csv-cli
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-cli/src/commands/sanads.rs"
target_patterns:
  - "Disclosure policy parsing is not yet implemented"
  - "Proof policy parsing is not yet implemented"
  - "This feature requires Phase 5 policy engine integration"
interface_files:
  - "csv-cli/src/commands/sanads.rs"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "vec![0u8;"
  - "Hash::new([0u8; 32])"
  - "Ok(true) // Placeholder"
  - "Ok(0) // Placeholder"
contract_files: []
cross_boundary_check: false
---

## Problem

`csv sanad create` accepts `--disclosure-policy` and `--proof-policy` flags
(`csv-cli/src/commands/sanads.rs:55,58`), but every code path that uses them
unconditionally errors (`sanads.rs:464-482`):

```rust
// Parse disclosure policy if provided
if let Some(ref disclosure_policy_path) = disclosure_policy {
    output::kv("Disclosure policy", disclosure_policy_path);
    return Err(anyhow::anyhow!(
        "Disclosure policy parsing is not yet implemented. Policy file: {}. \
         This feature requires Phase 5 policy engine integration.",
        disclosure_policy_path
    ));
}

// Parse proof policy if provided
if let Some(ref proof_policy_path) = proof_policy {
    output::kv("Proof policy", proof_policy_path);
    return Err(anyhow::anyhow!(
        "Proof policy parsing is not yet implemented. Policy file: {}. \
         This feature requires Phase 5 policy engine integration.",
        proof_policy_path
    ));
}
```

Both flags are accepted by the `clap` argument parser (they show up in
`--help` and are parsed successfully), but supplying either one always ends
the command in an error referencing a "Phase 5 policy engine" that does not
exist anywhere else in this repository — no RFC, doc, or ticket under
`csv-docs/` or `development/tickets/` currently describes or tracks this
"Phase 5" work (confirmed by repo-wide search at audit time). Note the repo
does have `disclosure_policy_hash`/`proof_policy_hash` flags (the "legacy"
hex-hash flags, `sanads.rs:62-67`) which are a separate, already-working path
(`parse_opt_hash`, `sanads.rs:834-836`) — this ticket is only about the
newer `--disclosure-policy`/`--proof-policy` *file path* flags, not the
hash flags.

## Why it matters

This is minor but user-facing: a flag that parses successfully but always
errors is confusing UX, and the error references phantom prior work ("Phase 5
policy engine integration") that a user (or future engineer) cannot locate or
track anywhere in the repository.

## Task

Either:

- **(a) Implement.** Build the disclosure/proof policy engine this depends on
  — this is a larger, separate scope. Before starting, search
  `csv-docs/` and `development/tickets/` again for any policy-engine RFC/ticket
  that may have landed since this audit; if one exists, make this ticket
  depend on it / reference it instead of duplicating scope. At audit time, no
  such RFC or ticket existed, so this may require originating the design
  itself (parse a policy file into `SanadPayloadDescriptor`'s
  `disclosure_policy_hash`/`proof_policy_hash` fields, presumably).
- **(b) Hide until ready.** As a smaller near-term fix, mark
  `--disclosure-policy` and `--proof-policy` as not-yet-available in a way
  users discover before constructing a full command, not after: e.g., a
  clap `hide = true` flag (so it doesn't appear in `--help` implying it
  works) with a dedicated pre-parse check that errors immediately and
  accurately, without inventing a phantom "Phase 5" reference — point instead
  at this ticket ID (`CLI-POLICY-ENGINE-001`) or wherever the real tracking
  now lives.

Prefer (b) unless a genuine policy-engine design/ticket already exists to
build against.

## Acceptance criteria

- [ ] Flag behavior is either fully implemented (policy file parsed and bound
      into the Sanad's disclosure/proof policy hashes correctly), or clearly
      and accurately communicated as unavailable with a pointer to a real
      tracking reference (not an unattested "Phase 5" mention).
- [ ] No dead-end flags with a generic/unverifiable error message remain.
- [ ] If hidden, `--help` output does not advertise a non-functional flag as
      if it works.
- [ ] Existing `--disclosure-policy-hash`/`--proof-policy-hash` (legacy hash)
      flags are unaffected by this change.
- [ ] All `verify_commands` pass.

## Notes

If choosing (b), keep the fix scoped to `sanads.rs` — do not start
implementing the policy engine itself as a side effect of "just fixing the
error message."
