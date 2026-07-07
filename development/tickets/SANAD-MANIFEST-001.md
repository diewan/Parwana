---
id: SANAD-MANIFEST-001
title: "Add canonical off-chain Sanad manifest and CLI display"
theme: "Sanad content identity UX"
crate: "csv-content"
priority: P1
security_critical: true
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-content/src/lib.rs"
target_patterns:
  - "pub use attachments"
  - "pub use content_tree"
target_file_2: "csv-cli/src/commands/sanads.rs"
target_patterns_2:
  - "cmd_create"
  - "cmd_show"
  - "attachments"
interface_files:
  - "csv-protocol/src/sanad.rs"
  - "csv-content/src/attachments.rs"
  - "csv-sdk/src/sanads.rs"
  - "csv-cli/src/state.rs"
reference_crate: "csv-content"
reference_file: "csv-content/src/attachments.rs"
reference_patterns:
  - "pub struct AttachmentRef"
  - "pub enum MediaType"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-content --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-content --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli state_tests --all-features"
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
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

Created Sanads currently look empty to users. The protocol already binds a
`SanadPayloadDescriptor` into the Sanad identity, but the descriptor is mostly a
hash-level commitment:

- schema hash
- payload hash
- optional content root
- optional attachment root
- policy hashes

That is correct for protocol identity, but insufficient for human inspection.
Operators need to see what a Sanad represents without embedding payload blobs or
large attachments directly in the Sanad.

Expected `csv sanad show <sanad_id>` UX should include off-chain manifest data
when available:

- title / short description
- schema or type label
- payload codec and payload hash
- attachment count
- attachment names or CIDs
- media types
- sizes
- hashes
- encryption status / key reference
- content root and attachment root

The full payload and attachment bytes must remain off-chain. The manifest is a
small, canonical, hash-verifiable description that tells users what to fetch and
how to verify it.

## Why it matters

A Sanad is useful only if the holder can understand and verify what it binds.
Without a manifest, users see only an opaque ID and commitment. That makes
off-chain transfer acceptance hard to audit and prevents a future P2P content
layer from having a stable metadata object to exchange before fetching blobs.

This is security-sensitive because the manifest hash/roots must match the
existing protocol descriptor. CLI display must not show unauthenticated metadata
as if it were bound to the Sanad. If the local manifest is missing or does not
match the Sanad descriptor roots, the CLI must say so clearly.

## Task

Introduce a canonical off-chain Sanad manifest model owned by `csv-content` and
wire it into Sanad creation and display.

The manifest should describe content and attachments without carrying full
payload blobs:

```rust
pub struct SanadManifest {
    pub version: u16,
    pub title: Option<String>,
    pub description: Option<String>,
    pub schema: String,
    pub payload_codec: String,
    pub payload_hash: Hash,
    pub content_root: Option<Hash>,
    pub attachments: Vec<SanadManifestAttachment>,
    pub attachment_root: Option<Hash>,
    pub disclosure_policy_hash: Option<Hash>,
    pub proof_policy_hash: Option<Hash>,
}

pub struct SanadManifestAttachment {
    pub name: Option<String>,
    pub cid: Option<String>,
    pub media_type: MediaType,
    pub size: u64,
    pub hash: Hash,
    pub encrypted: bool,
    pub encryption_key_id: Option<String>,
}
```

This shape is illustrative. Prefer existing `AttachmentRef` and `MediaType`
where possible, but add fields needed for user-facing display such as `name` and
`encrypted`.

## Scope

Implement this as an off-chain manifest/cache feature. Do not put the manifest
body on-chain. On-chain state should continue to carry only commitments/seal
state. The manifest may be carried in future consignments or P2P messages, but
this ticket should focus on the local creation/cache/display path.

## Acceptance criteria

- [ ] `csv-content` exposes a `SanadManifest` type with canonical encoding and a
      stable hash function.
- [ ] The manifest can compute or validate `payload_hash`, `content_root`, and
      `attachment_root` from declared payload/attachment references.
- [ ] Attachment references include enough metadata for display: name or CID,
      media type, size, hash, and encryption status.
- [ ] `csv sanad create` can accept a manifest file, or can produce/cache a
      manifest from `--payload` and `--attachments` arguments.
- [ ] Sanad creation binds the manifest-derived hashes into
      `ContentDescriptorInput`; it must not silently diverge from the manifest.
- [ ] Local CLI state stores or indexes the manifest by Sanad ID or descriptor
      hash without making it protocol authority state.
- [ ] `csv sanad show <sanad_id>` displays manifest details when a matching
      manifest is available locally.
- [ ] `csv sanad show <sanad_id>` clearly reports when only hashes are available
      and the manifest body is missing locally.
- [ ] If a manifest exists but its hash/roots do not match the Sanad descriptor
      cache, the CLI must warn and refuse to present it as verified metadata.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, zero-hash placeholders, fake proofs, or silent fallbacks.
- [ ] Positive tests cover manifest creation, hash/root derivation, and
      `sanad show` rendering verified metadata.
- [ ] Negative tests cover tampered manifest/attachment hash mismatch and missing
      manifest display.
- [ ] All `verify_commands` pass.

## Notes

This feature should make Sanads feel non-empty while preserving the architecture:

- on-chain: commitment/seal state only
- protocol descriptor: canonical hashes and roots
- manifest: human-readable, off-chain, hash-bound metadata
- payload/attachments: off-chain blobs delivered later by application/P2P
- CLI state: cache and display only

Do not use `serde_json` for canonical hashing paths. JSON may be accepted as a
CLI authoring format only if it is converted into the canonical manifest before
hashing/binding.
