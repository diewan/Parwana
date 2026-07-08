---
id: PROOF-COMMITMENT-VERIFY-001
title: "KZG and Bulletproof commitment verify() accept any non-empty proof"
theme: "advanced commitment scheme stubs"
crate: csv-proof
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-proof/src/commitments_ext.rs"
target_patterns:
  - "pub struct KZGCommitment"
  - "impl KZGCommitment"
  - "pub struct BulletproofCommitment"
  - "impl BulletproofCommitment"
  - "!self.commitment.is_empty()"
  - "!self.commitment_a.is_empty() && !self.commitment_b.is_empty()"
interface_files:
  - "csv-proof/src/lib.rs"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-proof --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-proof --all-features"
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
  - "!self.commitment.is_empty()"
  - "!self.commitment_a.is_empty()"
contract_files: []
cross_boundary_check: false
---

## Problem

`csv-proof/src/commitments_ext.rs` defines two public commitment types whose
`.verify()` methods do not perform real cryptographic verification:

```rust
/// KZG polynomial commitment stub
pub struct KZGCommitment { pub commitment: Vec<u8>, pub degree: usize, pub num_points: usize }

impl KZGCommitment {
    /// Verify a KZG proof
    ///
    /// In a real implementation, this would use pairing-based verification:
    /// e([f(s)]_1, [1]_2) == e([witness]_1, [s - alpha]_2)
    pub fn verify(&self, _proof: &[u8], _public_inputs: &[u8]) -> bool {
        // Stub: real implementation requires elliptic curve pairing crate
        !self.commitment.is_empty()
    }
}
```

```rust
/// Bulletproofs inner product argument stub
pub struct BulletproofCommitment { pub commitment_a: Vec<u8>, pub commitment_b: Vec<u8>, ... }

impl BulletproofCommitment {
    /// Verify a Bulletproof
    pub fn verify(&self, _proof_data: &[u8]) -> bool {
        // Stub: real implementation requires elliptic curve crate
        !self.commitment_a.is_empty() && !self.commitment_b.is_empty()
    }
}
```

Both `verify()` methods ignore their `_proof`/`_proof_data`/`_public_inputs`
arguments entirely and instead check whether the *commitment itself* is
non-empty. Any non-empty garbage byte string set as `commitment`
(`commitment_a`/`commitment_b`) will make `.verify()` return `true` regardless
of what proof bytes are passed in.

The module doc comment does already disclose this: `commitments_ext.rs:1-9`
states *"**Note:** ZK-proof verification is NOT implemented yet. This module
provides type infrastructure for indexing and querying."* — so the gap is not
undocumented at the module level, but the individual `.verify() -> bool`
method signatures read exactly like real pass/fail crypto verification and
give no such warning at the call site.

`KZGCommitment` and `BulletproofCommitment` are public types reachable via the
public `commitments_ext` module (`csv-proof/src/lib.rs:28`, `pub mod
commitments_ext;` — note they are not individually re-exported by name at the
crate root, only reachable as `csv_proof::commitments_ext::KZGCommitment` /
`::BulletproofCommitment`; the module itself is public API). A repo-wide
search found zero internal callers of either `.verify()` method — the blast
radius today is limited to any external consumer of `csv-proof` who
constructs one of these types directly.

## Why it matters

`.agents/AGENT.md §3` is explicit: *"`Ok(true)` in verification paths is
forbidden"* and every verification path *"MUST perform actual cryptographic
verification"* and *"MAY NEVER silently pass, fallback, infer success from
missing fields, substitute defaults."* Although these methods return `bool`
rather than `Ok(true)`, the effect is the same shape of bug: a
verification-looking function that returns a pass/fail crypto result while
performing no cryptography. A public type whose `.verify()` reads as real
crypto but is not is a trap for any external consumer of `csv-proof` — even
with the module doc comment disclosing the limitation, `.verify()` returning a
plain `bool` gives no signal at the call site that the check performed no
actual verification.

## Task

Either:

- **(a) Implement real verification.** Add real KZG pairing-based verification
  and real Bulletproofs inner-product-argument verification, using an
  appropriate elliptic-curve/pairing crate consistent with the rest of the
  workspace's crypto dependencies; or
- **(b) Fail closed instead of lying.** If full ZK verification implementation
  is out of scope for this ticket, make the incompleteness impossible to
  misuse silently: change `.verify()` to return `Result<(), CommitmentError>`
  (or the crate's existing verification error type) and return
  `Err(NotImplemented)` (or equivalent) unconditionally, rather than a `bool`
  that reads as a pass/fail crypto result from non-empty-check heuristics.
  Feature-gate or otherwise mark the types so an unimplemented verifier cannot
  be called without the caller explicitly acknowledging it is not yet real
  verification (e.g., a clearly named method, or a doc-visible `Err` variant
  naming the gap).

Prefer (b) as the minimum acceptable fix if full ZK verification is a larger
follow-up; do not leave `.verify() -> bool` returning `true` for
non-empty-but-cryptographically-meaningless input in either case.

## Acceptance criteria

- [ ] `.verify()` no longer returns `true` for non-empty-but-cryptographically-invalid
      commitment/proof input on either `KZGCommitment` or `BulletproofCommitment`.
- [ ] Either real verification lands for both types, or both fail closed with a
      clear "not implemented" error distinguishable from a real verification
      failure.
- [ ] Test asserting that garbage (non-empty) commitment + garbage proof bytes
      is rejected, for both `KZGCommitment` and `BulletproofCommitment`.
- [ ] If a real implementation lands, a positive test with a genuine valid
      proof succeeding is added.
- [ ] All `verify_commands` pass.
- [ ] A repo-wide search (`KZGCommitment`, `BulletproofCommitment`, `.verify(`)
      confirms no production caller relies on the old non-empty-check behavior.

## Notes

No internal workspace caller of either `.verify()` method was found at audit
time — this bounds the immediate blast radius to external SDK consumers, but
does not reduce the severity of the API contract violation, since `csv-proof`
is a published-surface crate whose types are meant to be trustworthy on their
own.
