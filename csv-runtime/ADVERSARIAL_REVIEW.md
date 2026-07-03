# Runtime Adversarial Review

Living adversarial-review record for `security_critical` tickets touching `csv-runtime`.
Each such ticket MUST land a completed review section here before merge: what could still
fail, and which test (or contract check) prevents it.

Related references:
- RFC-0012 thin-registry mint model: [csv-docs/rfcs/RFC-0012-thin-registry-cross-chain-mint.md](../csv-docs/rfcs/RFC-0012-thin-registry-cross-chain-mint.md)
- Frozen §9.2 digest byte layout: [csv-docs/contracts/ABI_CONSTITUTION.md](../csv-docs/contracts/ABI_CONSTITUTION.md)
- Destination contract adversarial record: [csv-contracts/ADVERSARIAL_REVIEW.md](../csv-contracts/ADVERSARIAL_REVIEW.md)

## Status

| Ticket | Scope | Review |
|--------|-------|--------|
| TRM-RUNTIME-001 | Chain-identity mapping + runtime mint-request alignment (`transfer_coordinator.rs`) | ✅ complete (below) |

---

## TRM-RUNTIME-001 — Chain-identity mapping and runtime mint request alignment

**Reviewed:** 2026-07-03 · **Crate:** `csv-runtime` · **File:** [src/transfer_coordinator.rs](src/transfer_coordinator.rs)

### Change under review

The destination-mint dispatch now builds a `RuntimeMintRequest` carrying the RFC-0012 §9.2
attestation inputs (chain identities via `keccak256("csv.chain.<name>")`, commitment,
lock-event id, nullifier, expiry) plus a `verifier_signatures` vector and the verified
`ProofBundle`, and passes its canonical CBOR to `adapter.mint_sanad`. Both mint sites (the
fresh `execute_outcome` path and the `execute_from_proof` resume path) construct this request
**after** off-chain verification. No proof root, state root, or Merkle-leaf gating remains in
runtime dispatch.

### Threats considered — what could still fail, and what prevents it

| # | Threat | Mitigation / where it fails closed | Guarding test |
|---|--------|-----------------------------------|---------------|
| 1 | **Mint dispatched before proof is verified** (authority bypass). | Both mint sites build the request only after `validate_source_proof` + `verify_proof_bundle` succeed and are journaled (`ProofValidated`). | `verification_failure_prevents_mint_dispatch` asserts a rejecting adapter is never asked to `mint_sanad`; existing `test_adversarial_proof_bundle_rejection`. |
| 2 | **Wrong contract-layer chain identity** lets an attestation for chain A be replayed on chain B. | `contract_chain_id` = `keccak256("csv.chain.<name>")` matches `CSVSeal.CHAIN_*` constants exactly; `destinationChainId` + `sourceChain` are bound into the digest. | `contract_chain_id_matches_rfc0012_vectors` (vs `cast keccak` + independent keccak); `contract_chain_id_is_deterministic_and_distinct_per_chain`. |
| 3 | **Digest byte-layout drift** from the contract → verifier signs a digest the contract will never reproduce (silent mint failure or, worse, a mismatched-but-valid preimage). | `attestation_digest()` reproduces `CSVSeal.mint_attestation_digest` byte-for-byte (23-byte domain tag asserted at compile time; fixed 287-byte preimage). | `attestation_digest_matches_independent_sha256_vector` (independent Python sha256/keccak, 287-byte preimage); `attestation_digest_is_field_sensitive` (no field silently dropped). |
| 4 | **Proof-root gating sneaks back** into runtime dispatch. | The request type has no root field; `grep proof_root/trusted_root` over the runtime is empty. | `build_runtime_mint_request_carries_attestation_not_proof_root`; forbidden-pattern scan. |
| 5 | **Nullifier aliased to sanad id**, weakening the replay-anchoring domain. | Nullifier derives from the source seal outpoint (`csv.mint.nullifier.v1` tagged hash of `seal_ref.id`), not the sanad id. | `build_runtime_mint_request_carries_attestation_not_proof_root` asserts `nullifier != sanad_id`. |
| 6 | **Request corrupted in transit** to the adapter. | Canonical CBOR (`csv-codec`); the adapter receives exactly the encoded request. | `runtime_mint_request_roundtrips_through_canonical_cbor`; `mint_dispatch_hands_adapter_the_attestation_request` decodes the payload the adapter actually received. |
| 7 | **Runtime forges authority** (signs its own mint). | The runtime holds no verifier key and cannot bind `destination_contract` (`address(this)`), so it emits `verifier_signatures = []` and `destination_contract = [0;32]`. An empty/zeroed request cannot mint: the contract reverts on `InsufficientSignatures` and on a digest computed with a zero contract address. Fail-closed by construction. | Contract-side `_require_verifier_threshold` / digest binding (see contract review); runtime carries but never fabricates signatures. |
| 8 | **wasm build regression** (runtime must stay adapter-free + wasm-compatible). | No new dependency added; hashing reuses `csv_protocol::cross_chain` (already wasm-built). No adapter import. | `cargo build -p csv-runtime --no-default-features --target wasm32-unknown-unknown` (see residual note). |

### Residual gaps (tracked for follow-up tickets — NOT closed here)

1. **Adapters not yet realigned.** The ETH adapter still decodes the mint payload as a bare
   `ProofBundle` and still builds the legacy `mintSanad(...,proof_root)` calldata in
   [sanad_contract.rs](../csv-adapters/csv-ethereum/src/sanad_contract.rs). A live BTC→ETH mint
   will fail to decode the new `RuntimeMintRequest` until each adapter's alignment ticket lands.
   This is the intended sequencing (runtime first; adapters after — `development/order.txt`), but
   it means the end-to-end mint path is **not** green until then. Owner of risk: TRM-ETH-ADPT-001
   and siblings.
2. **`destination_owner` is empty** until the interactive/materialize owner-wiring lands; the
   digest currently binds `keccak256("")`. The contract accepts arbitrary owner bytes, so this is
   a semantic-binding gap, not a safety hole, but it must be closed before real recipients.
3. **No verifier-signing infrastructure** exists in the runtime or verifier yet; the
   adapter/verifier that holds the key must produce the §9.2 signatures. Until that lands, the
   request is structurally complete but unsigned.
4. **Second independent review pass** (the `security_critical` protocol asks for one, ideally with
   a stronger model) has not been run — this section is a single self-review pass.

### Verification run

- `cargo test -p csv-runtime` → 71 passed (incl. the 7 tests above).
- `cargo build -p csv-runtime` and downstream `csv-sdk` / `csv-cli` compile; `cargo fmt` clean; no new clippy warnings.
- Pre-existing, not caused by this change: a `TransferLease` doctest in `user_runtime_lease.rs`
  fails to compile (confirmed by stashing this diff); the wasm build fails in `bzip2-sys`
  (`rocksdb → csv-storage`) because this environment's clang lacks a wasm libc sysroot — a
  dependency/toolchain issue that precedes any runtime Rust compilation.
