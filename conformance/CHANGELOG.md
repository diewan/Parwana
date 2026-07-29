# Parwana contract package changelog

The contract package is `contract-manifest.toml` plus the corpus it names
(`csv-testkit/corpus/v1`). This file records what changed in each published
`contract_version` so a consumer can tell whether moving its pin forward is
additive or breaking.

`contract_version` is **not** the Cargo crate version. The crate has been
`0.1.5` throughout; the contract package advanced independently. A consumer
pins `contract_version`, `source.value`, and `corpus.digest` — not the crate.

Each entry names the commit whose corpus produces the published digest. The
manifest's `source.value` and `corpus.digest` must always agree with each
other; see 0.1.10 for what happens when they do not.

## Portable conformance `stage5-v2`, reason-code registry v1, transition vectors v2 — 2026-07-29 (PAR-CONF-006)

**Breaking for any consumer routing on the portable package's reason codes.**

Publishes `conformance/v2-reason-code-registry.toml`: the complete V2 protocol
reason-code vocabulary, generated from each owning crate's own `registry_id`
function. This was the one contract-package component the charter's
cross-repository contract discipline named that had never been produced. It is
disjoint from the V1 `ACCOUNTABILITY.*` registry.

Fourteen codes the portable package told consumers to expect were emitted by
nothing in the repository. They are now either emitted or replaced:

- The eleven malicious-graph codes had no counterpart in the kernel, which
  reported typed errors with no stable identifiers. `DagStructureError`,
  `ResolutionError`, `ReferenceDecodeError`, and `ExclusivityError` now publish
  identifiers, and the package cites those. Four package codes were **removed**
  and have no successor under their old spelling:
  - `PROTOCOL.DAG.DUPLICATE_NODE` → `PROTOCOL.DAG.DUPLICATE_NODE_ID`
  - `PROTOCOL.STATE.COMMITMENT_MISMATCH` → `PROTOCOL.DAG.NODE_ID_MISMATCH`
  - `PROTOCOL.STATE.OUTPUT_NOT_FOUND` → `PROTOCOL.RESOLUTION.WRONG_OUTPUT_INDEX`
  - `PROTOCOL.TRANSITION.COMMITMENT_MISMATCH` →
    `PROTOCOL.RESOLUTION.COMMITMENT_MISMATCH`
- `ACCEPT.V2.ACCEPTED` is now emitted: recipient acceptance had only failure
  codes, so the positive path had no publishable outcome.
- `RUNTIME.SEND.RECOVERED` is now emitted. `SendReceipt` carries a
  `SendCompletion`, so a resumed send is distinguishable from a fresh one.
- `STORAGE.CHECKPOINT.ORPHANED` is now emitted. Accepted-state reconciliation
  had hardcoded `BITCOIN.CHECKPOINT.*` and `BITCOIN.ANCESTOR.NONFINAL` into a
  chain-agnostic store, so a Sui or Aptos closure reported a Bitcoin reason
  code. The identifiers are now `STORAGE.*` and name no chain. Consumers
  matching the `BITCOIN.*` spellings in accepted-state observations must move.
- `WIRE.V1.PORTABLE_NON_EQUIVOCATION_UNAVAILABLE` is now emitted by legacy V1
  inspection, alongside four sibling codes for what V1 cannot establish.
- The runtime's accepted-state observation reason changed from the unregistered
  `ACCEPTANCE.V2.COMMITTED` to `STORAGE.ACCEPTANCE.COMMITTED`.

Transition vectors v2 adds the seven missing negative vectors — `graph-cycle`,
`graph-self-parent`, `graph-missing-parent`, `graph-noncanonical-order`,
`canonical-root-recomputed`, `parent-output-index-absent`, and
`parent-commitment-mutated` — plus a published `parent_output` fixture the
resolution vectors resolve against. Every negative vector now declares an
`expected_reason_code` and its executor asserts the rejection path emits it. All
eleven malicious-graph cases are backed by an executed vector; none is
undistributed.

Every case that still distributes nothing now records `consumer_must_supply`
naming what to provide instead. The four `proof-wrong-*` cases will **not**
ship an encoded `bitcoin-spv-v1` proof: a real one is a signet header chain plus
a merkle branch, the generator has no chain access, and bytes shaped like a
proof that attest to nothing would misrepresent the case. That decision is
recorded in the package.

Gates added, so this cannot drift again: the generator refuses to write a case
whose code is not in the registry; the published registry must equal the
implementation's projection; a vector-backed case must expect its vector's own
code; and `scripts/check-v2-release.py` re-checks the same from the published
files alone.

## V2 transition vectors v1 — 2026-07-26 (PAR-VECTORS-001)

Adds the language-neutral `conformance/v2-transition-vectors.json` package.
It freezes positive vectors for node and segment identity, consumed and
evidence references, signature-bearing node bytes, and output-use semantics,
plus negative vectors whose machine-readable rejection reasons are pinned.
This package is independent of the V1 accountability corpus named by
`contract-manifest.toml`; later wire-affecting work must version this package
explicitly rather than silently rewriting its bytes.

## 0.1.10 — 2026-07-26 (PAR-PIN-001)

**Breaking.** Republishes the corpus as it has actually stood since `11423c6`,
and repairs the manifest's internal consistency.

Breaking change, previously unpublished:

- `ACCOUNTABILITY.PRESERVATION.NOT_EVALUATED_V0_1` (variant
  `PreservationSemanticsDeferred`) was **removed** in `11423c6`. A consumer
  that recognizes this reason code will no longer receive it.

Additive changes, previously unpublished:

- `11423c6` replaced the removed code with seven preservation codes:
  `EVIDENCE_ABSENT`, `EVIDENCE_INVALID`, `AUTHENTICITY_REJECTED`,
  `AUTHENTICITY_UNKNOWN`, `ALGORITHM_DEPRECATED`, `ALGORITHM_DISALLOWED`,
  `ALGORITHM_UNKNOWN`.
- `3ce86db` (AUTHREC-01) added three-state authority-reconstruction codes.
- `5ac9a10` (EVIDV2-01) added canonical conflict and custody evidence codes.

Manifest repairs:

- `source.value` moved from `9b3fd916` to `d6a39330`. It had been stale since
  at least 0.1.9: the manifest declared `9b3fd916` as its source while
  publishing `08ebb8ff…`, which is the digest of the corpus at `a623d10`. No
  commit ever produced that pairing, so every consumer pin validating against
  0.1.9 was validating a combination that did not exist.
- `corpus.digest` moved to `39869b92…`, recomputed from `d6a39330`.

The three prior corpus changes reached consumers with no version bump and no
digest refresh, so they were invisible to the pin gate. Publishing them under
one new version is what makes the removal above visible; it is not a new
change.

## 0.1.9 — `a623d10` (PROFILE-02)

Second action profile: production database migration. Digest `08ebb8ff…`,
which is correct for this commit's corpus. `source.value` was not updated and
continued to name `9b3fd916`.

## 0.1.8 — `bee8308` (ANCHOR-01)

On-chain commitment anchor node (commitment, finality, reorg). Digest
`832ff237…`.

## 0.1.7 — `441cd52`

Anchor port and adapter; anchor results registered as evidence sources. Digest
`122e4248…`.

## 0.1.6 — `32fd3c6`

Opened the profile boundary; reason-code registry established. Digest
`8d2718ec…`.

## 0.1.5 — `754e21e`

First published contract package. Digest `9158785f…`, computed from the corpus
at `9b3fd916`. This is the version and digest the three consumer pins carried
until PAR-PIN-001; they were internally consistent, only four versions behind.
