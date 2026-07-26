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
