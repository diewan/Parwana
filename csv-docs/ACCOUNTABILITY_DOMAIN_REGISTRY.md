# Accountability Domain Registry

Status: normative for Accountability Profile `0.1`, object schema `1`.

All tags are immutable compatibility surfaces. Hashing uses Parwana's canonical
BIP-340-style tagged-hash construction through `csv-hash`; the registered tag
is never reused for a different semantic object.

| Semantic object | Registered domain tag |
|---|---|
| Action intent | `csv.accountability.intent.v1` |
| Action mandate | `csv.accountability.mandate.v1` |
| Execution attempt | `csv.accountability.attempt.v1` |
| Execution receipt | `csv.accountability.receipt.v1` |
| Evidence node | `csv.accountability.evidence.v1` |
| Dispute bundle manifest | `csv.accountability.bundle.v1` |
| Verification context | `csv.accountability.verification-context.v1` |
| Assurance profile | `csv.accountability.assurance-profile.v1` |
| Gate profile | `csv.accountability.gate-profile.v1` |
| Disclosure commitment | `csv.accountability.disclosure.v1` |
| Preservation envelope (reserved) | `csv.accountability.preservation.v1` |

Adding a semantic object requires a new unique tag, collision-test coverage,
and governed compatibility review. Changing an existing tag creates different
identifiers and therefore requires a new object/domain version.
