# Preservation envelopes and algorithm agility

Status: normative for Accountability Profile 0.1, object schema 1.

`PreservationEnvelope` retains the exact canonical bytes of a historical
accountability object. Its identifier is derived with the registered
`csv.accountability.preservation.v1` domain. An envelope does not assert that
the historical claim is true and does not replace the original object's
identifier.

## Renewal law

A first envelope has no predecessor. Every renewal points to the immediately
preceding envelope, has a strictly later `preserved_at`, and retains the same
object registry identifier and byte-for-byte identical
`original_canonical_bytes`. A renewal may add algorithm identifiers but cannot
remove identifiers already recorded. Cycles, missing predecessors, duplicate
identifiers, reordered generations, and any historical-byte change fail
closed.

`renewal_material_digest` commits to externally retained renewal material. The
pure protocol does not infer a signature, timestamp, or chain fact from that
digest. Authenticity remains the responsibility of explicit verification
inputs and registered verifier rules. Every generation therefore requires a
canonically sorted context-supplied authenticity conclusion: `Verified` may
proceed to algorithm policy, `Rejected` fails, and `Unknown` or a missing
conclusion is indeterminate.

## Algorithm policy

The effective `VerificationContext.algorithm_policy_digest` commits to the
policy package. The verifier receives the corresponding canonically sorted
algorithm conclusions as explicit input:

- `Allowed` passes the preservation stage.
- `Deprecated` produces an explicit indeterminate downgrade and calls for a
  renewal; historical bytes remain inspectable.
- `Disallowed` fails the preservation stage.
- `Unknown`, including a missing policy entry, is indeterminate and never
  silently falls back to allowed.

The current registered identifier is
`org.diewan.algorithm.sha256-tagged.v1`. Additional identifiers are additive;
changing the meaning of an existing identifier is forbidden.

## Deployment, migration, and rollback

This is an additive object and verifier-input extension. Producers deploy
before consumers start exporting envelopes. Existing bundles without an
envelope remain readable and report preservation evidence as absent rather
than fabricated.

Migration creates a first envelope from the already stored canonical bytes. It
must never decode and re-encode a historical object as a substitute for the
original bytes. Renewals append a new generation; they never update or delete
an earlier generation.

Rollback stops producing new envelopes but retains every recorded generation.
Consumers that do not understand the object continue to verify the original
bundle under their pinned contract version. A rejected or partially deployed
renewal is discarded as a new generation; historical objects and earlier
envelopes are unchanged.
