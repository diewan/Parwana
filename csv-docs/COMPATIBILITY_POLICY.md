# CSV Compatibility Policy

**Status:** Normative.  
**Owner:** TBD.  
**Applies from:** the next coordinated release after adoption.  
**Repository strategy:** harden this workspace in place; no repository extraction
is authorized by this policy.

This policy distinguishes package API compatibility from protocol compatibility.
An implementation MUST reject an unknown or unsupported security-critical
version; it MUST NOT guess a decoder, hash domain, event layout, or contract
interface.

## Compatibility domains

| Domain | Owner | Compatibility rule | Unsupported input |
|---|---|---|---|
| Rust public API | owning crate | Cargo SemVer; L0-L4 changes additionally require an approved API snapshot update | compile-time incompatibility |
| Protocol semantics | `csv-protocol` | `ProtocolVersion.major` must match an implemented major | reject before state transition |
| Canonical CBOR and typed hashes | `csv-codec`, `csv-hash` | bytes, field order, and domain tags are immutable within a protocol major | reject malformed or unknown versioned envelope |
| Proof bundles and replay IDs | `csv-proof`, `csv-verifier` | version and every security binding are verified before use | reject before mint or settlement |
| Wire messages | `csv-wire` | a wire major is exact; additive fields require an explicit minor discriminator | typed decode error |
| Schemas | `csv-schema` | schema ID and version are part of the signed/committed input | reject unknown schema/version |
| Contract events and bindings | contracts and `csv-contract-bindings` | ABI/IDL/event checksum must match the deployment manifest | reject event or call |
| Deployments | `deployments/` | signed manifest binds network and contract/program/package identity | fail manifest verification/load |

`ProtocolVersion` already requires rejection of a proof with a newer major
version in the constitution. This policy extends that fail-closed rule to every
security-critical boundary above. A lower version is accepted only while it is
explicitly listed in the release compatibility matrix; deprecated is not a
synonym for accepted.

## Supported release combinations

During a coordinated release, the following combinations are supported:

| Consumer | Required producer versions |
|---|---|
| CLI/tools | current runtime and SDK; previous runtime only when its protocol/wire major is listed in the release notes |
| Runtime | current core, verifier, and ports; N-1 adapters only when adapter conformance passes against the current golden corpus |
| Adapter | current ports and wire; N-1 core/runtime only when the same protocol major and corpus version are supported |
| Contract bindings | exact released ABI/IDL and deployment-manifest checksum; no implicit N-1 allowance |
| Contracts | current protocol major; an old contract remains usable only through a deployment-specific compatibility entry |

N/N-1 support is opt-in per release, tested against the immutable golden corpus,
and expires at the next coordinated release unless renewed. It is a workspace
compatibility promise, not an authorization to split repositories.

## Core-layer change gate

The protected core is L0-L4: `csv-algebra`, `csv-wire`, `csv-hash`,
`csv-protocol`, and `csv-verifier`. A public API change in any of these layers
is a build-breaking governance event even when Cargo SemVer would call it
additive. It requires all of the following:

1. the public-API snapshot architecture test passes with the intentional
   snapshot update reviewed;
2. a changelog entry in the changed core crate; and
3. the shared conformance corpus passes for the affected layer group.

This rule encodes ownership in CI rather than assigning a person. Owner: TBD.

## Change and deprecation rules

1. Rust-only additive API changes follow SemVer and do not change protocol,
   wire, corpus, ABI, or deployment versions.
2. Any canonical-byte, typed-hash, replay-input, proof, schema, wire, event,
   ABI/IDL, or deployment-identity change requires a compatibility review, new
   immutable vectors, and coordinated core/runtime/adapter/binding releases.
3. A breaking protocol or wire change increments the relevant major version.
   Additive optional data requires an explicit discriminator and an unknown-
   version rejection rule before shipping.
4. Deprecation lasts at least 30 days unless a security emergency requires an
   earlier fail-closed sunset.
5. An emergency security release may remove an unsafe version immediately;
   consumers MUST reject it rather than downgrade verification.

## Required implementation work

The current codebase does not yet expose a single discriminator for every
wire-message and contract-event family. Before claiming independent-release
support, create one atomic implementation ticket per missing discriminator,
with decoder rejection tests and golden vectors. This policy does not authorize
permissive decoding while that work is pending.

## Release evidence

Every release records supported combinations, protocol/wire/corpus versions,
ABI/IDL checksums, deployment-manifest digest, and the conformance CI run.
