# Accountability CLI: first canonical intent

This path starts with readable JSON, converts it to Parwana's canonical
`ActionIntent` bytes, and inspects the resulting transport envelope. It does
not issue a mandate, approve an action, execute a deployment, or prove that the
example assertions are true.

## 1. Generate a complete input

```bash
cargo run -p csv-cli -- accountability example-intent \
  --out /tmp/diewan-action-intent-v1.json
```

The output is an `ActionIntentJsonV1`: a strict, versioned JSON input DTO. It
contains a complete GitHub deployment profile, including fixed controls and
opaque byte fields encoded for JSON. Generate it rather than guessing digest,
nonce, context, or profile encodings.

## 2. Create the canonical artifact

```bash
cargo run -p csv-cli -- accountability create-intent \
  --input /tmp/diewan-action-intent-v1.json \
  --out /tmp/diewan-action-intent-artifact.json
```

Parwana parses the JSON DTO, resolves its registered profile codec, rechecks
the target and parameter commitment, then emits a
`CanonicalAccountabilityObjectWire`. Its `canonical_bytes_hex` field contains
the exact bytes produced by the semantic crate's sole canonical serializer.

Malformed hex, unknown fields, unregistered profiles, altered fixed controls,
and profile bytes that do not reproduce the claimed bindings fail closed.

## 3. Inspect without changing bytes

```bash
cargo run -p csv-cli -- accountability inspect \
  --file /tmp/diewan-action-intent-artifact.json
```

Inspection validates the transport envelope and prints its kind, version,
identifier, and canonical byte length. It does not reconstruct organizational
authorization or claim successful execution.

## Names used by this workflow

| Name | Role |
|---|---|
| `ActionIntent` | Canonical protocol domain object describing the exact proposed action. |
| `ActionIntentJsonV1` | Version 1 JSON input DTO; not the canonical hashing representation. |
| `GitHubDeploymentIntentV1Wire` | Provider-profile JSON shape nested inside the DTO. |
| `CanonicalAccountabilityObjectWire` | Transport envelope preserving canonical semantic bytes. |

`ActionIntentWire` and `action_intent_from_wire` remain deprecated
source-compatible aliases for the 0.1.6 migration window. They serialize the
same JSON fields and do not alter canonical bytes or registered identifiers.
New code uses `ActionIntentJsonV1` and `action_intent_from_json`.

The JSON Schema title is `ActionIntentJsonV1`. The legacy schema lookup key
`action-intent-wire` remains available for CLI compatibility; its title and
content describe the current versioned JSON DTO.
