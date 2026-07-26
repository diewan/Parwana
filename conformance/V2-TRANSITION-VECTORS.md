# Parwana V2 transition vectors

`v2-transition-vectors.json` is the language-neutral compatibility baseline for
V2 transition identity and state-use semantics. Native Rust tests, WASM builds,
and downstream conformance suites must consume this exact JSON file; copies or
repackaged variants are not authoritative.

The positive fixture pins node identifiers, signature-bearing node bytes,
segment roots, consumption and evidence references, and output schema
semantics. Every negative vector names the exact machine-readable rejection
reason it must produce.

Canonical bytes marked `frozen` are intentionally preserved across later wire
changes. Changing any expected byte or digest requires:

1. incrementing the JSON `version`;
2. recording the compatibility decision in `conformance/CHANGELOG.md`; and
3. updating every consumer pin in dependency order.
