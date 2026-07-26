# Portable conformance package

`manifest.json` is the versioned Stage 4 hostile-conformance inventory consumed
through `csv_sdk::v2::conformance_manifest()`. Regenerate it with:

```text
python3 scripts/generate-portable-conformance.py
```

Every case pins its wire and contract versions, expected assurance dimensions,
stable reason code, immutable input bytes where applicable, and the executable
test that establishes the behavior. Native and WASM capabilities are explicit;
an unsupported persistent store never degrades verification.
