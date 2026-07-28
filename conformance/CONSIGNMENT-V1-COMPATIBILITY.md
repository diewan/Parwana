# Consignment V1 compatibility

Legacy V1 consignments are supported only through the explicit
`Consignment::decode_v1_for_inspection` entry point. V2 consignments are
supported only through `ConsignmentV2::decode_v2`. Callers must select the
expected format; Parwana does not auto-detect or fall back between versions.

## Supported V1 form

The supported form is the unique canonical CBOR encoding of the original
four-field V1 `Consignment`: `version`, `invoice`, `sanad_id`, and
`proof_bundle`. The envelope, invoice, and proof bundle must all use their
supported V1 versions. The invoice schema identifier, destination seal, and
sanad identifier must be structurally inspectable.

The result is a `LegacyConsignmentInspection`, not a `ConsignmentV2`. It
preserves the invoice, sanad identifier, and legacy proof bundle for forensic
inspection. It reports destination consistency without claiming that the
legacy proof material was cryptographically verified.

## Unavailable V2 integrity

V1 has no distinct consumed-state reference, chain-native source closure, or
authorization over a commitment to the complete portable envelope. Every V1
inspection therefore reports:

```text
source_closure: unavailable
complete_envelope_authorization: unavailable
portable_non_equivocation: unavailable
```

Legacy inclusion or finality fields do not fill those gaps. They remain
`present_unverified` proof material and cannot upgrade the result.

`LegacyConsignmentInspection` has no conversion into `ConsignmentV2` and is
not accepted by the V2 validation path. Parwana has no prior public release and
therefore no release migration. A V1 development artifact can only be replaced
with a complete, newly authorized V2 payload carrying real closure evidence and
verified through the V2 path.

## Rejected and unsupported forms

- malformed or truncated CBOR: `malformed_encoding`;
- unknown/extended fields: `malformed_encoding`;
- trailing or otherwise noncanonical CBOR: `non_canonical_encoding`;
- any V1 envelope version other than `1`: `unsupported_version`;
- unsupported nested invoice/proof versions or malformed required fields:
  `unsupported_artifact`;
- V1 bytes passed to the V2 decoder, or V2 bytes passed to the V1 decoder:
  rejected by that explicit decoder.

Unknown fields are not compatibility extensions. In particular, fake
`source_closure` or finality-upgrade fields are rejected and never interpreted.
The canonical positive digest and negative cases are pinned in
`consignment-v1-legacy-vectors.json`.
