# Consignment V2 wire contract

`csv-wire::ConsignmentV2` is the portable non-equivocation envelope. Consumers
must call the explicit `ConsignmentV2::decode_v2` entry point; format
auto-detection is not part of the contract.

The signed commitment is:

```text
csv_tagged_hash("consignment-v2", canonical_cbor(ConsignmentV2Payload))
```

The payload commits to both version fields, the distinct `ConsumedStateRef`,
the resolved parent and successor outputs, the chain-native `ClosureProof`, the
recipient invoice, and all checkpoint/provider/context/trust requirements.
Authorization records are accepted structurally only when they name that exact
commitment. Cryptographic signature and native closure verification remain
separate verifier stages.

The canonical unit vector in `csv-wire/src/consignment.rs` pins the commitment:

```text
a30786a98a733fc92b8f26b4bbc64e45ef1a2bbf1c31ee5722f9a02344f577e3
```

Its fixture uses protocol version `2`, envelope version `2`, an exclusive
state reference, a Bitcoin transaction-inclusion closure, a Signet checkpoint,
a light-client trust requirement, and an Ed25519 authorization record.

## Rejection behavior

V2 decoding rejects malformed CBOR, noncanonical encodings, trailing data,
unknown protocol or envelope versions, unresolved or mismatched sources,
closure/source/successor disagreement, invalid proof requirements, destination
invoice mismatch, commitment mismatch, and missing or misbound authorization
evidence. Each failure crosses the wire API with a stable
`ConsignmentV2ErrorCode`.

Legacy `Consignment` remains the V1 inspection shape. It is not accepted by the
explicit V2 decoder and cannot acquire V2 closure assurance through this API.
The complete V1 inspection policy is specified by PAR-WIRE-002.
