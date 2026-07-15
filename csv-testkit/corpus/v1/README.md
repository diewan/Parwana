# CSV Conformance Corpus v1

**Owner:** TBD. This manifest is release input, not live-chain evidence.

Corpus v1 references deterministic, test-only vectors and rejection cases. It
never treats fabricated RPC responses or synthetic chain state as positive
production evidence. A released corpus directory is immutable: a semantic
change requires `corpus/v2`, an RFC, and compatibility-matrix review.

Adapters consume the same port-level contract: successful operations must
produce evidence accepted by the canonical verifier; malformed proof,
authorization, replay, insufficient-finality, and recovery cases must fail
closed. Native adapter integration evidence is added only from retained,
non-secret testnet artifacts.
