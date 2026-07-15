# RFC-0013: Unified RPC Endpoint and Trust Policy

**Status:** Accepted for incremental implementation
**Date:** 2026-07-14
**Scope:** csv-sdk/runtime/adapters, csv-cli, Hemion, and csv-explorer

## Decision

CSV has one endpoint policy model. An endpoint is not a bare URL: it has an
exact chain and network, transport, capabilities, provider identity, source,
priority, and optional reference to credentials held outside configuration.

Libraries never read `.env` files or RPC environment variables. A native host,
CLI, container entrypoint, or wallet settings screen may read its platform's
configuration source, but it must convert that input into the same typed policy
and pass it explicitly. There is no second precedence system inside adapters.

## Goals

1. Make the reviewed default safe and understandable.
2. Let a user use a self-hosted or personally trusted endpoint without editing
   code or relying on magic environment-variable names.
3. Keep JSON-RPC over HTTP, WebSocket subscriptions, REST indexers, and gRPC
   distinct so an endpoint is never guessed from its URL.
4. Preserve the protocol trust model: convenience reads may use one provider;
   finality, inclusion, seal-consumption, and mint-confirmation evidence require
   the configured independent-provider quorum.
5. Keep credentials out of TOML/JSON, logs, diagnostics, and endpoint display.

## Non-goals

- A single universal HTTP client. Chain adapters retain their wire codecs and
  request implementations.
- Treating an explorer/indexer response as protocol authority.
- Automatically deriving HTTP URLs from WebSocket URLs or vice versa.
- Claiming that an endpoint is honest because it is called “official.”

## Canonical model

The canonical SDK types live in `csv-sdk::rpc_policy` during the migration:

- `ChainRpcPolicy`: exact `chain`, exact `network`, selection mode, endpoints.
- `RpcEndpoint`: stable ID, URL, transport, capabilities, source, independent
  provider identity, priority, and optional credential reference.
- `RpcTransport`: `json_rpc_http`, `web_socket`, `rest`, or `grpc`.
- `RpcCapability`: `read`, `broadcast`, `subscribe`, `address_index`, or
  `verify`.
- `RpcSelectionMode`: `built_in_only`, `user_only`, or the explicitly enabled
  `user_then_built_in`.
- `RpcTrustRequirement`: single-source or independent-provider quorum.

The type is application configuration, not consensus data. It is never hashed
into a Sanad, proof, invoice, or transfer state.

## Source and fallback rules

The default installed profile uses `built_in_only`. Adding a user endpoint
switches that chain to `user_only`; a failure never leaks traffic to a bundled
provider. The user may opt into `user_then_built_in`, and the UI must describe
that choice before saving it. There is no automatic “try anything” mode.

Fallback means trying the next endpoint allowed by the selected source policy
for the same capability. It does not mean:

- changing network;
- changing transport/dialect;
- accepting stale or lower-finality data;
- replacing a failed verification quorum with one successful response;
- treating an explorer REST API as a full-node RPC.

Endpoint health affects attempt order only. It never changes trust thresholds.

## Trust classes

| Operation | Minimum trust | Notes |
| --- | --- | --- |
| Balance/activity display | One selected endpoint | Label source and observation time; never call it verified protocol state |
| Subscription notification | One selected WebSocket | Notification is a hint; fetch and validate before acting |
| Transaction broadcast | One selected request endpoint | A returned hash is not confirmation |
| Address/UTXO discovery | One REST/indexer endpoint | Every spendability/inclusion claim is independently validated |
| Inclusion/finality/seal/mint verification | 3 independent providers, 2 agreeing by Stage-1 default | Fail closed on insufficient providers or disagreement |

Multiple URLs operated by one provider count as one quorum provider. A user's
single self-hosted node is valid for private reads and broadcast, but it does
not silently satisfy protocol verification quorum.

## Chain transport matrix

The chain adapter declares required capabilities; configuration only supplies
matching endpoints.

| Chain | Request transport | Subscription | Separate index capability |
| --- | --- | --- | --- |
| Bitcoin | Bitcoin Core JSON-RPC or an explicitly named REST dialect | No generic WebSocket assumption | Esplora/Blockbook address index is a distinct REST capability |
| Ethereum | JSON-RPC over HTTPS | JSON-RPC over WSS | Optional third-party index APIs are non-authoritative |
| Solana | JSON-RPC over HTTPS | JSON-RPC subscriptions over WSS | Optional index provider, separately typed |
| Sui | Adapter-declared JSON-RPC/gRPC during migration | Explicit only | GraphQL/index services are separately typed |
| Aptos | Fullnode REST API | Explicit stream/index service only | Indexer API is distinct from the fullnode REST API |

REST endpoints require a dialect/capability adapter. “REST” alone does not make
Bitcoin Esplora, Bitcoin Core REST, Aptos Fullnode, and an explorer API
interchangeable.

## Exact network validation

Every endpoint is unusable until its adapter proves the configured identity:

- Ethereum: numeric chain ID.
- Solana: genesis hash/cluster identity and expected program deployment.
- Bitcoin: genesis/network identity and signet/testnet/mainnet parameters.
- Sui: chain identifier plus expected package/registry deployment.
- Aptos: ledger chain ID plus expected module deployment.

The resolved deployment identifiers come from
`deployments/deployment-manifest.json`. A URL name containing `testnet` is not
evidence. An identity mismatch disables the endpoint; it never relabels data.

## Credentials and persistence

`RpcCredentialRef` contains only an opaque ID. The host resolves it through an
application-owned vault/keyring. Raw API keys, bearer tokens, basic-auth values,
and credential-bearing URLs must not be serialized into chain TOML, explorer
JSON, portable wallet exports, diagnostics, or logs.

- Hemion native: OS keyring/encrypted wallet storage.
- Hemion web: encrypted wallet-local storage; never browser build-time env.
- CLI/service: secret manager or process environment read by the executable's
  explicit config adapter.
- `.env`: local developer convenience for an entrypoint only; libraries do not
  load it and it is never a deployment source of truth.

Wallet RPC preferences are portable only when explicitly exported. Credential
material is never included. Imported preferences remain disabled until their
credentials are reattached and network identity validation passes.

## Configuration example

```toml
[chains.solana.rpc_policy]
chain = "solana"
network = "devnet"
selection = "user_only"

[[chains.solana.rpc_policy.endpoints]]
id = "my-solana-http"
url = "https://rpc.example.net/solana"
transport = "json_rpc_http"
capabilities = ["read", "broadcast", "verify"]
source = "user"
provider = "self-hosted"
priority = 10
credential = { id = "rpc/solana/example-net" }

[[chains.solana.rpc_policy.endpoints]]
id = "my-solana-ws"
url = "wss://rpc.example.net/solana"
transport = "web_socket"
capabilities = ["subscribe"]
source = "user"
provider = "self-hosted"
priority = 10
credential = { id = "rpc/solana/example-net" }
```

## Ownership boundaries

- `csv-sdk::rpc_policy`: canonical serializable policy and deterministic
  selection; no I/O and no secret resolution.
- Host/CLI/Hemion: load, edit, encrypt, and pass policies explicitly.
- Adapter factory: request endpoints by capability/transport; never read env or
  choose defaults.
- Chain adapter: perform protocol-specific calls and prove network identity.
- Runtime verifier: request independent evidence and enforce quorum.
- Explorer: use the same policy schema but separate service-owned credentials;
  no `rpc_config.json` side channel.

Hemion never sends user RPC credentials to csv-explorer. A wallet user endpoint
is used by the wallet/runtime boundary only. Explorer endpoints are configured
by its operator.

## Migration

1. Land the typed SDK policy and strict injection behavior.
2. Remove SDK/adaptor implicit env reads and route construction through one
   resolver. Scalar `rpc_url`, `indexer_url`, and `api_key` fields become
   migration-only.
3. Convert `chains/*.toml` to the canonical schema and add startup identity
   checks plus per-chain capability tests.
4. Add Hemion Settings UI, encrypted credential references, connection test,
   identity display, strict/fallback choice, and reset-to-built-in action.
5. Replace explorer `rpc_config.json` plus TOML precedence with the same schema.
6. Delete duplicate config models and add an architecture test rejecting RPC
   environment reads below executable/application layers.
7. Wire quorum verification and prove that insufficient independent providers,
   disagreement, identity mismatch, and transport mismatch fail closed.

## Acceptance tests

- User injection selects only user endpoints by default.
- Built-in fallback occurs only after explicit selection.
- HTTP/WS transport mismatch and remote plaintext endpoints are rejected.
- Missing credentials disable only the affected endpoint without exposing the
  secret identifier/value.
- Changing the configured network without replacing/revalidating endpoints
  invalidates them.
- Two URLs owned by one provider do not satisfy a three-provider quorum.
- A subscription event never completes a protocol transition without an
  independent verified read.
- No library crate reads RPC environment variables or `.env` files.
- Hemion native/WASM and the protocol host deserialize the same fixtures.
- Explorer cannot load a second configuration source that changes network or
  endpoint precedence.

## Current implementation status

The canonical policy types, strict user injection, TLS/transport validation,
deterministic candidate ordering, and independent-provider quorum precondition
are implemented. Hemion also persists the shared non-secret policy schema for
native and WASM targets.

Migration step 2 (remove SDK/adapter implicit env reads; route construction
through one resolver) and step 6's model cleanup are landed: the scalar
`url`/`indexer_url`/`indexer_backend`/`api_key` fields are deleted from
`csv-sdk::config::RpcConfig`, the typed policy is the sole endpoint authority
(request URL and REST address-index URL resolve by capability; `required_request_url`
fails closed with no scalar fallback), the `Config::builtin_rpc` host seam
converts platform config into a reviewed policy without guessing transport, and
the implicit RPC env reads below the executable layer (csv-bitcoin `with_env_rpc`,
csv-store `default_for` overrides, CLI `get_rpc_url`) are removed. Verified across
the csv-protocol workspace, its RPC/config/quorum test suites, the csv-cli suite,
and a full Hemion rebuild.

Remaining release gates: the wallet Settings UI/runtime swap (step 4) and the
explorer configuration unification (step 5) are not wired, the architecture test
that rejects RPC env reads (step 6's test, tracked as RPC-005) is not yet added,
and quorum enforcement is not yet wired into the live runtime read paths (step 7,
RPC-004). Until step 4 lands, no UI may imply multi-provider assurance.
