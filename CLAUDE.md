# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CSV Protocol — a multi-chain, client-side-validated cryptographic state protocol (Single-Use Seals + Sanads + proof-carrying ownership). Rust monorepo, Cargo workspace, **edition 2024**, toolchain pinned to **1.95** (`rust-toolchain.toml`). Root crate is `csv-protocol`.

## Build & test

```bash
cargo build --workspace --all-features
cargo test  --workspace --all-features
cargo test --workspace --doc                    # doc tests
cargo test -p <crate> <test_name>               # single test / single crate
cargo build -p csv-cli --release                # the `csv` CLI binary

cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings

# WASM gates (the whole SDK path must stay wasm-compilable; persistence and
# chain adapters are target-gated out on wasm32 and served by in-memory stores)
cargo build -p csv-runtime --target wasm32-unknown-unknown
cargo build -p csv-sdk --no-default-features --features std,wasm,wallet --target wasm32-unknown-unknown
```

The workspace is pure Rust (persistence is `redb`; RocksDB and its C++ toolchain requirement are gone — no `CXXFLAGS` needed).

- Integration tests are `#[ignore]`d and need live RPC secrets (signet, sepolia, sui testnet).
- nextest config in `.config/nextest.toml` (30s slow-timeout for crypto tests).
- Fuzz targets live in `fuzz/` (`cd fuzz && cargo fuzz run <target>`).

## Architecture (the big picture)

Strict layering, **enforced by CI** via `deny.toml` and the `csv-architecture` crate's compliance tests. Violating these will fail the build:

```
csv-sdk (public facade)
 └ csv-runtime (orchestration: TransferCoordinator, leases, replay DB,
   │            circuit breakers, execution journal, health)
   ├ csv-admission    (pressure boundary — rejects excess work before state mutation)
   ├ csv-coordinator  (per-chain execution cells — isolated failure domains)
   ├ csv-observability (metrics, logging, health — chain-agnostic)
   └ csv-protocol (protocol types & traits; defines *what is correct*, not *how*)
       ├ csv-algebra   (no_std typestate transfer state machine — compile-time transition safety)
       ├ csv-wire      (owns ALL serde / transport encoding)
       ├ csv-codec     (canonical CBOR for hashed protocol state)
       ├ csv-hash / csv-proof / csv-verifier / csv-content / csv-storage
       └ csv-adapters/* (per-chain: bitcoin, ethereum, solana, sui, aptos, celestia)
```

Hard rules to respect when editing:

- **`csv-cli` holds NO protocol authority state** (no leases/transfers) and must NOT import chain adapters — everything goes through `csv-runtime`.
- **`csv-runtime` must not import chain adapters** — only csv-protocol / csv-coordinator / csv-admission / csv-observability. Chain-specific work is dispatched through the coordinator + adapter registry.
- **`csv-algebra` must not depend on `csv-wire`** (typestate stays transport-free).
- **`serde_json` is forbidden in canonical hashing paths** — use canonical CBOR (`csv-codec`). Serialization boundary lives only in `csv-wire`.
- Each adapter under `csv-adapters/` implements the `SealProtocol` + `ChainBackend` traits.
- **Finality is never optional** — all runtime modes enforce strict finality; don't add a "skip confirmation" path.
- The execution journal (`csv-runtime/.../execution_journal.rs`) provides crash-safe phase tracking; transfer phases must be journaled.

`csv-core` has been **removed** (legacy); its types migrated to csv-protocol/csv-algebra/csv-wire. Don't reintroduce imports of it.

## Where to look

- **[AGENTS.md](AGENTS.md)** — full crate-by-crate breakdown, the complete `csv` CLI command reference, and contract build commands (Foundry/Anchor/Sui Move/Aptos). Consult this before asking about a crate's purpose or a CLI subcommand.
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — deeper design rationale.
- `csv-docs/` — protocol docs (`PROTOCOL_INVARIANTS.md`, `PROTOCOL_CONSTITUTION.md`, `THREAT_MODEL.md`). There is no root `docs/`.
- `.agents/AGENT.md` — protocol invariants, forbidden patterns, verification rules.
- `chains/*.toml` — per-chain network/RPC config; `csv-contracts/{ethereum,solana,sui,aptos}/` — on-chain contracts.
- `development/agent-workflow/context_packs/` — per-ticket context packs (ticket IDs like `BTC-XFER-001` map to files here and to recent commits).
