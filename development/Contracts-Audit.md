# Contracts Audit — Canonical Lifecycle State Machine

**Last validated:** 2025-06-09
**Status:** Active — tracks canonical event naming, state enum, and query interface across all chains.

## Current State

### 1. Canonical Events Across Chains

All four chains define the canonical event names. Ethereum, Solana, and Sui emit them correctly. Aptos has two versions with different conformance levels.

| Event | Ethereum (CSVSeal.sol) | Solana | Sui | Aptos (legacy) | Aptos (sources) |
|-------|----------------------|--------|-----|-----------------|-----------------|
| SanadCreated | Emitted | Emitted | Emitted | Emitted | Emitted |
| SanadConsumed | Emitted | Emitted | Emitted | Emitted | Emitted |
| SanadLocked | Emitted | Defined | Emitted | Emitted | **MISSING** |
| CrossChainLock | Emitted (alongside SanadLocked) | Defined | Emitted | Emitted | Emitted |
| SanadMinted | Emitted | Emitted | Emitted | Emitted | **MISSING** |
| CrossChainMint | Emitted (alongside SanadMinted) | Defined | Emitted | Emitted | Emitted |
| SanadRefunded | Emitted | Emitted | Emitted | Emitted | Emitted |
| CrossChainRefund | Emitted (alongside SanadRefunded) | Defined | Emitted | Emitted | Emitted |
| SanadTransferred | Emitted | Emitted | Emitted | Emitted | **MISSING** |
| NullifierRegistered | Emitted | Emitted | Emitted | Emitted | Emitted |
| ReplayDetected | Emitted | Emitted | Emitted | **MISSING** | **MISSING** |
| CommitmentAnchored | Emitted | **MISSING** | Emitted | **MISSING** | **MISSING** |
| ProofRootUpdated | **MISSING** | **MISSING** | Emitted | **MISSING** | **MISSING** |

**Verdict: PARTIAL** — Ethereum, Solana, Sui, and Aptos-legacy are mostly compliant. Aptos-sources version is significantly behind: missing `SanadLocked`, `SanadMinted`, `SanadTransferred`, `ReplayDetected`, `CommitmentAnchored`, `ProofRootUpdated`.

### 2. Canonical State Enum

All chains define the 10-state enum (0-9):

| Chain | State Enum | Values | Query Interface |
|-------|-----------|--------|-----------------|
| Ethereum (CSVSeal.sol) | `enum SanadState` | Uncreated=0 through Invalid=9 | `get_sanad_state(bytes32)` returns full view, `get_seal_state(bytes32)` |
| Solana | `enum SanadState` (repr u8) | Uncreated=0 through Invalid=9 | `get_sanad_state` exists; `get_seal_state` missing |
| Sui | Constants `SANAD_STATE_*` | 0-9 | `public fun state(seal: &Seal): u8` — returns raw u8, not full view |
| Aptos (legacy) | Constants `SANAD_STATE_*` | 0-9 | `public fun get_sanad_state(addr: address): u8` — returns raw u8 |
| Aptos (sources) | **MISSING** | — | **No query functions** |

**Verdict: PARTIAL** — Ethereum has the most complete query interface (full state view). Solana has `get_sanad_state` only. Sui and Aptos-legacy return raw u8. Aptos-sources has no state enum or query functions.

### 3. SanadStateReader Trait (Rust side)

Defined in `csv-protocol/src/backend.rs:548-557`:

```rust
pub trait SanadStateReader: Send + Sync {
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState>;
    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState>;
    async fn trace_sanad(&self, sanad_id: &SanadId) -> ChainOpResult<Vec<CanonicalLifecycleEvent>>;
}
```

Implemented by all 5 chain adapters:
- `EthereumBackend` — `csv-adapters/csv-ethereum/src/ops.rs:1510`
- `SolanaBackend` — `csv-adapters/csv-solana/src/ops.rs:994`
- `SuiBackend` — `csv-adapters/csv-sui/src/ops.rs:1401, 1453`
- `AptosBackend` — `csv-adapters/csv-aptos/src/ops.rs:1255`
- `BitcoinBackend` — `csv-adapters/csv-bitcoin/src/ops.rs:2488`

**Verdict: PASS** — Trait defined and implemented by all adapters.

### 4. CanonicalSanadState (Rust side)

Two definitions exist:

**A. `csv-protocol/src/backend.rs:508-528`** (protocol-level):
```rust
pub struct CanonicalSanadState {
    pub state: u8,
    pub owner: String,
    pub commitment: Hash,
    pub nullifier: Option<Hash>,
    pub created_at: i64,
    pub locked_at: Option<i64>,
    pub consumed_at: Option<i64>,
    pub minted_at: Option<i64>,
    pub refunded_at: Option<i64>,
}
```

**B. `csv-store/src/state/domain.rs:601-627`** (CLI/display-level):
```rust
pub struct CanonicalSanadState {
    pub sanad_id: String,
    pub seal_id: Option<String>,
    pub chain: ChainId,
    pub state: SanadLifecycleState,
    pub owner: Option<String>,
    pub commitment: Option<String>,
    pub nullifier: Option<String>,
    pub source_chain: Option<ChainId>,
    pub destination_chain: Option<ChainId>,
    pub tx_hash: Option<String>,
    pub block_height: Option<u64>,
    pub updated_at: Option<u64>,
}
```

**Verdict: INCONSISTENT** — Two different structs with different fields. The CLI uses the `csv-store` version. The protocol-level version is more timestamp-focused. These should be unified.

### 5. CLI State Handling

**`cmd_list`** (`csv-cli/src/commands/sanads.rs:733-810`):
- Calls `query_sanad_on_chain_state()` which returns `Option<CanonicalSanadState>`
- Uses `SanadLifecycleState::from_u8(state)` to convert on-chain u8 to full enum
- Displays `state_enum.label()` — shows full state name (Locked, Minted, Transferred, etc.)
- **No longer collapses states** — each of the 10 states displayed distinctly

**`cmd_show`** (`csv-cli/src/commands/sanads.rs:694-731`):
- Still uses old `SanadStatus` enum (Active/Transferred/Consumed) for local display
- Does NOT query on-chain state

**`check_sanad_on_chain_status`** (`csv-cli/src/commands/sanads.rs:814-1096`):
- Ethereum path (997-1096) still has stale state mapping: state 0="Uncreated", 1="Active", 2="Locked", 3="Consumed", 4="Refunded"
- This mapping does NOT match the canonical 0-9 enum

**Verdict: PASS (mostly)** — `cmd_list` uses full `SanadLifecycleState`. `cmd_show` and `check_sanad_on_chain_status` need updating.

### 6. Legacy Event Names

Ethereum and Sui emit legacy events (`SealUsed`, `CrossChainLock`, `AnchorEvent`) alongside canonical ones — safe transition pattern. Solana legacy events are defined but not emitted. Aptos-sources ONLY emits legacy events without canonical equivalents.

## Required Corrections

### High Priority

1. **Fix Aptos sources contract** — Add canonical state constants, canonical event names (`SanadLocked`, `SanadMinted`, `SanadTransferred`, `ReplayDetected`), and query functions (`get_sanad_state`, `get_seal_state`).

2. **Unify CanonicalSanadState** — Choose one definition. The `csv-store` version is more complete for CLI/display. The `csv-protocol` version is more compact for protocol-level use. Consider keeping both but ensuring they map to each other.

3. **Fix CLI `check_sanad_on_chain_status`** — Replace stale Ethereum state mapping with canonical 0-9 enum.

4. **Fix CLI `cmd_show`** — Replace old `SanadStatus` enum with `SanadLifecycleState`.

5. **Add `get_seal_state` to Solana, Sui, Aptos** — Currently only Ethereum has both query functions.

### Medium Priority

6. **Add `ReplayDetected` to Aptos legacy** — Missing from Aptos legacy contract.
7. **Add `CommitmentAnchored` to Solana** — Missing from Solana events.
8. **Add `ProofRootUpdated` to Ethereum and Solana** — Missing from both.
9. **Deprecate legacy event emission** — Once all chains emit canonical events, stop emitting legacy aliases.

### Low Priority

10. **Sui state view** — Replace `public fun state(seal: &Seal): u8` with full `SanadStateView` struct.
11. **Aptos sources contract** — Consider removing if Aptos legacy is the canonical deployment.

## Critical Tests to Add

For every chain:
```
create_sanad -> state = Created or Active
lock_sanad -> state = Locked
consume_sanad -> state = Consumed
mint_sanad -> state = Minted
transfer_sanad -> state = Transferred
refund_sanad -> state = Refunded
double_consume -> rejected
double_mint -> rejected
refund_after_mint -> rejected
mint_without_verified_proof -> rejected
CLI sanad state equals on-chain state
CLI sanad trace reconstructs full lifecycle
```

Naming constitution test:
```
No production contract may emit SealUsed without also emitting SanadConsumed.
No production contract may emit SanadMinted without also emitting CrossChainMint.
No chain may expose CreateSanad while another exposes create_seal for the same semantic operation unless bindings normalize it.
```

## Bottom Line

The core fix is not just "add more events." You need a **canonical lifecycle state machine** stored on-chain, exposed through one query interface, and consumed by the CLI through one normalized adapter path.

Target:
```
Contract state is authoritative.
Events are the audit log.
CLI local storage is only cache.
Runtime/indexer reconciles state from chain.
Naming is canonical across all chains.
```
