I inspected the uploaded Repomix bundle. Your diagnosis is correct: the project has **two conflicting truths** right now: contracts emit/store some state, while the CLI mostly relies on **local display records and ad-hoc chain-specific queries**. That makes Sanad/Seal lifecycle untraceable across chains. The repo itself says the CLI “holds NO protocol authority state” and only stores display records, while protocol state should live in runtime/on-chain systems, but the current contracts do not expose a uniform state API everywhere. 

## Main audit findings

### 1. Canonical docs exist, but contracts do not consistently implement them

The docs define canonical events that all chains must follow:

`SanadCreated`, `SanadConsumed`, `CrossChainLock`, `CrossChainMint`, `CrossChainRefund`, `NullifierRegistered`, `ProofAccepted`, `ProofRejected`, and `ReplayDetected`. 

But Ethereum uses mixed names:

* `CSVLock` has `CrossChainLock`, `SealUsed`, `SanadRefunded`.
* `CSVMint` has `SanadMinted`, `NullifierRegistered`, `CommitmentAnchored`, `ProofRootUpdated`.
* `CSVSeal` merges lock and mint logic but still uses mixed names like `SealUsed`, `SanadMinted`, `SanadRefunded`.

That is the naming inconsistency you saw: `CSVLock`, `CreateSanad`, `SealUsed`, `SanadMinted`, `CrossChainMint`, and `SanadConsumed` are not being treated as one canonical lifecycle vocabulary.

### 2. Ethereum has partial state tracing, but it is incomplete and inconsistent

`CSVLock` exposes `getSanadState(bytes32)` returning a state enum like `Uncreated=0, Active=1, Locked=2, Consumed=3, Refunded=4`, plus used/refund metadata. 

But `CSVSeal`, the merged Ethereum contract, appears not to expose the same `getSanadState` interface in the Repomix summary. The CLI specifically calls Ethereum `getSanadState(bytes32)`, so if the deployed contract is `CSVSeal` or `CSVMint` rather than `CSVLock`, status can silently become wrong or incomplete.

### 3. CLI collapses important states into “Active” or “Consumed”

The CLI `sanad list --update` logic maps several on-chain states poorly. For Ethereum, the code comments say `getSanadState` returns state values, but the CLI maps `3` to `Consumed`, `4` to `Consumed`, and everything else to `Active`. That destroys distinctions between:

* `Uncreated`
* `Created`
* `Active`
* `Locked`
* `Minted`
* `Transferred`
* `Refunded`
* `Burned/Consumed`

So the CLI cannot show a true lifecycle even when the contract gives it more detail. 

### 4. Solana is closest to canonical events, but still needs explicit queryable state

Solana has event structs for `SanadCreated`, `SanadConsumed`, `CrossChainLock`, `CrossChainMint`, `CrossChainRefund`, `SanadTransferred`, `NullifierRegistered`, and metadata. That is better than Ethereum’s naming. However, the CLI still needs a uniform `get_sanad_state` / account decoding path rather than custom partial parsing.

### 5. Aptos and Sui have Seal objects with flags, not a canonical state machine

Aptos and Sui represent seals with fields like `consumed`, `locked`, owner, commitment, metadata, and proof fields. That is useful, but it is still not a canonical Sanad lifecycle enum. A pair of booleans cannot safely express all valid states. For example:

* `consumed=false, locked=false` could mean created, active, refunded, or transferred depending on history.
* `consumed=true, locked=true` could mean locked, minted, or consumed depending on destination proof status.

The RFC already recognizes state-machine complexity and proposes formal transition rules and forbidden-transition tests. 

---

# Recommended canonical model

Use one vocabulary everywhere.

## Canonical object names

Use these terms consistently:

| Concept   | Canonical name     | Meaning                                             |
| --------- | ------------------ | --------------------------------------------------- |
| Sanad     | `Sanad`            | The transferable proof-bearing asset/state object   |
| Seal      | `Seal`             | Single-use constraint/nullifier backing a Sanad     |
| Nullifier | `Nullifier`        | Replay-prevention value proving one-time use        |
| Lock      | `CrossChainLock`   | Source-chain transition for cross-chain transfer    |
| Mint      | `CrossChainMint`   | Destination-chain creation after proof verification |
| Refund    | `CrossChainRefund` | Recovery after failed/expired transfer              |

Avoid these as primary names:

* `CSVLock` as the main contract name.
* `CreateSanad` in one chain and `create_seal` in another for the same lifecycle operation.
* `SealUsed` when the canonical meaning is `SanadConsumed`.
* `SanadMinted` when the canonical event is `CrossChainMint`.

## Canonical state enum

Every chain should expose the same logical state enum:

```text
0 = Uncreated
1 = Created
2 = Active
3 = Locked
4 = Consumed
5 = Minted
6 = Transferred
7 = Refunded
8 = Burned
9 = Invalid
```

Minimum query interface on every chain:

```text
get_sanad_state(sanad_id) -> SanadStateView
get_seal_state(seal_id) -> SealStateView
is_sanad_created(sanad_id) -> bool
is_sanad_active(sanad_id) -> bool
is_sanad_locked(sanad_id) -> bool
is_sanad_consumed(sanad_id) -> bool
is_sanad_minted(sanad_id) -> bool
is_sanad_refunded(sanad_id) -> bool
is_nullifier_used(nullifier) -> bool
```

Canonical view structure:

```text
SanadStateView {
  sanad_id
  seal_id
  commitment
  owner
  source_chain
  current_chain
  destination_chain
  state
  created_at
  updated_at
  locked_at
  consumed_at
  minted_at
  transferred_at
  refunded_at
  nullifier
  last_tx
  version
}
```

This is the missing piece that makes the CLI reliable.

---

# Chain-by-chain contract fixes

## Ethereum

Unify around one deployed contract: preferably `CSVSeal`, not separate `CSVLock` + `CSVMint`, unless there is a strong architectural reason.

Add or rename events to match canonical schema:

```solidity
event SanadCreated(bytes32 indexed sanad_id, bytes32 commitment, address indexed owner, uint256 timestamp);
event SanadConsumed(bytes32 indexed sanad_id, bytes32 indexed nullifier, uint256 timestamp);
event CrossChainLock(bytes32 indexed sanad_id, string source_chain, string destination_chain, bytes32 commitment, uint256 timestamp);
event CrossChainMint(bytes32 indexed sanad_id, bytes32 commitment, address indexed owner, string source_chain, uint256 timestamp);
event CrossChainRefund(bytes32 indexed sanad_id, bytes32 commitment, string reason, uint256 timestamp);
event SanadTransferred(bytes32 indexed sanad_id, address indexed from, address indexed to, uint256 timestamp);
event NullifierRegistered(bytes32 indexed nullifier, bytes32 indexed sanad_id, uint256 timestamp);
event ProofAccepted(bytes32 indexed proof_root, string protocol_version, uint256 timestamp);
event ProofRejected(bytes32 indexed proof_root, string reason, uint256 timestamp);
event ReplayDetected(bytes32 indexed replay_id, bytes32 indexed sanad_id, uint256 timestamp);
```

Add a real state mapping:

```solidity
enum SanadState {
    Uncreated,
    Created,
    Active,
    Locked,
    Consumed,
    Minted,
    Transferred,
    Refunded,
    Burned,
    Invalid
}

struct SanadStateRecord {
    SanadState state;
    bytes32 sanadId;
    bytes32 sealId;
    bytes32 commitment;
    address owner;
    uint8 sourceChain;
    uint8 currentChain;
    uint8 destinationChain;
    bytes32 nullifier;
    uint256 createdAt;
    uint256 updatedAt;
    uint256 lockedAt;
    uint256 consumedAt;
    uint256 mintedAt;
    uint256 refundedAt;
}
```

Every lifecycle function must update this record and emit the canonical event.

Important: keep legacy events like `SealUsed` and `SanadMinted` only temporarily as compatibility aliases. The indexer and CLI should use canonical events.

## Aptos

Add a `SanadStateRecord` resource/table keyed by `sanad_id`.

Do not rely only on `Seal { consumed, locked }`.

Expose:

```move
public fun get_sanad_state(sanad_id: vector<u8>): SanadStateView
public fun get_seal_state(seal_id: vector<u8>): SealStateView
public fun is_nullifier_used(nullifier: vector<u8>): bool
```

Emit canonical events with the same semantic fields as Ethereum and Solana. Aptos already has several of these structs, but the important fix is to wire them to every state transition and expose one normalized state view.

## Sui

Sui’s object model is good for ownership, but the current `Seal` object’s booleans are not enough. Add an explicit `state: u8` or `SanadState` field to the `Seal`/Sanad object.

Expose:

```move
public fun state(seal: &Seal): u8
public fun sanad_id(seal: &Seal): vector<u8>
public fun seal_state_view(seal: &Seal): SealStateView
```

For events, use canonical names:

* `SanadCreated`
* `SanadConsumed`
* `CrossChainLock`
* `CrossChainMint`
* `CrossChainRefund`
* `SanadTransferred`
* `NullifierRegistered`
* `ReplayDetected`

## Solana

Solana events are already closer to the canonical schema. The missing part is a stable account query model.

Add or confirm `SanadAccount` contains:

```rust
pub state: u8,
pub sanad_id: [u8; 32],
pub seal_id: [u8; 32],
pub commitment: [u8; 32],
pub owner: Pubkey,
pub source_chain: u8,
pub current_chain: u8,
pub destination_chain: u8,
pub nullifier: [u8; 32],
pub created_at: i64,
pub updated_at: i64,
pub locked_at: i64,
pub consumed_at: i64,
pub minted_at: i64,
pub refunded_at: i64,
```

Then the CLI should fetch and decode `SanadAccount` instead of guessing from local state or event history.

---

# CLI fixes

The CLI should stop treating local storage as the source of truth for Sanad/Seal state.

## Add one normalized command path

Add:

```bash
csv sanad state --chain ethereum --sanad-id <id>
csv seal state --chain sui --seal-id <id>
csv sanad trace --chain solana --sanad-id <id>
```

`state` should call the chain-specific adapter but return one normalized structure:

```rust
pub struct CanonicalSanadState {
    pub sanad_id: String,
    pub seal_id: Option<String>,
    pub chain: Chain,
    pub state: SanadLifecycleState,
    pub owner: Option<String>,
    pub commitment: Option<String>,
    pub nullifier: Option<String>,
    pub source_chain: Option<Chain>,
    pub destination_chain: Option<Chain>,
    pub tx_hash: Option<String>,
    pub block_height: Option<u64>,
    pub updated_at: Option<u64>,
}
```

## Add a real enum in CLI

```rust
pub enum SanadLifecycleState {
    Uncreated,
    Created,
    Active,
    Locked,
    Consumed,
    Minted,
    Transferred,
    Refunded,
    Burned,
    Invalid,
    Unknown,
}
```

Do not collapse `Locked`, `Created`, and `Uncreated` into `Active`.

## Replace ad-hoc chain status logic

Current behavior is effectively:

* Bitcoin: check UTXO.
* Ethereum: try `getSanadState`.
* Sui: query object.
* Solana: decode PDA.
* Aptos: use table/REST behavior.
* Otherwise: fall back to local state.

That is why state looks random. Replace it with:

```rust
trait SanadStateReader {
    async fn get_sanad_state(&self, sanad_id: Hash) -> Result<CanonicalSanadState>;
    async fn get_seal_state(&self, seal_id: Hash) -> Result<CanonicalSealState>;
    async fn trace_sanad(&self, sanad_id: Hash) -> Result<Vec<CanonicalLifecycleEvent>>;
}
```

Then each chain adapter implements the same interface.

## CLI display should show state, not just status

Use columns like:

```text
Sanad ID | Chain | State | Owner | Seal | Nullifier | Last Tx | Updated
```

For trace:

```text
Time | Chain | Event | From | To | Tx | State After
```

---

# Implementation order

1. **Freeze canonical naming** in one ABI/state document.
2. **Patch Ethereum first**, because it has the worst naming split: `CSVLock`, `CSVMint`, `CSVSeal`, `SealUsed`, `SanadMinted`.
3. **Add `get_sanad_state` and `get_seal_state` to all four chains.**
4. **Make all lifecycle functions update one explicit state record.**
5. **Emit canonical events from every state transition.**
6. **Update CLI to use normalized state readers.**
7. **Add cross-chain equivalence tests** that assert the same lifecycle produces the same canonical event sequence on Aptos, Sui, Solana, and Ethereum.
8. **Deprecate legacy names** only after the CLI and bindings are switched.

---

# Critical tests to add

For every chain:

```text
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

Also add a naming constitution test:

```text
No production contract may emit SealUsed without also emitting SanadConsumed.
No production contract may emit SanadMinted without also emitting CrossChainMint.
No chain may expose CreateSanad while another exposes create_seal for the same semantic operation unless bindings normalize it.
```

## Bottom line

The core fix is not just “add more events.” You need a **canonical lifecycle state machine** stored on-chain, exposed through one query interface, and consumed by the CLI through one normalized adapter path.

Your target should be:

```text
Contract state is authoritative.
Events are the audit log.
CLI local storage is only cache.
Runtime/indexer reconciles state from chain.
Naming is canonical across all chains.
```

That will solve the current Sanad creation/status bug and make Seal/Sanad state traceable across Aptos, Sui, Solana, and Ethereum.
