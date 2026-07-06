# Operator Runbook — Manual Mint (BTC → ETH)

**Ticket:** TRM-OPER-001 · **Phase:** 4 (ETH fast-track) · **Security critical**

This runbook covers the manual mint-operator flow: observe a verified BTC → ETH
transfer, submit the destination mint under the RFC-0012 thin-registry ABI, and
leave auditable settlement evidence for a later source-chain release
(TRM-ESCROW-001). It also defines the retry, revert, and duplicate-handling
procedures.

Escrow / source release is **out of scope** here and is authorized separately by a
verifier-signed `SettlementReceipt` (RFC-0012 §5). This flow only *records
evidence* that the mint confirmed.

---

## 1. Model in one paragraph

A cross-chain transfer runs through one resumable state machine in
`csv-runtime`'s `TransferCoordinator`. Every phase is written to the crash-safe
execution journal **before** the corresponding chain mutation, and the source
replay entry is the double-mint guard. The operator never re-implements any of
this; they drive it through the `csv` CLI (or the runtime API) and observe the
journal + event store.

Finality is never optional: the BTC lock must reach its configured confirmation
depth (default 6) before any inclusion proof is built. There is no
skip-confirmation path.

### Phases (journaled)

```
Initialized → LockConfirmed → AwaitingFinality → ProofBuilding
            → ProofValidated → MintSubmitted → MintConfirmed → Completed
```

Terminal-off-path: `RolledBack`, `Compromised`.

### Replay-entry states (the double-mint guard)

| State        | Meaning                                    | Re-execution |
|--------------|--------------------------------------------|--------------|
| `Pending`    | Reserved; mint not yet confirmed           | refused (`ReplayDetected`) |
| `Consumed`   | Mint confirmed on destination              | idempotent no-op (`Ok`) |
| `RolledBack` | A mint attempt reverted and was unwound    | refused (`ReplayDetected`) — **fail-closed** |

---

## 2. Happy path

1. **Start the transfer** (locks BTC, journals, returns immediately awaiting finality):

   ```bash
   csv cross-chain transfer --from bitcoin --to ethereum --sanad-id <hex> --dest-owner <eth-addr>
   ```

   Record the printed **Transfer ID** and **Lock Tx Hash**.

2. **Wait for BTC finality, then mint.** Either poll-and-block from the start
   with `--wait`, or resume once the lock confirms:

   ```bash
   csv cross-chain resume <transfer-id> --wait
   ```

   Resume never re-locks. It gates on real confirmations, rebuilds and re-verifies
   the proof, then submits the ETH mint under the attested ABI and confirms it.

3. **Confirm settlement evidence was recorded.** On `MintConfirmed`, the runtime
   appends a `Transfer.SettlementRecorded` event to the durable event store for
   the sanad aggregate. This is the record escrow will later consult
   (`TransferCoordinator::settlement_evidence`). Check status:

   ```bash
   csv cross-chain status <transfer-id>
   ```

   The settlement evidence carries the settlement key material: `lock_event_id`
   (derived from the confirmed lock outpoint), `nullifier`, `commitment`,
   `sanad_id`, both chain names, the lock tx hash, the confirmed mint tx hash and
   block height, and the record timestamp.

---

## 3. Retry

There are two distinct retry scopes. Use the right one.

### 3a. Transient failure *during* a mint (in-call retry) — automatic

A transient RPC error or a temporary revert while submitting the ETH mint is
retried inside the same execution according to `RuntimePolicy` (`max_retries`,
`retry_delay`). If a later attempt succeeds, the transfer completes normally and
settlement evidence is recorded. No operator action is required; the replay entry
stays `Pending` throughout and is promoted to `Consumed` only after the mint
confirms.

### 3b. Interruption before completion (crash / timeout) — resume

If the process crashed, the `--wait` timed out, or you ran without `--wait`, the
transfer is safely resumable from its last journaled phase:

```bash
csv cross-chain resume <transfer-id> --wait
```

Resume is **idempotent and never double-submits**:

- It re-derives the confirming block height and re-verifies the proof.
- From `MintSubmitted` it confirms the already-broadcast mint rather than
  re-broadcasting.
- Completion is gated on the replay entry being promoted `Pending → Consumed`;
  an already-`Consumed` entry makes re-execution a safe no-op.

Resume works even if the local display cache is lost — the CLI recovers the
source/destination chains and sanad id from the runtime journal.

---

## 4. Revert

A **revert** is a mint that failed on *every* in-call attempt (all retries
exhausted). The coordinator then:

1. Journals `MintConfirmed` with a `Failed` outcome, and
2. Marks the replay entry `RolledBack`.

Consequences and procedure:

- **The transfer is fail-closed.** A `RolledBack` entry refuses any re-execution
  with the same sanad (`ReplayDetected`) and cannot be resumed
  (`MintConfirmed`/terminal). This is deliberate: it makes a double-mint
  impossible even under operator error.
- **Recovery is a manual decision, not an automatic re-run.** Because the source
  BTC lock is still in place while nothing was minted on ETH, releasing the
  operator's obligation requires human investigation:
  1. Confirm on-chain (block explorer / RPC) that **no** ETH mint landed for this
     `sanad_id` — check the destination contract's `is_sanad_minted` and search
     for a `SanadMinted` event keyed by the sanad. Never rely solely on local
     state.
  2. If truly un-minted: the source lock can be unwound per the source-chain
     escrow/timeout policy (TRM-ESCROW-001). Do **not** attempt to re-drive the
     same transfer id; start a fresh transfer with a new sanad if the intent
     still stands.
  3. If a mint *did* land (e.g. the revert was a false negative from an RPC
     timeout), treat it as completed: the settlement evidence / `SanadMinted`
     event is the source of truth for release. Do not re-mint.
- **Escalate** any case where local journal state and on-chain state disagree —
  that is a `Compromised`-class incident, not a routine revert.

---

## 5. Duplicate handling

Duplicate submissions are refused by construction; the operator's job is to
recognize each outcome, not to force a second mint.

| Situation | What the runtime does | Operator action |
|-----------|-----------------------|-----------------|
| Re-submit a transfer whose mint **confirmed** (`Consumed`) | Returns `Ok` (idempotent no-op); no second mint | None — it already completed |
| Re-submit while a mint is **in flight** (`Pending`) | Returns `ReplayDetected` | Wait / `resume` the original; do not start a new one |
| Re-submit after a **revert** (`RolledBack`) | Returns `ReplayDetected` | Follow §4 (revert), not a re-run |
| Two runtimes race the same transfer | Loser gets a `LeaseViolation` | Only the lease owner executes; investigate why two operators acted |

The atomic `consume_if_unconsumed` on the replay database is the single guard
behind all of the above — a mint is dispatched only once per replay id, and the
entry is promoted to `Consumed` only after the mint confirms on-chain.

---

## 6. Auditing

- **Event store** (per sanad aggregate): `Transfer.Locked`,
  `Transfer.FinalityAwaited`, `Transfer.ProofBuilt`, `Transfer.ProofVerified`,
  `Transfer.Complete`, and `Transfer.SettlementRecorded`. These are append-only
  and are the auditable trail for a transfer.
- **Execution journal**: crash-safe per-phase records (entered/completed/failed)
  used for resume.
- **Settlement evidence**: read back with
  `TransferCoordinator::settlement_evidence(sanad_id)` — the input a source
  release consults. Its absence means no confirmed mint; never release against a
  missing record.

---

## 7. Invariants the operator must never bypass

- No mint without verified inclusion **and** finality. `validate_source_proof` and
  the canonical verifier run *before* the mint; the adapter never fabricates a
  proof root from a block hash.
- Finality depth is enforced for every mode. Do not lower it below the source
  chain's configured depth to "speed things up".
- Never manually edit the replay database or journal to force a retry past a
  `RolledBack`/`Consumed` state. That reintroduces double-mint risk.
