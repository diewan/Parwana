# Threat Model

## 1. Scope

This document covers the CSV (Cross-chain Sanad Validation) protocol, including:

- Core protocol logic in `csv-protocol`, `csv-algebra`, `csv-hash`, and `csv-proof`
- Protocol orchestration in `csv-protocol`
- Chain adapters in `csv-adapters/csv-bitcoin`, `csv-adapters/csv-ethereum`, `csv-adapters/csv-solana`, `csv-adapters/csv-sui`, `csv-adapters/csv-aptos`, `csv-adapters/csv-celestia`
- Runtime orchestration in `csv-runtime` (TransferCoordinator, execution journal, lease management)
- CLI tooling in `csv-cli` (stateless client — delegates to runtime)
- SDK in `csv-sdk`
- Storage layer in `csv-storage` (RocksDB, PostgreSQL, in-memory backends)
- MCP server in `csv-mcp-server`
- Smart contracts in `csv-contracts`

**Note:** `csv-wallet` is a workspace crate. `tuppira/*` and `typescript-sdk/` do not exist in the current codebase.

**Out of scope:** Chain-level consensus, external oracle services, user device security.

## 2. Trust Assumptions

| Entity | Trust Level | Assumptions |
|--------|-------------|-------------|
| Source chain validators | Semi-trusted | May collude but cannot forge proofs without majority |
| Destination chain validators | Semi-trusted | Verify proofs before minting |
| RPC providers | Untrusted | May return incorrect data; quorum required |
| Indexers | Untrusted | May be delayed or return stale data |
| Client (CLI/SDK) | Trusted | Runs on user-controlled hardware |
| csv-runtime | Trusted | Sole authority for protocol execution, lease management, and replay protection |
| csv-storage backends | Semi-trusted | May fail; protocol handles failures gracefully |

## 3. Adversarial Models

### 3.1 Byzantine Nodes

**Threat:** Source or destination chain nodes return invalid data.

**Impact:** Incorrect proof generation, failed transfers, or minting of invalid Sanads.

**Mitigation:**

- RPC quorum client (`csv-protocol/src/rpc`) requires agreement from multiple providers
- Finality depth checks prevent acting on unconfirmed transactions
- Inclusion proofs are verified against on-chain state roots

### 3.2 Malicious Indexers

**Threat:** Indexers return stale, incorrect, or fabricated data.

**Impact:** Client acts on outdated state, leading to failed transfers or double-spends.

**Mitigation:**

- All indexer data is verified against on-chain state before use
- `csv-protocol/src/finality` defines and tracks finality state
- Reorg detection (`csv-protocol/src/reorg`) handles chain reorganizations

### 3.3 RPC Equivocation

**Threat:** Different RPC providers return conflicting data for the same block.

**Impact:** Client may generate proofs based on incorrect state roots.

**Mitigation:**

- Quorum client requires agreement from ≥2/3 of providers
- Disagreement triggers fallback to additional providers
- All RPC responses are logged for audit

### 3.4 Delayed Finality

**Threat:** Source chain finality is delayed beyond expected time.

**Impact:** Transfer stalls; destination chain may reject late proofs.

**Mitigation:**

- Configurable finality depth per chain
- Timeout handling in csv-runtime
- Recovery engine (csv-runtime/src/recovery.rs, csv-runtime/src/execution_journal.rs) handles stuck transfers ✅ Implemented (Phase 9)

### 3.5 Partial Chain Partitions

**Threat:** Network partition prevents communication with some chain nodes.

**Impact:** Transfer cannot complete; funds may be temporarily locked.

**Mitigation:**

- Multiple RPC endpoints per chain
- Timeout-based fallback to alternative providers
- Recovery engine can retry with different providers ✅ Implemented (Phase 9)

## 4. Protocol-Specific Threats

### 4.1 Cross-Chain Double-Spend

**Threat:** Same Sanad transferred to multiple destination chains simultaneously.

**Impact:** Double-spend of Sanad; loss of destination chain integrity.

**Mitigation:**

- Source chain lock consumes the seal, preventing reuse
- Cross-chain registry tracks all transfers via ReplayDatabase
- Lease system prevents concurrent transfer attempts on same Sanad
- csv-runtime/src/distributed_coordinator_lease.rs enforces exclusive access during transfer window

### 4.2 Replay Attacks

**Threat:** Replaying a valid transfer proof on a different chain or block height.

**Impact:** Unauthorized minting on destination chain.

**Mitigation:**

- Tagged hashing with domain separation (`csv_tagged_hash`)
- Chain-specific hash algorithms (`CrossChainHashAlgorithm`)
- Replay semantics (`csv-protocol/src/replay/registry.rs`) and the runtime replay database track processed proofs
- Block height and finality checks in proof verification

### 4.3 Lease Bypass

**Threat:** Bypassing lease acquisition to execute concurrent transfers.

**Impact:** Race conditions, double-spend attempts, inconsistent state.

**Mitigation:**

- `csv cross-chain acquire-lease` command required before transfer
- `--lease-token` flag on transfer command validates lease ownership
- Lease expires after TTL, preventing indefinite locking
- Lease validation occurs before lock_sanad execution

### 4.4 Proof Tampering

**Threat:** Modifying inclusion proof data to forge a valid transfer.

**Impact:** Unauthorized minting; loss of destination chain integrity.

**Mitigation:**

- Canonical CBOR serialization (`csv-codec`) prevents encoding ambiguity
- Tagged hashing ensures proof data cannot be substituted
- Merkle proofs are verified against on-chain state roots
- All proof fields are cryptographically bound

### 4.5 Ownership Proof Forgery

**Threat:** Creating a fake ownership proof for a Sanad.

**Impact:** Unauthorized transfer of another user's Sanad.

**Mitigation:**

- Signature verification using chain-specific schemes (Secp256k1, Ed25519)
- `ProofBundle.signature_scheme` is checked against the source chain adapter before verification, preventing Secp256k1 fallback on Ed25519 chains
- Ownership proofs include the signer's public key
- `csv-protocol/src/signature.rs` defines signature schemes and runtime verification binds them to the source chain

### 4.7 Crash During Mint Completion

**Threat:** Runtime crashes after destination mint submission or confirmation but before local persistence is complete.

**Impact:** Replay state and transfer registry diverge, causing stuck transfers or lost recovery context.

**Mitigation:**

- Mint submission stores the destination transaction hash before confirmation recovery
- Confirmed mints promote replay state to `Consumed` and persist the completed transfer entry
- Failed mint paths mark replay state `RolledBack`
- Recovery checkpoints carry canonical CBOR payloads rather than empty placeholders ✅ Implemented (Phase 9)

### 4.6 Sanad Consumption

**Threat:** Consuming a Sanad's seal without completing the transfer.

**Impact:** Sanad locked on source chain with no destination mint; funds lost.

**Mitigation:**

- Recovery engine (csv-runtime/src/recovery.rs, csv-runtime/src/execution_journal.rs) detects stuck transfers ✅ Implemented (Phase 9)
- Timeout-based recovery releases locked seals
- Transfer status tracking enables monitoring

## 5. Client-Side Threats

### 5.1 Key Compromise

**Threat:** User wallet keys extracted from local storage.

**Impact:** Full control over user's Sanads and funds.

**Mitigation:**

- Encrypted state storage (`csv-cli/src/state.rs`)
- Passphrase required for all operations
- Keys never stored in plaintext

### 5.2 CLI Command Injection

**Threat:** Malicious input in CLI arguments or configuration.

**Impact:** Unauthorized operations or data exfiltration.

**Mitigation:**

- All inputs validated before use
- Hex decoding with length checks
- No shell command execution from user input

### 5.3 MCP Server Abuse

**Threat:** Malicious MCP client sending crafted tool calls.

**Impact:** Unauthorized operations, data leakage, or resource exhaustion.

**Mitigation:**

- Zod schema validation on all tool inputs (`csv-mcp-server/src/validation/schemas.ts`)
- Structured audit logging (`csv-mcp-server/src/audit/logger.ts`)
- Lease acquisition pattern prevents concurrent operations
- Temp file handling with cleanup

## 6. Smart Contract Threats

### 6.1 Contract Upgrade

**Threat:** Malicious contract upgrade breaking protocol guarantees.

**Impact:** Loss of Sanad integrity, unauthorized minting.

**Mitigation:**

- Contract manifest governance (`csv-contracts/`) tracks deployed versions
- Bytecode hash verification prevents unauthorized deployments
- Semantic versioning ensures compatible upgrades

### 6.2 Reentrancy

**Threat:** Reentrant calls during cross-chain mint operations.

**Impact:** Double-minting, state corruption.

**Mitigation:**

- Checks-Effects-Interactions pattern in contract code
- State changes before external calls
- No external calls after mint completion

## 7. Network Threats

### 7.1 Man-in-the-Middle

**Threat:** Intercepting or modifying communication between client and RPC nodes.

**Impact:** Data tampering, proof forgery.

**Mitigation:**

- TLS required for all RPC connections
- Certificate pinning for known providers
- Response signing verification where available

### 7.2 Sybil RPC Providers

**Threat:** Attacker controls majority of RPC providers.

**Impact:** Quorum consensus can be manipulated.

**Mitigation:**

- Diverse provider selection (different infrastructure providers)
- Provider reputation tracking
- Fallback to public endpoints

## 8. Threat Matrix

| Threat | Likelihood | Impact | Detection | Response |
|--------|-----------|--------|-----------|----------|
| Byzantine nodes | Medium | High | Quorum disagreement | Fallback to additional providers |
| Malicious indexers | Medium | Medium | On-chain verification | Reject stale data |
| RPC equivocation | Low | High | Provider disagreement | Quorum re-evaluation |
| Delayed finality | High | Medium | Timeout monitoring | Recovery engine activation |
| Partial partitions | Low | Medium | Connection monitoring | Provider rotation |
| Double-spend | Low | Critical | Registry checks | Transfer rejection |
| Replay attacks | Low | High | Replay registry | Proof rejection |
| Lease bypass | Low | High | Lease validation | Transfer rejection |
| Proof tampering | Low | Critical | Canonical hashing | Proof rejection |
| Key compromise | Low | Critical | Anomaly detection | Key rotation |
| Contract upgrade | Low | Critical | Manifest verification | Deployment rejection |

## 9. Compliance Checklist

- [x] All hashing uses `csv_tagged_hash` with domain separation
- [x] Canonical serialization uses `ciborium` (deterministic CBOR)
- [x] Lease system prevents concurrent transfers
- [x] Replay registry tracks all processed proofs
- [x] RPC quorum client requires multi-provider agreement
- [x] Finality depth checks prevent premature action
- [x] Reorg detection handles chain reorganizations
- [x] Recovery engine handles stuck transfers ✅ Implemented (Phase 9)
- [x] Encrypted state storage for wallet keys
- [x] Zod schema validation on all MCP inputs
- [x] Structured audit logging for all operations
- [x] Contract manifest governance for deployments

## 10. Review Schedule

This threat model should be reviewed:

- After each protocol upgrade
- When adding new chain adapters
- When modifying core cryptographic primitives
- Annually, or when new attack vectors are discovered

## 11. Portable non-equivocation threats

Scope of this section: the threats that [RFC-0014](./rfcs/RFC-0014-portable-non-equivocation-invariant.md)
must survive before Parwana may advertise recipient-verifiable non-equivocation.
It is normative for Stage 1–4 of `development/PARWANA_PORTABLE_NON_EQUIVOCATION_PLAN.md`.

Three rules govern this section and differ from §4–§7 above:

1. **Every threat names the verifier rule that rejects it and the conformance
   test that proves the rejection.** An unmapped threat blocks the Stage 0 gate.
2. **No threat is mitigated by a local database property alone.** A replay
   database is a property of one participant (RFC-0014 §2, Claim A) and cannot
   discharge a threat about a *second* participant. Where a local defense is
   real but insufficient, it is listed as *defense in depth*, never as the
   mitigation.
3. **Residual threats are recorded as assumptions in §11.4, not omitted.**

Rule identifiers (`NE-R-*`) are the names the verifier reports; test
identifiers (`NE-T-*`) are the conformance cases that prove them. Both are
planned deliverables of the named ticket — this section is the contract they
must satisfy, written before the wire types change.

### 11.1 Threat-to-rule mapping

#### T-NE-01 — Same source state, different transition IDs

**Threat:** A holder builds two successor transitions from one source state,
differing only in transition ID, and delivers one to each of two recipients.

**Impact:** Two recipients each believe they hold the unique successor. Critical.

**Verifier rule:** `NE-R-CLOSURE-UNIQUE` — a successor's source-closure dimension
verifies only if closure evidence in the source state's declared closure domain
proves consumption of that state's closure handle *and* binds the consumption to
this transition's commitment. Two commitments cannot both satisfy it under one
finalized checkpoint (RFC-0014 §1.3, §1.5).

`NE-R-CLOSURE-HANDLE-SINGLE-USE` — the closure-domain verifier must reject a
second canonical consumption of the same closure handle. Assigning two
consumptions different positions in an ordered registry does not establish
non-equivocation (RFC-0014 §1.3, §1.7).

**Conformance test:** `NE-T-ISO-DOUBLESPEND` (PAR-CONF-001, RFC-0014 §5,
assertions A1–A2, A8).

**Defense in depth (not the mitigation):** the local replay registry rejects the
second consumption *within one process*.

#### T-NE-02 — Same source state, different recipients and destination chains

**Threat:** As T-NE-01, but the two successors also target different destination
chains, so the two closures are attempted in different settlement domains.

**Impact:** Cross-domain double-spend; the source appears consumed in neither
domain's local view. Critical.

**Verifier rules:**

- `NE-R-CLOSURE-DOMAIN` — closure evidence is evaluated only in the closure
  domain declared by the *source state*, never one chosen by the successor.
  A settlement chain is not a closure domain unless it is the source's.
- `NE-R-DEST-BINDING` — the destination assignment delivered to the recipient
  must be the one bound by the transition commitment; a re-pointed destination
  invalidates the commitment.

**Conformance test:** `NE-T-XCHAIN-CONFLICT` (PAR-XCHAIN-001) with
`NE-T-ISO-DOUBLESPEND` as the single-domain case.

**Note:** settlement on the destination chain and closure on the source chain
are separate invariants and are tested separately. Success at settlement is
never evidence of source closure.

#### T-NE-03 — Independent replay databases

**Threat:** The sender runs two processes, two wallets, and two replay
databases, so no local uniqueness check ever sees both attempts.

**Impact:** The entire local-replay defense is bypassed at zero cost. Critical.

**Verifier rule:** `NE-R-NO-LOCAL-AUTHORITY` — the source-closure dimension may
only be satisfied by chain-native closure evidence verified against a named
checkpoint. No local store, cache, or registry may set, upgrade, or substitute
for that dimension. Local stores are caches of verified history only.

**Conformance test:** `NE-T-ISO-DOUBLESPEND` (PAR-CONF-001). The fixture's
isolation requirement (RFC-0014 §5.2 — no shared process, wallet, database,
store, filesystem path, or in-memory registry) exists specifically to prove this
threat is addressed. A test that shares any of these does not test T-NE-03.

**Explicitly not a mitigation:** the replay database, the nullifier set, the
lease system, and the accepted-state store. Each is local.

#### T-NE-04 — Forged nonempty inclusion or finality payloads

**Threat:** An attacker supplies syntactically well-formed, nonempty proof
bytes — random data, a proof for a different outpoint, or a valid proof whose
commitment binds a different transition — and relies on a length or emptiness
check to pass.

**Impact:** Fabricated closure; the whole invariant collapses. Critical.

**Verifier rules:**

- `NE-R-PROOF-CONSUMES` — inclusion evidence must demonstrate consumption of
  the specific closure handle, verified cryptographically. Nonempty bytes are
  not evidence (RFC-0014 §1.3).
- `NE-R-PROOF-BINDS` — the consumption must commit to this transition's
  commitment; a valid proof bound to another transition fails.
- `NE-R-NO-CALLER-BOOLEAN` — no caller-supplied flag may raise any assurance
  dimension. `native_proof_validated`-style booleans may cache a result
  internally but must not cross the verifier boundary (RFC-0014 §2; plan §2
  rule 4).

**Conformance test:** `NE-T-FORGED-PROOF-CORPUS` (PAR-CONF-003) — nonempty
garbage, wrong header, wrong Merkle path, wrong outpoint, wrong transition
commitment; plus RFC-0014 §5.6 controls C1–C3 and C6.

#### T-NE-05 — Cyclic, duplicate-ID, self-parenting, and root-substitution DAGs

**Threat:** A hostile graph that decodes successfully: a cycle, two nodes
sharing an identifier, a node listing itself as parent, a substituted segment
root, mutated node content under a preserved identifier, or the same graph
reordered to produce a second identity.

**Impact:** Ancestry and therefore state provenance become forgeable. Critical.

**Verifier rules:**

- `NE-R-NODE-ID-RECOMPUTED` — node identity is recomputed from canonical node
  content; a supplied identifier is never trusted.
- `NE-R-ROOT-RECOMPUTED` — the segment root is recomputed from the canonical
  node set; a supplied root is never trusted.
- `NE-R-DOMAIN-SEPARATED` — node, edge, and root hashes use distinct domain
  tags, so no digest is reusable across positions.
- `NE-R-NODE-ID-UNIQUE` — duplicate node identifiers fail with a distinct error.
- `NE-R-ACYCLIC` — cycles and self-parenting fail with distinct errors.
- `NE-R-PARENTS-RESOLVE` — every declared parent must exist in the segment.
- `NE-R-ROOTS-DEFINED` — a root is a node declaring no parents. Multiple roots
  and disconnected components are **permitted**: a segment may carry parallel
  histories, and refusing them would reject honest evidence rather than a
  hostile shape. Ancestry must terminate inside the segment, so a nonempty
  acyclic segment whose parents resolve always has at least one root; a segment
  reaching the ordering step without one fails closed.
- `NE-R-CANONICAL-ORDER` — a reordered but otherwise identical graph either
  canonicalizes to the same identity or is rejected; it is never accepted twice
  under two identities.

**Conformance tests:** `NE-T-HOSTILE-GRAPH-CORPUS` (PAR-CONF-002) plus the
property-generated hostile-graph suite required by PAR-DAG-002. Fixed fixtures
alone do not discharge this threat.

#### T-NE-06 — Stale checkpoints and chain reorganizations

**Threat:** A recipient verifies against a checkpoint far behind the tip, or a
reorganization orphans the block that justified an accepted result and orders a
competing consumption first.

**Impact:** A revoked closure keeps reading as final; a double-spend succeeds
retroactively. Critical.

**Verifier rules:**

- `NE-R-CHECKPOINT-NAMED` — every result names the checkpoint it was evaluated
  against. A result with no named checkpoint is not a result.
- `NE-R-FRESHNESS-SEPARATE` — checkpoint staleness is reported as its own
  dimension and never silently upgrades or downgrades another dimension.
- `NE-R-REORG-DEMOTES` — an accepted result whose justifying checkpoint is
  orphaned moves to `revoked` or `indeterminate` and can never remain `final`;
  its descendants become nonfinal until revalidated; prior observations are
  superseded, never erased (RFC-0014 §1.6).

**Conformance tests:** `NE-T-REORG-REVOCATION` (RFC-0014 §5.5 / PAR-REORG-001),
`NE-T-STALE-CHECKPOINT` (PAR-CONF-003; RFC-0014 §5.6 controls C4–C5).

#### T-NE-07 — Crash between closure submission, persistence, and consignment emission

**Threat:** The sender crashes after broadcasting the source closure but before
journaling it, or after journaling but before emitting the consignment. On
restart it either re-closes (creating a second closure attempt) or treats the
source as spendable again.

**Impact:** Duplicate closure attempts, or an equivocation created by accident
rather than malice. High.

**Verifier and runtime rules:**

- `NE-R-ATOMIC-ACCEPT` — accepted transition, consumed source, created outputs,
  closure identity, checkpoint, and verification report are recorded atomically
  or not at all.
- `NE-R-CONFLICT-KEY-IS-SOURCE` — replay and conflict keys derive from the
  consumed source state, not from a transfer or transaction identifier, so a
  retry under a new transfer ID cannot escape the conflict domain.
- `NE-R-RECOVERY-DETERMINISTIC` — journal recovery reproduces the same artifact
  and never creates a second closure; a failed emission does not make the source
  appear spendable again.

**Conformance test:** `NE-T-CRASH-CAMPAIGN` (PAR-CONF-004) with fault injection
before and after source submission, proof acquisition, journal writes,
consignment emission, and recipient persistence.

**Defense in depth (not the mitigation):** the execution journal and the lease
system. Both are local; they bound the damage, and the chain ordering decides.

#### T-NE-08 — Reference-as-endorsement and citation-as-consumption confusion

**Threat:** An `EvidenceRef` (a repeatable citation) is placed in a consumed-input
slot, or a `ConsumedStateRef` is presented as a repeatable citation, or the two
canonical encodings are made to collide so one decodes as the other.

**Impact:** Exclusive state is consumed observationally without closure, or a
citation is read as an endorsement of the cited material. Critical.

**Verifier rules:**

- `NE-R-REF-DISJOINT` — consumption references and evidence references are
  distinct types with distinct domain tags and distinct canonical
  discriminants; neither encoding can be reinterpreted as the other.
- `NE-R-EXCLUSIVITY-BOUND` — exclusivity is fixed by the output's state type at
  creation and is non-downgradable. No transition, schema revision, profile, or
  decoding path may consume an exclusive output observationally.
- `NE-R-CITATION-NOT-ENDORSEMENT` — citing evidence asserts only that the
  commitment was referenced under its stated proof requirement. It never
  asserts that the cited material is true, endorsed, or authorized.

**Conformance tests:** `NE-T-REFERENCE-FIREWALL` — the type-level / compile-fail
firewall cases required by PAR-STATE-001 and the observational-consumption
cases in PAR-STATE-002; plus the encoded type-confusion cases in
`NE-T-HOSTILE-GRAPH-CORPUS` (PAR-CONF-002).

### 11.2 Threat matrix (non-equivocation)

| ID | Threat | Likelihood | Impact | Primary rule | Conformance test |
|----|--------|-----------|--------|--------------|------------------|
| T-NE-01 | Same source, different transition IDs | High | Critical | `NE-R-CLOSURE-UNIQUE` | `NE-T-ISO-DOUBLESPEND` |
| T-NE-02 | Same source, different recipients/destinations | High | Critical | `NE-R-CLOSURE-DOMAIN` | `NE-T-XCHAIN-CONFLICT` |
| T-NE-03 | Independent replay databases | High | Critical | `NE-R-NO-LOCAL-AUTHORITY` | `NE-T-ISO-DOUBLESPEND` |
| T-NE-04 | Forged nonempty proof payloads | Medium | Critical | `NE-R-PROOF-CONSUMES` | `NE-T-FORGED-PROOF-CORPUS` |
| T-NE-05 | Hostile DAGs | Medium | Critical | `NE-R-NODE-ID-RECOMPUTED` | `NE-T-HOSTILE-GRAPH-CORPUS` |
| T-NE-06 | Stale checkpoints and reorgs | High | Critical | `NE-R-REORG-DEMOTES` | `NE-T-REORG-REVOCATION` |
| T-NE-07 | Crash between closure and emission | Medium | High | `NE-R-ATOMIC-ACCEPT` | `NE-T-CRASH-CAMPAIGN` |
| T-NE-08 | Citation/consumption confusion | Medium | Critical | `NE-R-REF-DISJOINT` | `NE-T-REFERENCE-FIREWALL` |

### 11.3 Status

This section is the Stage 0 contract that Stage 1–4 must satisfy. A named rule
is not evidence that its complete production path or portable conformance case
has shipped. Current status:

| Threat | Current implementation status |
|---|---|
| T-NE-01 | Implemented for Bitcoin: the isolated-recipient campaign exercises both delivery orders against one finalized source ordering and isolated recipient stores. |
| T-NE-02 | Planned: source-domain closure and portable destination binding require Stages 2–3; additional chains are Stage 5. |
| T-NE-03 | Implemented for Bitcoin: typed assurance refuses to equate local replay with external closure and the isolated-recipient test uses separate stores. |
| T-NE-04 | Implemented for Bitcoin: the versioned forged-proof corpus and cryptographic closure verifier fail closed by assurance dimension. |
| T-NE-05 | Implemented in the V2 conformance surface: canonical DAG identity and every plan-listed hostile mutation have stable expected reasons. |
| T-NE-06 | Implemented for Bitcoin: finality, freshness, and orphaning remain distinct checkpoint-relative outcomes. |
| T-NE-07 | Implemented: atomic acceptance and deterministic send-resume campaigns are required release checks. |
| T-NE-08 | Implemented by the reference firewall, creation-time exclusivity binding, and the shared V2 conformance package. |

The Stage 4 release gate unlocks exactly this claim: for Bitcoin sources, an
isolated recipient can verify that a successor consumes a uniquely ordered
source state and is bound to the delivered destination assignment, relative to
the named checkpoint, finality policy, proof provider, freshness bound, and
trust mode. It does not claim equivalent closure for Ethereum, Sui, Aptos, or
Solana; those adapters remain outside this release claim.

### 11.4 Accepted residual risk (assumptions, not mitigations)

These are not addressed by any rule above. They are recorded here so a reader
cannot mistake silence for coverage.

| ID | Assumption | Why it is accepted | Where it must be visible |
|----|------------|--------------------|--------------------------|
| A-NE-01 | The closure domain's ordering is honest — no majority-hashpower rewrite, no compromised registry. | Parwana cannot be stronger than the ordering it grounds on. | The verification report names the closure domain, trust mode, and finality model, so the reader can price this risk. |
| A-NE-02 | The recipient's view of the checkpoint is not attacker-controlled. A lying RPC quorum can supply a false tip. | Mitigating this fully requires a light client or full node; those are trust modes, not defaults. | Trust mode (`full node` / `light client` / `RPC quorum` / `attested registry`) is named in every report. |
| A-NE-03 | Probabilistic-finality domains may reorganize below the configured depth. | Depth is a policy choice, not a proof. | Finality strength and checkpoint are separate reported dimensions; §11.1 T-NE-06 governs retraction. |
| A-NE-04 | Sender-side key compromise is out of scope: an attacker with the authorization key is the authorized party. | Non-equivocation orders *authorized* successors; it does not authenticate intent. | §5.1 Key Compromise. Portable closure limits the damage to one successor, which is the improvement it offers. |
| A-NE-05 | Detection of equivocation *attempts* (as opposed to prevention of a second success) requires out-of-band comparison. | RFC-0014 §2 Claim B is detectable-after-the-fact by construction. | Reports distinguish "no conflict observed" from "uniqueness proven"; absence of an observed conflict is never reported as proof. |
| A-NE-06 | Parwana proves binding and uniqueness, not that referenced off-chain content is true, useful, or legally operative. | Out of protocol scope. | RFC-0014 §3.2 N7; `NE-R-CITATION-NOT-ENDORSEMENT`. |
| A-NE-07 | V1 artifacts carry no closure evidence and can never be promoted to Claim C. | They predate the invariant. | V1 reports `closure: unavailable`; no format auto-detection (PAR-WIRE-002). |

## 12. References

- [RFC-0014: Portable Non-Equivocation Invariant](./rfcs/RFC-0014-portable-non-equivocation-invariant.md)
- [Protocol Constitution](./PROTOCOL_CONSTITUTION.md)
- [Protocol Invariants](./PROTOCOL_INVARIANTS.md)
- [Audit Implementation Specification](./audit/implementation.md)
- BIP-340: Tagged Hashing
- NIST SP 800-208: Authenticated Key Exchange
