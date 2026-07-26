# RFC-0014: Portable Non-Equivocation Invariant

## Status

Accepted (Stage 0 of `development/PARWANA_PORTABLE_NON_EQUIVOCATION_PLAN.md`, ticket PAR-NE-001)

Normative for: `csv-protocol`, `csv-hash`, `csv-verifier`, `csv-runtime`, chain adapters, `csv-sdk`.

Companion documents:

- [RFC-0004: Replay Model](./RFC-0004-replay-model.md) — the *local* replay defense this RFC deliberately refuses to call non-equivocation.
- [RFC-0003: Finality Model](./RFC-0003-finality-model.md) — confirmation and finality vocabulary reused here.
- [THREAT_MODEL.md](../THREAT_MODEL.md) — the threat-to-rule mapping derived from this RFC (PAR-NE-002).

## Motivation

Parwana today can produce a canonical, signed, proof-carrying transition
envelope, and it can refuse to consume the same seal twice *in its own
database*. That is local replay protection. It is not non-equivocation.

A recipient who receives a consignment from a sender it does not trust
currently cannot answer the only question that matters:

> Is this the *unique* successor of the source state, or did the sender build a
> second, incompatible successor for someone else?

Answering that question requires an external ordering that both recipients
observe and neither can forge. Until that mechanism is specified precisely
enough to write an adversarial test against, "finish the seal" is not a
reviewable task. This RFC specifies it.

The RFC deliberately stops short of implementation. It fixes vocabulary,
separates three claims that are routinely conflated, states what a recipient
proves and what it must still assume, and defines the isolated-recipient
adversarial scenario as an executable-test specification.

## 1. Protocol terms

These terms are normative. Every later Stage 1–4 ticket, every verifier rule
name, and every conformance vector uses them with exactly these meanings.

### 1.1 Source state

A **source state** is one owned output created by a previously accepted
transition (or by genesis), identified by the triple

```text
(transition_id, output_index, state_type)
```

and carrying an **exclusivity class** fixed at creation (§1.8). A source state
is the object whose *unique successor* the protocol asserts. It is not a
seal, not a UTXO, and not a database row; a seal or UTXO is the chain-native
*closure handle* by which a source state becomes ordered (§1.3).

A source state has exactly one **closure domain**: the named external ordering
that decides which of several candidate successors wins. The closure domain is
a property of the source state, not a choice made by a successor transition.

### 1.2 Successor transition

A **successor transition** is a transition that lists a source state in its
consumed inputs. A successor transition is **candidate** until its source
closure is verified, and **closed** afterwards.

Two successor transitions of the same source state are **incompatible** if
both are candidate and their transition commitments differ. Incompatibility is
a structural property computable offline by anyone holding both artifacts. It
is *not* a verdict: seeing only one of the two proves nothing about the other.

### 1.3 Closure evidence

**Closure evidence** is chain-native material proving that the source state's
closure handle was consumed in the closure domain, *and* that the consumption
is cryptographically bound to exactly one successor transition commitment.

Closure evidence is well-formed only if it establishes all four of:

1. **Domain** — which closure domain (chain, network, contract/deployment) the
   evidence belongs to.
2. **Consumption** — that the specific closure handle of *this* source state
   was consumed, not some other handle.
3. **Binding** — that the consumption commits to *this* successor transition's
   commitment, so the evidence cannot be re-pointed at a sibling.
4. **Position** — where in the closure domain's ordering the consumption sits,
   so it can be evaluated against a checkpoint (§1.4).

Evidence that establishes fewer than four is not closure evidence. These four
properties are necessary but do not create uniqueness by themselves: the
verifier MUST also enforce the closure domain's rule that one closure handle
can have at most one canonical consumption at a checkpoint. A registry that
can order two successful consumptions of the same handle has ordering, but is
not a closure domain under this RFC. In particular, *nonempty proof bytes* are
not closure evidence, and a tagged hash of a seal is not closure evidence:
neither establishes consumption.

### 1.4 Checkpoint

A **checkpoint** is a recipient-selected, explicitly named position in a
closure domain's ordering, together with the finality policy applied at that
position. For Bitcoin a checkpoint is a block hash at height `H` plus a
required confirmation depth; §1.7 generalizes.

Every verification result is *relative to a checkpoint*. A result with no named
checkpoint is not a verification result. Two recipients evaluating the same
consignment against the same checkpoint MUST reach the same conclusion; that
determinism is the property Stage 4 tests.

A checkpoint is **stale** relative to an observed tip when the tip is more than
the deployment's configured freshness bound beyond it. Staleness is reported as
its own dimension and never silently upgrades or downgrades another.

### 1.5 Conflict

A **conflict** exists when two incompatible successor transitions (§1.2) of the
same source state both carry well-formed closure evidence in the same closure
domain. Under a correct closure domain this is impossible after finality; a
conflict observed before finality means at most one of the two can survive.

The **conflict reason** returned to a rejected recipient is machine-readable
and names: the source state, the two competing transition commitments, the
closure domain, and the checkpoint under which the loss was decided.

Absence of an observed conflict is never evidence of uniqueness. An indexer
that has seen no competitor has proven nothing; only the closure domain's
ordering decides.

### 1.6 Reorganization

A **reorganization** is a change to a closure domain's ordering that removes or
relocates a previously observed consumption. On reorganization:

- An accepted result whose justifying checkpoint is orphaned MUST move to
  `revoked` (a competing consumption is now ordered first) or `indeterminate`
  (the ordering no longer contains the consumption and no competitor is known).
- It MUST NOT remain `final`.
- Descendants of the affected result become nonfinal until revalidated.
- Audit history is append-only: revocation supersedes an observation, it never
  erases it.

### 1.7 Closure domain kinds

Bitcoin is the **normative reference model** (§4). Other closure domains
reproduce its properties; they do not redefine the invariant. A closure domain
MUST declare, in every verification report:

| Property | Meaning |
|---|---|
| Ordering source | UTXO spend order, object/resource version order, nullifier-set insertion order, or attested-registry sequence |
| Trust mode | full node, light client, RPC quorum, or attested registry |
| Finality model | probabilistic depth, or deterministic certificate |
| Reorg exposure | whether and how the ordering may retract |

A domain that cannot state all four is not usable for closure. In addition, its
verification rules MUST reject a second canonical consumption of the same
closure handle; merely assigning the two consumptions different sequence
positions does not satisfy portable non-equivocation.

### 1.8 Exclusivity class

Every owned output carries an **exclusivity class** determined by its state
type in the schema at the moment the output is created:

- **Exclusive** — at most one successor transition may consume it, ever. Requires
  closure evidence in the source state's closure domain.
- **Citable** — may be referenced any number of times as evidence. Consuming it
  is not a defined operation.

The exclusivity class is immutable and non-downgradable. No later transition,
schema revision, profile, or decoding path may reinterpret an exclusive output
as citable. This is the protocol-level statement of the rule that
`ConsumedStateRef` and `EvidenceRef` never share a wire type or verifier path.

## 2. Three claims that must never be conflated

Reviewers, product copy, and verification reports must keep these separate.
They have different adversaries, different evidence, and different failure
modes. Collapsing them is the specific error this RFC exists to prevent.

### Claim A — Local replay protection

> *This process has not previously accepted a transition consuming this source
> state.*

- **Evidence:** the verifier's own replay database / nullifier set.
- **Adversary defeated:** an honest-but-repeating sender; accidental resubmission.
- **Adversary NOT defeated:** a sender running a second process, second wallet,
  or second database. A local database is a property of *one* participant and
  says nothing about any other.
- **Scope:** one verifier instance.
- **Status in Parwana today:** implemented (RFC-0004).

### Claim B — Sender non-equivocation (authenticated uniqueness)

> *The sender has not signed two incompatible successors of this source state
> — as far as the material I hold shows.*

- **Evidence:** signatures over transition commitments, plus any equivocation
  proof (two conflicting signed artifacts) that happens to be presented.
- **Adversary defeated:** a sender who signs two successors *and whose victims
  compare notes*. Equivocation becomes attributable after the fact.
- **Adversary NOT defeated:** a sender who equivocates to two isolated
  recipients who never meet. Claim B is *detectable-after-the-fact*, not
  *preventive*, and it requires out-of-band comparison.
- **Scope:** the set of artifacts actually gathered.

### Claim C — Globally ordered closure (portable non-equivocation)

> *In closure domain D, as of finalized checkpoint H, the source state's closure
> handle was consumed exactly once, and that consumption is bound to this
> successor transition.*

- **Evidence:** closure evidence (§1.3) verified against checkpoint H.
- **Adversary defeated:** a sender with unlimited processes, wallets, databases,
  and recipients. The ordering is external to all of them.
- **Adversary NOT defeated:** an adversary who controls the closure domain
  itself (majority hashpower, a compromised registry, a lying RPC quorum). The
  report names the trust mode precisely so this residual is visible.
- **Scope:** the closure domain, up to checkpoint H, under the declared trust mode.

**Only Claim C is portable.** Claims A and B travel with a participant; Claim C
travels with the artifact. A verification report MUST NOT present A or B in a
way that a reader could mistake for C, and MUST NOT aggregate them into a single
badge (see PAR-VERIFY-001).

## 3. What a recipient proves and what it still assumes

### 3.1 Provable

Given a V2 consignment, a named closure domain D, and a finalized checkpoint H,
an isolated recipient can establish, offline apart from acquiring H:

| # | Provable statement |
|---|---|
| P1 | The delivered bytes decode canonically and re-encode identically. |
| P2 | Every node identity and the segment root are recomputed from content, not asserted. |
| P3 | The graph is acyclic, has defined roots, and has a single canonical order. |
| P4 | Each consumed reference resolves to exactly one parent output of matching index, state type, and schema. |
| P5 | The transition commitment binds the resolved inputs and the created outputs. |
| P6 | The declared authorizations verify against the transition commitment. |
| P7 | The source state's closure handle was consumed in D. |
| P8 | That consumption commits to *this* transition commitment and no other. |
| P9 | The consumption is included at a position at or before H, and H satisfies the configured finality policy. |
| P10 | Therefore: **as of finalized checkpoint H in domain D, no transition other than this transition has consumed the source state.** Equivalently, before applying this transition it was unspent at H, and after applying it this transition is its unique canonical successor. |
| P11 | The destination assignment delivered to this recipient is the one bound by the commitment. |

### 3.2 Not provable

| # | Statement that is NOT provable, and why |
|---|---|
| N1 | "This state is unspent everywhere right now." Offline, the recipient has no view past H. Later activity or a reorganization may change the canonical conclusion after H. Only *as of a checkpoint* is meaningful. |
| N2 | "No conflicting consignment was ever created." A sender may sign any number of candidates; the ordering decides which one closes, not which ones exist. |
| N3 | "The sender is honest." Non-equivocation is enforced by the ordering, not inferred from behaviour. |
| N4 | "The closure domain will never reorganize." Probabilistic finality is a policy choice; §1.6 governs retraction. |
| N5 | "The observed absence of a conflict proves uniqueness." Only the ordering proves uniqueness; an indexer's silence is lag, not evidence. |
| N6 | "The trust mode does not matter." An RPC quorum result is not a full-node result; the report names which was used. |
| N7 | "The off-chain payload is meaningful." Parwana proves binding and uniqueness, not that the referenced content is true, useful, or legally operative. |

The public claim language for M0–M3 remains the plan's §8 first form. Only after
the Stage 4 gate passes for Bitcoin may Parwana advertise the second form.

## 4. Bitcoin as the normative reference closure model

Bitcoin is the reference because its ordering property is the one this
invariant is defined against: **a UTXO can be spent at most once in the
canonical chain, and the spend is publicly and independently verifiable from
headers plus a Merkle path.** Parwana's RGB ancestry already models source
states as single-use seals over outpoints.

Normative consequences:

1. The Bitcoin closure domain is `ordering source = UTXO spend order`,
   `finality model = probabilistic depth`, `reorg exposure = yes`.
2. Closure evidence for Bitcoin is: the spending transaction, the consumed
   outpoint, the commitment binding (per the selected RGB-compatible
   seal-closing construction), a Merkle path to a block header, and the header
   chain position relative to checkpoint H.
3. Every other chain adapter MUST map its primitive onto §1.3's four
   properties and MUST pass the same abstract conformance suite. An adapter
   that cannot express "consumption" as a *single* ordering event does not
   qualify as a closure domain.
4. Where a chain's native semantics and Bitcoin's differ, the difference is
   recorded as a declared property (§1.7), never as a redefinition of the
   invariant.

This RFC does not generalize to other chains. Stage 5 tickets do, and they are
bound by this section.

## 5. The isolated-recipient adversarial scenario

This section is the normative acceptance scenario. It is written as an
executable-test specification: a reviewer implements it directly, without
inventing missing semantics. It is realized by ticket PAR-CONF-001.

### 5.1 Test identity

```text
id:      NE-ISO-001
name:    isolated recipient double-spend rejection
gate:    Stage 4 exit / milestone M4
domain:  bitcoin (regtest or signet), the normative reference model
```

### 5.2 Fixture

| Symbol | Meaning | Constraint |
|---|---|---|
| `S` | one source state | exclusivity class = Exclusive; created by an accepted transition; closure handle = one Bitcoin outpoint |
| `H0` | checkpoint at which `S` is confirmed unspent | finality policy satisfied |
| `Sender` | hostile holder of `S`'s authorization key | may run arbitrary processes |
| `R1`, `R2` | recipients | distinct destinations; **no shared state of any kind** |

Isolation is a hard requirement of the fixture, not an implementation detail.
`R1` and `R2` MUST NOT share: OS process, wallet, replay database, accepted-state
store, filesystem path, or in-memory registry. A test that shares any of these
is testing Claim A and MUST NOT be presented as testing Claim C.

The two recipients MAY share a view of the Bitcoin chain. That is the point:
the chain is the only permitted shared object.

### 5.3 Procedure

```text
 1. arrange: create S; confirm to H0; assert S is unspent at H0.
 2. arrange: start two isolated verifier instances V1 (for R1) and V2 (for R2).
 3. act:     Sender builds transition T1 consuming S, paying R1.
 4. act:     Sender builds transition T2 consuming S, paying R2,
             with commitment(T1) != commitment(T2)
             and a different transition id, destination, and process.
 5. act:     Sender attempts source closure for T1 and for T2 in the
             Bitcoin domain. The chain accepts at most one.
 6. act:     wait for a checkpoint H1 that satisfies the finality policy.
 7. act:     deliver consignment C1 only to V1; deliver C2 only to V2.
 8. assert:  see 5.4.
```

Step 5 is the only step that may be nondeterministic about *which* transition
wins. The test MUST NOT assume T1 wins.

Each verifier receives only its own consignment, but it resolves the source
handle's canonical consumption from the shared Bitcoin view at `H1`. The
losing verifier therefore learns the winning transition commitment from
chain-authenticated closure material, not from the other verifier, the sender,
or a shared replay database. If the closure construction cannot reveal and
authenticate that binding, assertion A2 cannot be implemented and the
construction does not satisfy §1.3.

### 5.4 Assertions

| # | Assertion |
|---|---|
| A1 | Exactly one of `{V1.verify(C1, H1), V2.verify(C2, H1)}` reports source closure as **verified**. |
| A2 | The other reports source closure as **failed**, with a machine-readable conflict reason naming `S`, both transition commitments, the closure domain, and `H1`. |
| A3 | Neither verifier consulted the other, and neither consulted the sender's database. Enforced by construction: the fixture gives them no channel. |
| A4 | The losing verifier's report does **not** claim `FullyVerified`, and its aggregate label does not hide the failed closure dimension. |
| A5 | Both reports name their closure domain, checkpoint `H1`, trust mode, and proof provider. |
| A6 | Re-running verification of either consignment against `H1` reproduces the identical report (determinism). |
| A7 | Reversing delivery order, or running `V2` first, does not change which consignment wins. |
| A8 | Running the winning verifier with the loser's consignment *also* rejects it — the outcome is a property of the artifact and the checkpoint, not of arrival order. |

### 5.5 Reorganization extension (NE-ISO-002)

```text
 9. act:    force a reorganization that orphans the block containing the
            winning closure, and re-mine so the competing closure is ordered
            first.
10. assert: the previously accepted result moves to `revoked` or
            `indeterminate`; it is never still reported as `final`.
11. assert: descendants of the revoked result are nonfinal until revalidated.
12. assert: the prior observation is retained in append-only audit history.
```

### 5.6 Negative controls

A conformance run is invalid unless these also hold — they exist to prove the
test can fail:

| # | Control |
|---|---|
| C1 | Replacing closure evidence with random nonempty bytes of the same length fails. |
| C2 | Substituting a well-formed closure proof for a *different* outpoint fails. |
| C3 | Substituting a valid closure whose commitment binds a *different* transition fails. |
| C4 | Verifying against a checkpoint before the closure's inclusion height fails as not-yet-final, not as invalid. |
| C5 | Verifying against a stale checkpoint reports staleness as its own dimension. |
| C6 | A caller-supplied "already validated" flag cannot make any of C1–C5 pass. |

## 6. Impact

- Stage 1 tickets (PAR-DAG-\*, PAR-STATE-\*, PAR-VERIFY-001, PAR-VECTORS-001)
  implement P1–P6 and the reporting discipline of §2.
- Stage 2 tickets implement P7–P9 for Bitcoin.
- Stage 3 makes the whole of §3.1 portable in one artifact.
- Stage 4 executes §5.
- V1 artifacts predate closure evidence. They report `closure: unavailable` and
  are never promoted to Claim C.

## 7. Alternatives considered

**Local replay database as the uniqueness authority.** Rejected: it is a
property of one participant. The plan's §7 lists this as permanently deferred.

**Sender attestation of uniqueness (a signed "I did not double-spend").**
Rejected: an authoritative boolean crossing a trust boundary. It converts
Claim C into Claim B while reading like Claim C.

**An indexer (Tuppira) as the conflict oracle.** Rejected: an indexer's absence
of an observed conflict is lag, not proof (N5). Tuppira observes; it never
grants validity.

**A transition-selected closure mode.** Rejected and deferred by plan §7:
letting the successor choose its own strength lets an attacker downgrade an
exclusive state observationally. §1.8 binds exclusivity to the output at
creation instead.

## 8. Unresolved questions

1. The exact RGB-compatible seal-closing construction for Bitcoin (owned by
   PAR-BTC-001) — this RFC fixes the properties the construction must satisfy,
   not the construction.
2. The default freshness bound per deployment (§1.4). The bound must exist;
   its value is deployment configuration.
3. Whether an attested-registry closure domain is permitted in production or
   only for development. Its trust mode is expressible, so it is not excluded
   here; the release gate (PAR-REL-001) decides what may be advertised.
