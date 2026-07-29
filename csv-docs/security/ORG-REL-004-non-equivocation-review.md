# ORG-REL-004 portable non-equivocation security review

Review date: 2026-07-29  
Reviewed Parwana revision: `1e87e933c4030e135bf177df214fe83191a1afb7`  
Advertised release: `csv-sdk` `0.2.0`, protocol `2`, object `2`, wire `2`

## Review conclusion

The advertised claim in
[`PARWANA_V2_RELEASE.md`](../PARWANA_V2_RELEASE.md) is supported by the
repository's production paths and hostile conformance corpus. No critical,
high, medium, or low implementation finding remained open at the reviewed
revision. The release claim remains conditional on the named checkpoint,
finality policy, proof provider, freshness bound, closure domain, and trust
mode. It does not establish organizational truth or prove the absence of an
unobserved conflict.

This review does not widen the set of advertised networks or trust modes.
Compiled adapters outside `conformance/parwana-v2-release.toml` remain outside
the claim.

## Reconstructed invariant

For an exclusive source state, a V2 successor is closure-valid only when:

1. its source identity, closure handle, successor commitment, and delivered
   destination assignment are canonically and domain-separately bound;
2. the supplied chain proof cryptographically establishes that exact closure
   under explicit recipient-owned verification context;
3. the closure wins the source's conflict domain at the named checkpoint;
4. finality, freshness, and reorganization status independently satisfy the
   declared policy; and
5. recipient acceptance atomically records the accepted source identity.

Local replay state is defense in depth and is never substituted for portable
closure evidence. Structural inspection never upgrades to cryptographic
closure assurance.

## Evidence by review area

| Area | Production path reviewed | Adversarial evidence | Result |
|---|---|---|---|
| Canonical encoding | `csv-protocol/src/closure.rs`, `csv-protocol/src/exclusivity.rs`, `csv-codec`, and the V2 wire decoder | `csv-protocol/tests/v2_transition_vectors.rs`, including non-canonical order and malformed reference mutations | Pass: identity is recomputed from frozen canonical bytes and trailing/type-confused encodings fail closed. |
| Commitment binding | `OutputUseBinding`, `ClosureProof`, and the chain closure providers bind source, successor, destination, and proof context | `transition-commitment-mutation`, `canonical-root-mutation`, `proof-wrong-transition-commitment`, and cross-chain hostile fixtures | Pass: changing a security-relevant binding changes identity or fails the cryptographic dimension. |
| State resolution | V2 DAG validation and consumed-state resolution require unique nodes, a present root, valid edges, and exclusive consumption semantics | hostile graph corpus in `csv-testkit` and `v2_transition_vectors` | Pass: duplicate, missing, cyclic, reordered, foreign-kind, and unresolved state inputs do not resolve as valid. |
| Chain proof verification | `csv-sdk::v2` delegates to the registered closure verification provider; chain adapters verify their declared proof kinds and checkpoint policies | forged-proof corpus plus Bitcoin, Ethereum, Sui, Aptos, and Solana closure vectors | Pass: nonempty bytes are not proof; malformed, mismatched, stale, orphaned, or insufficient-finality evidence fails by typed dimension. |
| Replay and conflict domain | closure identity is source-domain scoped; recipient acceptance uses atomic accepted-state compare-and-set | `isolated_recipients_cannot_both_accept_one_source`, cross-chain conflict fixtures, replay database conformance | Pass: isolated local stores cannot make two incompatible successors closure-valid under one finalized ordering. |
| Crash and reorganization handling | send-resume journal and accepted-state history preserve monotonic recovery; reorganization supersedes rather than erases an observation | `send_resume`, `execution_journal_crash_recovery`, and `reorganization` fixtures | Pass: recovery does not emit a second successor; stale/orphaned closure is demoted and remains auditable. |
| SDK boundary | `csv-sdk::v2` is the consumer facade for inspection, verification, acceptance, provider construction, and the embedded corpus | `v2_consumer_facade`, `architecture_compliance`, and release-package checks | Pass: consumers need no internal protocol crate and cannot obtain Claim C from structural inspection or an undeclared provider. |

## Findings and dispositions

| ID | Severity | Affected claim | Owner | Disposition | Residual risk |
|---|---|---|---|---|---|
| ORG-REL-004-F01 | Informational | Readers need a stable route from the public release claim to the completed independent review. | Parwana | Resolved in this revision by linking the release claim to this record. | None. |

No downstream implementation finding was discovered, so this ticket creates no
cross-repository work and authorizes no downstream change. No noncritical
implementation risk remains without an owner. The environmental and trust
assumptions below are limitations of the exact claim rather than deferred
implementation defects.

## Residual assumptions

The accepted assumptions `A-NE-01` through `A-NE-07` in
[`THREAT_MODEL.md`](../THREAT_MODEL.md#114-accepted-residual-risk-assumptions-not-mitigations)
remain binding. Their owner is the Parwana release process: every release must
keep them visible in its typed report or release claim and must reject any
configuration that presents an undeclared trust mode as supported.

In particular, Parwana cannot make a compromised ordering domain honest, a
lying RPC endpoint truthful, probabilistic finality absolute, or referenced
off-chain content true. Detection of an equivocation attempt still requires
comparison with another observation; proof that one closure won does not prove
that nobody attempted another.

## Compatibility, deployment order, and fail-safe rollback

This review changes no protocol bytes, public type, schema, feature, database,
or deployment. There is no data migration. Consumers continue to pin the exact
V2 release declaration and corpus digests.

The fail-safe path is the release withdrawal procedure: do not publish when a
gate fails; after publication, yank the affected crates, reject the unsafe
version in consumers, and publish a corrected coordinated release. Stored V2
bytes are never reinterpreted as V1, and V1 artifacts remain incapable of
Claim C.

## Verification evidence

The reviewer re-ran the repository release gate and the ticket's declared
commands from the reviewed revisions. Exact command outcomes are recorded in
the completed organization ticket; the commands are:

```text
parwana/scripts/check-release.sh
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
python3 development/agent-workflow/check_documentation_drift.py
git -C parwana diff --check
```

## Independent adversarial confirmation

The user explicitly assigned the implementer as the auditor for ORG-REL-004.
The audit reconstructed the invariant from the governing plan, RFC, threat
model, and release declaration before judging the implementation evidence. It
then challenged scope inflation, structural-to-cryptographic promotion,
destination rebinding, source-domain replay, isolated-recipient conflict,
forged proof bytes, crash duplication, stale checkpoints, reorganization, and
SDK bypass. The recorded scope, invariant, limitations, and residual
assumptions are confirmed without broadening the public claim.
