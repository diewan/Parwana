# Multi-Repository Readiness Tickets

This backlog starts after commit `853c151`, which reconciled documentation,
dependency declarations, the Rust toolchain, architecture rules, and package
checks. Those completed tasks are intentionally not repeated here.

## Target repository groups

| Repository | Intended contents |
|---|---|
| `csv-spec` | RFCs, protocol constitution, threat model, formal models, normative vectors |
| `csv-core-rs` | algebra, codec, hash, keys, protocol, wire, proof, verifier, schema, content |
| `csv-runtime-rs` | admission, coordinator, storage, observability, runtime, SDK |
| `csv-adapters-rs` | adapter interfaces/composition and all concrete chain adapters |
| `csv-contracts` | contracts, ABIs/IDLs, deployments, generated Rust bindings |
| `csv-tools` | CLI, wallet, P2P, examples, chain configuration, deployment tooling |

This is not a one-repository-per-crate plan. A physical split remains blocked
until the virtual-boundary rehearsal produces a go decision.

## Phase 1 — Stabilize cross-repository interfaces

- [ ] [REPOSPLIT-PORTS-001](./REPOSPLIT-PORTS-001.md) — Separate chain-neutral ports from adapter implementations
- [ ] [REPOSPLIT-COMPOSE-002](./REPOSPLIT-COMPOSE-002.md) — Move concrete adapter assembly to the composition boundary
- [ ] [REPOSPLIT-COMPAT-003](./REPOSPLIT-COMPAT-003.md) — Define API, protocol, and wire compatibility policy

## Phase 2 — Establish independent release confidence

- [ ] [REPOSPLIT-CI-004](./REPOSPLIT-CI-004.md) — Add the complete Rust release CI matrix
- [ ] [REPOSPLIT-RELEASE-005](./REPOSPLIT-RELEASE-005.md) — Add tagged release automation and provenance
- [ ] [REPOSPLIT-CONFORMANCE-006](./REPOSPLIT-CONFORMANCE-006.md) — Publish golden vectors and adapter conformance tests
- [ ] [REPOSPLIT-READINESS-007](./REPOSPLIT-READINESS-007.md) — Complete TRM-HARDEN release evidence
- [ ] [REPOSPLIT-GOVERNANCE-008](./REPOSPLIT-GOVERNANCE-008.md) — Define ownership and coordinated security releases

## Phase 3 — Prove and pilot the split

- [ ] [REPOSPLIT-BOUNDARY-009](./REPOSPLIT-BOUNDARY-009.md) — Build virtual repositories in isolation
- [ ] [REPOSPLIT-CONTRACTS-010](./REPOSPLIT-CONTRACTS-010.md) — Pilot extraction of contracts and generated bindings

## Dependency order

```text
PORTS-001 ─┐
COMPOSE-002 ├──> BOUNDARY-009 ──> CONTRACTS-010
COMPAT-003 ┤
CI-004 ────┤
RELEASE-005┤
CONFORMANCE-006
READINESS-007
GOVERNANCE-008
```

After `REPOSPLIT-CONTRACTS-010` has operated successfully for one release
cycle, create separate execution tickets for adapters, tools, and finally the
core/runtime decision. Do not schedule those physical extractions before the
pilot provides operational evidence.
