# ❓ CSV Protocol: Comprehensive FAQ & Defensibility Guide

## 1. Philosophical & Strategic Foundations

### What is the CSV Protocol?

CSV stands for **Client-Side Validation**. Instead of a global blockchain validating every state transition, the CSV Protocol allows the parties involved in a transaction to validate the state themselves. The L1 (Bitcoin/Ethereum) acts only as a "Double-Spend Registry" through **Single-Use Seals**.

### What is a Single-Use Seal?

A primitive that can be closed exactly once. On Bitcoin, this is a UTXO. On Ethereum, it is a specific state entry in a smart contract. Once "spent," the seal is closed forever, preventing double-spends at the hardware/consensus level of the L1.

### What is the core innovation of CSV Protocol?

Most interoperability solutions focus on "messaging" or "bridging." CSV (Client-Side Validation) focuses on Sovereign State Portability. We treat the L1 not as an execution environment, but as a decentralized, immutable Single-Use Seal registry. The logic, history, and verification of an asset live with the user, not the chain.

### Is this a Bridge?

**No.** Bridges usually rely on a set of third-party validators (a multisig or a new consensus layer) to "lock and mint" assets. CSV Protocol moves the *right to spend* a seal across chains. The security comes from the source chain's finality and the mathematical integrity of the Proof Bundle, not a third-party committee.

### Why do we avoid the term "Bridge"?

A "Bridge" implies a middleman or a vault where assets are locked. In CSV, we are not locking assets to mint synthetic versions; we are evolving the state of an asset and "sealing" that evolution on a new chain. By removing the bridge narrative, we remove the "Bridge Hack" risk profile.

### "Who pays for the destination chain mint?"

Fee escrow in source-chain native token.

When a transfer is initiated, the sender escrows a small amount of the source chain's native asset (e.g., a few basis points of gas equivalent). This amount is released to the proof-delivery operator upon cryptographic confirmation of successful destination mint. No new token is issued.

Operators run Nostr relay nodes and are economically incentivized by the escrow release. The protocol enforces this at the smart contract level.

This model:

- Requires no new token (correct — no token before Series A)
- Aligns proof-delivery node operator incentives
- Is verifiable on-chain
- Has a clear answer for every partner question about economics

## 2. Technical Security & Verification

### "If I lose my Proof Bundle, I lose my money. This is too risky for users."

In CSV, data availability is a first-class citizen but decoupled from validation. While the *user* is responsible for their proof, the protocol integrates with **Nostr** and **Celestia** to ensure redundant, decentralized storage of these bundles. Losing a proof is no more likely than losing a private key if the backup infrastructure is used.

### "Offline verification is a myth; you still need to be online to check the L1 state."

We distinguish between **Verification** and **Finality Acquisition**.

1. **Acquisition (Online):** You fetch the Merkle proof from the L1.
2. **Verification (Offline):** Once you have the Proof Bundle, you can verify the entire
history of the asset on a device with zero internet. This is critical for privacy and high-security "cold" validation.

### "A reorg on the source chain makes the destination chain's asset 'fake'."

This is the "Ghost Seal" problem. Our protocol handles this through **Causal Invalidation**. The Proof Bundle includes a "Finality Proof." If a source chain reorgs below the threshold defined in the bundle, the destination seal is considered "Unstable" or "Invalid" by any conforming SDK until a new proof is provided. We don't ignore reorgs; we model them into the state machine.

### "This is overengineered. Why not just use a ZK-Rollup?"

ZK-Rollups are excellent but tethered to a single "L1" host. CSV Protocol is **chain-agnostic**. It allows a Bitcoin UTXO to "commit" to a state transition that ends up on Solana without a centralized sequencer. We provide sovereign interoperability, not just vertical scaling.

### How does "Offline Verification" actually work without a Node?

The protocol utilizes Proof Bundles. A bundle contains the entire cryptographic pedigree of an asset.

    Transition Logic: The code defining the state change.

    Witness Data: The signatures or proofs of the change.

    Inclusion Proofs: Merkle branches linking the transaction to an L1 block header.

    Header Chain: A sequence of block headers reaching a "Trusted Checkpoint."
    An offline device checks the math of the Merkle path against a trusted header. If the math checks out, the state is valid.

**Current Status (Stage 1):** Offline verification is the target model, but chain-specific verifiers have known security holes that are being fixed in Phase 3 (see AUDIT.md §3.1). For example, Bitcoin SPV Merkle verification currently validates a self-computed checksum but does not verify the Merkle branch against the block header's `merkle_root`. Production-grade offline verification will be available after Phase 3 completion.

### How do we prevent Double-Spending if validation is client-side?

Double-spending is prevented by the Single-Use Seal on the L1 and the programmatic `ReplayDatabase` mechanism. Even if a client "validates" a fake state, they cannot spend it unless they can produce a witness that the L1 seal was closed. Since the L1 (e.g., Bitcoin) enforces that a UTXO can only be spent once, the "Truth" is anchored in the hardware-backed consensus of the L1.

**Implementation:** The coordinator derives a `ReplayId` from all transfer inputs and checks it via `ReplayDatabase::insert_if_absent()` with compare-and-swap semantics before minting. This prevents concurrent coordinators from minting the same transfer (see PROTOCOL_INVARIANTS.md Invariant 9).

### What happens during a Chain Reorg?

This is the "Causal Invalidation" problem. If Chain A reorgs, the seal that anchored a transfer to Chain B might disappear.

    We implement Finality Thresholds. A Proof Bundle is not "Final" until it reaches a depth (e.g., 6 blocks on BTC). If a reorg occurs deeper than our threshold, the protocol would trigger a protocol-level rollback, marking the destination asset as "Orphaned" until a new anchor is found.

**Current Status (Stage 1):** The rollback mechanism is planned behavior but not yet implemented. We identifiesd this as "Unresolved problem — partial failure between insert and mint" with no recovery protocol yet designed. This is a target feature for Phase 2/3. The coordinator inserts the ReplayId before minting (intentionally — to block duplicate mints on retry).
If the mint then fails, the transfer is permanently poisoned with no recovery path. The rollback protocol for this case requires:
(a) a separate `pending` state before `consumed`,
(b) a timeout-based expiry for `pending` entries,
(c) a recovery coordinator that can promote `pending` → `consumed` after verifying the mint on-chain, or demote `pending` → `available` after confirming the mint never landed.
This protocol is not specified here and must be designed before production.

## 3. Competitive Comparison

### How is this different from IBC (Inter-Blockchain Communication)?

IBC requires "Light Client" logic on both chains. This is extremely expensive (gas-heavy) on chains like Ethereum. CSV moves the Light Client logic to the User's SDK, making cross-chain movement gas-efficient and possible even on chains that don't support complex smart contracts (like Bitcoin).

### How is this different from RGB or BitVM?

We share ancestors with RGB, but CSV Protocol is designed for Multi-Chain Native Seals. While RGB is primarily Bitcoin-centric, we provide a unified verification layer for Ethereum, Solana, and Move-based chains using the same Proof Bundle format.

## 4. CLI & Tooling

### How do I get started with the CLI?

Build the CLI with:

```bash
CXXFLAGS="-include cstdint" cargo build -p csv-cli --release
```

Then run the quick start:

```bash
csv chain list
csv wallet init --network test --words 12
```

See `csv-cli-tutorial.md` for a comprehensive guide with testnet examples.

### What chains does the CLI support?

The CLI supports Bitcoin (signet), Ethereum (Sepolia), Sui (testnet), Aptos (testnet), and Solana (devnet). Configure RPC URLs with `csv chain set-rpc`.

### Can I use the CLI for content management?

Yes. The CLI supports Merkleized content trees with selective disclosure:

```bash
csv content create --input data.txt --output tree.json
csv content prove --tree tree.json --index 0
csv content disclose --tree tree.json --include 0,2
```

### How does trust management work?

Trust packages define which chain states are considered authoritative. Manage them with:

```bash
csv trust status
csv trust import trusted-package.json
csv trust rotate <height> <hash>
```

### How do I monitor runtime health?

Use the runtime monitoring commands:

```bash
csv runtime status
csv runtime health
csv runtime admission
```

## 5. Architecture & Development

### What happened to csv-core?

`csv-core` has been removed as part of the Phase 1 restructuring. All legacy types have been migrated to `csv-protocol`, `csv-algebra`, and `csv-wire`. See `csv-core-TOMBSTONE.md` for the migration path.

### How is the repository structured?

The repository follows a layered architecture:

- `csv-algebra` — Pure typestate algebra
- `csv-protocol` — Protocol orchestration
- `csv-runtime` — Runtime coordination with csv-coordinator and csv-admission
- `csv-adapters/` — Chain-specific implementations
- `csv-cli` — Stateless CLI interface

See `ARCHITECTURE.md` for the full architecture overview.

### How are architecture rules enforced?

CI enforces dependency rules through:

- `deny.toml` — Compile-time dependency checks
- Architecture compliance tests — Runtime verification of import rules
- Constitution tests — Protocol invariant validation

### What testing infrastructure exists?

- Golden corpus tests — CBOR fixture validation
- Integration tests — Require RPC secrets (signet, sepolia, sui testnet)
- Adversarial tests — Byzantine simulations
- Replay tests — Replay safety validation
- End-to-end tests — Full transfer workflows via `csv test run-all`
