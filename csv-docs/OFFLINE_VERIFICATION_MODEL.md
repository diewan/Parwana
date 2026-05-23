# ❄️ Offline Verification Model

## 1. The Core Thesis

The CSV Protocol allows a party to receive an asset and prove its validity without querying a blockchain node at the moment of receipt.

## 2. The Proof Bundle Anatomy

A `ProofBundle` is a self-contained DAG containing:

1. **Transition Proofs:** The "What" (state changes).
2. **Seal Commitments:** The "Who" (the L1 anchor).
3. **Inclusion Proofs:** The "Where" (Merkle branches linking to an L1 block).
4. **Finality Proofs:** The "Weight" (Chain-specific `FinalityEvidence` variants: `CumulativeWork` for Bitcoin, `FinalizedCheckpoint` for Ethereum, `FinalizedSlot` for Solana, `ValidatorCertificate` for Aptos/Sui, or `DaHeaderInclusion` for DA layers).

## 3. The Trust Boundary

| Component | Status | Source |
| :--- | :--- | :--- |
| **Header Chain** | Verified Offline | Local Header Cache |
| **State Transition** | Verified Offline | Bundle Logic |
| **Inclusion** | Verified Offline | Merkle Math |
| **L1 Finality** | Typed Strength | `FinalityStrength::{Probabilistic|Deterministic}` |

**Note:** Finality is now a typed, independently-checked dimension (see AUDIT.md §1.1). The strength is specified per-chain as either `Probabilistic { confirmations }` (PoW chains like Bitcoin) or `Deterministic` (BFT chains like Ethereum, Solana, Aptos, Sui). This is orthogonal to inclusion strength.

## 4. Verification Workflow (Offline)

1. **Hash Verification:** Recompute the `TaggedHash` of the transition.
2. **Seal Verification:** Confirm the transition matches the commitment in the Single-Use Seal.
3. **Path Verification:** Walk the Merkle path from the commitment to the `state_root` (ETH) or `merkle_root` (BTC) provided in the bundle.
4. **Header Verification:** Verify the block header matches the user's local "Checkpoint" (Trusted Block Hash).
5. **Replay Check:** Query the local `ReplayDatabase` with `ReplayId` derived from all transfer inputs. The verifier MUST check this database before accepting any state transition (see PROTOCOL_INVARIANTS.md Invariant 9).

## 5. Security Invariant (Target Model, Stage 3)
>
> "An offline verifier with a trusted block hash at height $H$ can verify the entire history of an asset up to height $H$ with the same security as a Full Node."

**Current Status (Stage 1):** This requires an embedded header-chain validator (light client) per chain, which is a **Stage 3 roadmap item** (see PROTOCOL_INVARIANTS.md RPC Trust Model section). The invariant is architecturally correct but represents the target model, not current behavior. Stage 1 uses RPC quorum for header verification.

---

## VerifiedComponents

A valid offline verification requires the following components to be present and verified:

- **`inclusion`**: Merkle/MPT/checkpoint proof linking the commitment to an L1 block
- **`finality`**: Chain-specific finality evidence (see above)
- **`replay_checked`**: Confirmation that `ReplayId` is not in the local replay database
- **`ownership_signature`**: Signature proving ownership of the seal, verified using the scheme derived from chain configuration

Implementers must ensure all four components are verified before accepting a proof bundle as valid.
