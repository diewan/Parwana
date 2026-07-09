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
6. **Signer Binding:** Verify each proof-bundle signature and confirm the recovered public key is a member of the recipient's **approved verifier set** (the RFC-0012 §9 verifier keys). The public key embedded in a signature blob is chosen by the sender and proves nothing on its own — an offline accept that trusts it is forgeable. The approved set is supplied from **trusted local config** (`[verifier] approved_keys` in `~/.csv/config.toml`), never from the consignment. Offline acceptance **fails closed** when no approved keys are configured. (Implemented by `csv_verifier::verify_proof_bound` / `verify_proof`; see VERIFY-SIGNER-BINDING-001.)

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
- **`signature_scheme`**: The proof bundle's declared signature scheme; offline verifiers must compare it with the source chain's expected scheme before signature verification
- **`ownership_signature`**: Signature proving ownership of the seal, verified using the scheme derived from chain configuration
- **`approved_signer`**: The recovered signature key MUST be a member of the recipient's approved verifier set (from trusted local config), not merely a well-formed signature over the DAG root. Fails closed when the set is empty (see VERIFY-SIGNER-BINDING-001)

Implementers must ensure all of these components are verified before accepting a proof bundle as valid.
