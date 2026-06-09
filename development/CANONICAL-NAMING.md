# Canonical Contract Naming — Unified Across All Chains

**Status:** Constitutional — all chain contracts MUST use these names
**Last Updated:** 2026-06-09

---

## Naming Principles

1. **Self-expressive:** Every function name clearly states what it does and on what entity
2. **Distinct:** No ambiguity — `lock_sanad` ≠ `mint_sanad` ≠ `consume_seal`
3. **Consistent:** Same name on Ethereum, Solana, Sui, and Aptos
4. **Explorer-friendly:** When you look at a transaction on any chain explorer, you see the same function name
5. **Snake_case:** All chains use snake_case (Solana/Sui/Aptos native, Ethereum adapted)

---

## Canonical Function Names

### Lifecycle Mutations (state-changing)

| Operation | Canonical Name | Parameters | Description |
|---|---|---|---|
| Create seal | `create_seal` | `value: u64` | Create a new seal with associated value |
| Consume seal | `consume_seal` | `seal_id: bytes32` | Mark seal as consumed (single-use) |
| Lock for transfer | `lock_sanad` | `sanad_id, commitment, destination_chain, destination_owner` | Lock sanad for cross-chain transfer |
| Mint on destination | `mint_sanad` | `sanad_id, commitment, state_root, source_chain, source_seal_point, proof, proof_root` | Mint sanad on destination chain after proof verification |
| Refund locked | `refund_sanad` | `sanad_id, destination_owner` | Refund a locked sanad after timeout |
| Transfer ownership | `transfer_sanad` | `sanad_id, new_owner` | Transfer sanad ownership (same chain) |
| Register nullifier | `register_nullifier` | `nullifier, sanad_id, source_chain, source_seal_ref` | Register nullifier for replay protection |
| Anchor commitment | `anchor_commitment` | `commitment, seal_id` | Anchor a commitment to a seal on-chain |
| Record metadata | `record_sanad_metadata` | `sanad_id, asset_class, asset_id, metadata_hash, proof_system, proof_root` | Record metadata for a sanad |

### View Functions (read-only)

| Query | Canonical Name | Returns | Description |
|---|---|---|---|
| Get sanad state | `get_sanad_state` | `SanadStateView` | Full state view for a sanad |
| Get seal state | `get_seal_state` | `SealStateView` | Full state view for a seal |
| Check seal available | `is_seal_available` | `bool` | True if seal exists and is not consumed |
| Check seal consumed | `is_seal_consumed` | `bool` | True if seal has been consumed |
| Check nullifier registered | `is_nullifier_registered` | `bool` | True if nullifier is already registered |
| Check commitment anchored | `is_commitment_anchored` | `bool` | True if commitment is anchored to a seal |
| Check sanad minted | `is_sanad_minted` | `bool` | True if sanad has been minted on this chain |
| Check refund available | `can_refund` | `bool` | True if sanad can be refunded (timeout expired) |

### Governance

| Action | Canonical Name | Description |
|---|---|---|
| Update proof root | `update_proof_root` | Update the trusted proof root (admin only) |
| Transfer ownership | `transfer_ownership` | Transfer contract ownership (admin only) |

---

## Canonical Event Names

| Event | Parameters | Emitted When |
|---|---|---|
| `SanadCreated` | `sanad_id, commitment, owner, timestamp` | Seal is created |
| `SanadConsumed` | `sanad_id, nullifier, consumer, timestamp` | Seal is consumed |
| `SanadLocked` | `sanad_id, commitment, owner, destination_chain, destination_owner, timestamp` | Sanad locked for cross-chain transfer |
| `SanadMinted` | `sanad_id, commitment, owner, source_chain, source_seal_ref, timestamp` | Sanad minted on destination |
| `SanadRefunded` | `sanad_id, commitment, claimant, reason, timestamp` | Sanad refunded after timeout |
| `SanadTransferred` | `sanad_id, from, to, timestamp` | Sanad ownership transferred |
| `NullifierRegistered` | `nullifier, sanad_id, timestamp` | Nullifier registered for replay protection |
| `CommitmentAnchored` | `commitment, seal_id, owner, timestamp` | Commitment anchored to seal |
| `ProofRootUpdated` | `proof_root, updater, timestamp` | Proof root updated by admin |
| `ReplayDetected` | `replay_id, sanad_id, timestamp` | Replay attempt detected |

---

## Canonical State Enum

```
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

All chains MUST use these exact numeric values.

---

## Canonical View Structures

### SanadStateView
```
SanadStateView {
    sanad_id: bytes32,
    seal_id: bytes32,
    commitment: bytes32,
    owner: address (Ethereum) / Pubkey (Solana) / address (Sui/Aptos),
    source_chain: uint8,
    current_chain: uint8,
    destination_chain: uint8,
    state: uint8,  // SanadState enum value
    nullifier: bytes32,
    created_at: uint256,
    updated_at: uint256,
    locked_at: uint256,
    consumed_at: uint256,
    minted_at: uint256,
    refunded_at: uint256,
    last_tx: bytes32,
}
```

### SealStateView
```
SealStateView {
    seal_id: bytes32,
    sanad_id: bytes32,
    commitment: bytes32,
    state: uint8,  // SealState enum
    consumed_at: uint256,
    locked_at: uint256,
}
```

---

## Cross-Chain Mapping (Old → New)

### Ethereum (CSVSeal.sol)
| Old Name | New Name | Notes |
|---|---|---|
| `lockSanad` | `lock_sanad` | snake_case |
| `lockSanadWithMetadata` | `lock_sanad` | merged with metadata param |
| `mintSanad` | `mint_sanad` | snake_case |
| `mintSanadWithMetadata` | `mint_sanad` | merged with metadata param |
| `markSealUsed` | `consume_seal` | semantic match |
| `refundSanad` | `refund_sanad` | snake_case |
| `registerNullifier` | `register_nullifier` | snake_case |
| `anchorCommitment` | `anchor_commitment` | snake_case |
| `isSealUsed` | `is_seal_consumed` | clearer name |
| `isSanadMinted` | `is_sanad_minted` | snake_case |
| `isNullifierRegistered` | `is_nullifier_registered` | snake_case |
| `isCommitmentAnchored` | `is_commitment_anchored` | snake_case |
| (none) | `get_sanad_state` | NEW |
| (none) | `is_seal_available` | NEW |
| (none) | `transfer_sanad` | NEW |
| (none) | `record_sanad_metadata` | NEW |

### Solana
| Old Name | New Name | Notes |
|---|---|---|
| `create_seal` | `create_seal` | ✓ already canonical |
| `consume_seal` | `consume_seal` | ✓ already canonical |
| `lock_sanad` | `lock_sanad` | ✓ already canonical |
| `mint_sanad` | `mint_sanad` | ✓ already canonical |
| `refund_sanad` | `refund_sanad` | ✓ already canonical |
| `register_nullifier` | `register_nullifier` | ✓ already canonical |
| `record_sanad_metadata` | `record_sanad_metadata` | ✓ already canonical |
| `transfer_sanad` | `transfer_sanad` | ✓ already canonical |
| (none) | `get_sanad_state` | NEW |
| (none) | `get_seal_state` | NEW |
| (none) | `is_seal_available` | NEW |
| (none) | `is_seal_consumed` | NEW |
| (none) | `is_nullifier_registered` | NEW |
| (none) | `is_commitment_anchored` | NEW |
| (none) | `is_sanad_minted` | NEW |
| (none) | `can_refund` | NEW |

### Sui
| Old Name | New Name | Notes |
|---|---|---|
| `create_seal` | `create_seal` | ✓ already canonical |
| `consume_seal` | `consume_seal` | ✓ already canonical |
| `lock_sanad` | `lock_sanad` | ✓ already canonical |
| `mint_sanad` | `mint_sanad` | ✓ already canonical |
| (none) | `refund_sanad` | NEW |
| `transfer_seal` | `transfer_sanad` | renamed for consistency |
| `is_seal_available` | `is_seal_available` | ✓ already canonical |
| `is_consumed` | `is_seal_consumed` | renamed for clarity |
| (none) | `get_sanad_state` | NEW |
| (none) | `get_seal_state` | NEW |
| (none) | `is_nullifier_registered` | NEW |
| (none) | `is_commitment_anchored` | NEW |
| (none) | `is_sanad_minted` | NEW |
| (none) | `can_refund` | NEW |
| (none) | `anchor_commitment` | NEW |
| (none) | `record_sanad_metadata` | NEW |

### Aptos
| Old Name | New Name | Notes |
|---|---|---|
| `create_seal` | `create_seal` | ✓ already canonical |
| `consume_seal` | `consume_seal` | ✓ already canonical |
| `lock_sanad` | `lock_sanad` | ✓ already canonical |
| `mint_sanad` | `mint_sanad` | ✓ already canonical |
| (none) | `refund_sanad` | NEW |
| (none) | `transfer_sanad` | NEW |
| `is_seal_available` | `is_seal_available` | ✓ already canonical |
| `is_consumed` | `is_seal_consumed` | renamed for clarity |
| (none) | `get_sanad_state` | NEW |
| (none) | `get_seal_state` | NEW |
| (none) | `is_nullifier_registered` | NEW |
| (none) | `is_commitment_anchored` | NEW |
| (none) | `is_sanad_minted` | NEW |
| (none) | `can_refund` | NEW |
| (none) | `anchor_commitment` | NEW |
| (none) | `record_sanad_metadata` | NEW |

---

## Implementation Rules

1. **All public functions MUST use the canonical names above**
2. **No chain may introduce alternative names for the same operation**
3. **Legacy names may exist as internal aliases during transition, but must emit canonical events**
4. **All chains MUST implement all view functions listed above**
5. **Event names MUST match the canonical event names exactly**
6. **State enum values MUST be identical across all chains**

---

## Naming Constitution Test

```text
No production contract may use a function name outside the canonical list above.
No production contract may emit an event name outside the canonical event list above.
No chain may use a different state enum value for the same lifecycle state.
```
