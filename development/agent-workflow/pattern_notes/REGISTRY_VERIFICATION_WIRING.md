# Pattern Note: Registry Verification Wiring

> **Drift warning (verified 2026-07-09).** Two parts of this note no longer match
> the tree:
>
> - The "Fix Placeholder Commitments" example below shows a `ProofLeafV1`
>   construction in `csv-adapters/csv-ethereum/src/runtime_adapter.rs`.
>   `ProofLeafV1` no longer appears anywhere in the Ethereum adapter — the
>   proof-root mint was removed by the thin-registry rewrite (`TRM-ETH-*`). The
>   *principle* (bind commitments to real on-chain transaction data, never to
>   `sanad_id`) still holds; the code excerpt is historical.
> - The "Repository-Wide Application" checklist is still unresolved.
>   `verify_seal_registry` exists **only** in `csv-ethereum`
>   (`seal_protocol.rs`, `verifier.rs`). Bitcoin, Solana, Sui, Aptos, and
>   Celestia have no such function.

## Context

This pattern note documents the security-critical pattern for wiring on-chain seal registry verification into production paths for chain adapters.

## Problem

Chain adapters were implementing seal consumption checks using only local registry state, bypassing authoritative on-chain verification. This created a security vulnerability where:

- Local state corruption could allow replay attacks
- Concurrent processes on different machines could bypass single-use guarantees
- Placeholder commitments (e.g., using `sanad_id` instead of actual transaction data) weakened proof binding

## Solution Pattern

### 1. Implement Authoritative On-Chain Verification

**Location:** Adapter-specific verifier module (e.g., `csv-adapters/csv-ethereum/src/verifier.rs`)

```rust
#[cfg(feature = "rpc")]
pub async fn verify_seal_registry(
    &self,
    seal_id: Hash,
) -> Result<VerificationResult, Box<dyn std::error::Error>> {
    // Construct contract call to isSealUsed or equivalent
    let call = Contract::is_seal_used_call { sealId: seal_id_fixed };
    let call_data = call.abi_encode();
    
    // Execute eth_call on-chain
    let result = self.rpc.eth_call(call_params, "latest").await?;
    
    // Parse boolean response (32 bytes, last byte = 0x00 for false, 0x01 for true)
    let is_used = result[31] == 1;
    
    Ok(VerificationResult {
        valid: !is_used,
        assurance: VerificationAssurance::Cryptographic,
        verified_components: VerifiedComponents {
            replay_checked: true,
            // ...
        },
        error: if is_used { Some(VerificationFailure::ReplayDetected) } else { None },
    })
}

#[cfg(not(feature = "rpc"))]
pub async fn verify_seal_registry(
    &self,
    _seal_id: Hash,
) -> Result<VerificationResult, Box<dyn std::error::Error>> {
    // Fail closed: security-critical checks must not be silently bypassed
    Err(Box::new(EthereumError::RpcError(
        "On-chain seal registry verification requires RPC feature".to_string()
    )))
}
```

**Key Principles:**

- Use feature gates to separate RPC-dependent code
- Fail closed when verification is unavailable
- Return typed errors (VerificationFailure::ReplayDetected) not strings
- Use proper cryptographic assurance level

### 2. Wire Verification into Production Path

**Location:** SealProtocol implementation (e.g., `csv-adapters/csv-ethereum/src/seal_protocol.rs`)

```rust
async fn enforce_seal(
    &self,
    seal: Self::SealPoint,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    // Step 1: Check local registry (fast path)
    let registry = self.seal_registry.lock().map_err(...)?;
    if registry.is_seal_used(&seal) {
        return Err(Box::new(ProtocolError::SealReplay(...)));
    }
    drop(registry);

    // Step 2: Check on-chain state (authoritative check)
    #[cfg(feature = "rpc")]
    {
        let verification_result = self.verifier.verify_seal_registry(seal_id).await?;
        if !verification_result.valid {
            return Err(Box::new(ProtocolError::SealReplay(
                verification_result.error.unwrap_or_else(|| "Seal already consumed".to_string())
            )));
        }
    }

    #[cfg(not(feature = "rpc"))]
    {
        // Fail closed: security-critical checks must not be silently bypassed
        return Err(Box::new(ProtocolError::NetworkError(
            "On-chain seal registry verification requires RPC feature".to_string()
        )));
    }

    // Step 3: Mark seal as used in local registry (after on-chain check)
    let registry = self.seal_registry.lock().map_err(...)?;
    registry.mark_seal_used(&seal)?;
    
    Ok(())
}
```

**Key Principles:**

- Check local registry first (fast path)
- Always perform on-chain verification when RPC available
- Fail closed when RPC unavailable
- Update local state AFTER on-chain verification (prevents race conditions)

### 3. Fix Placeholder Commitments

**Location:** Runtime adapter (e.g., `csv-adapters/csv-ethereum/src/runtime_adapter.rs`)

**Before (INCORRECT):**

```rust
let proof_leaf = ProofLeafV1::new(
    transfer.source_chain.clone(),
    transfer.destination_chain.clone(),
    transfer.sanad_id,
    transfer.sanad_id, // ❌ Placeholder: using sanad_id as commitment
);
```

**After (CORRECT):**

```rust
// The commitment is the lock transaction hash, which was actually published to the chain
let commitment = lock_tx_hash;

let proof_leaf = ProofLeafV1::new(
    transfer.source_chain.clone(),
    transfer.destination_chain.clone(),
    transfer.sanad_id,
    commitment, // ✅ Actual commitment from on-chain transaction
);
```

**Key Principles:**

- Commitments must bind to actual on-chain transaction data
- Use transaction hash or derived commitment from lock result
- Never use placeholder values like sanad_id

### 4. Add Negative Tests

**Location:** SealProtocol tests

```rust
#[cfg(not(feature = "rpc"))]
#[tokio::test]
async fn test_enforce_seal_fails_closed_without_rpc() {
    let adapter = test_adapter();
    let seal = adapter.create_seal(None).await.unwrap();
    
    // Without RPC feature, enforce_seal should fail closed
    let result = adapter.enforce_seal(seal).await;
    assert!(result.is_err());
    
    let error_msg = format!("{:?}", result.unwrap_err());
    assert!(error_msg.contains("NetworkError") || error_msg.contains("RPC"));
}

#[cfg(feature = "rpc")]
#[tokio::test]
async fn test_enforce_seal_on_chain_consumed() {
    // Mock RPC to return that seal is consumed
    // Verify that error is returned
}
```

**Key Principles:**

- Test fail-closed behavior without RPC
- Test on-chain verification path with RPC
- Verify proper error types and messages

## Security Invariants

1. **No bypass paths:** All production paths must call on-chain verification
2. **Fail closed:** If verification is unavailable, return error instead of silently skipping
3. **Typed errors:** Use VerificationFailure enum, not String
4. **Proper commitments:** Bind to actual transaction data, not placeholders
5. **Authoritative source:** On-chain state is authoritative, local state is cache

## Anti-Patterns to Avoid

❌ **Skipping verification with TODO comments:**

```rust
// TODO: Implement verify_seal_registry
// For now, skip on-chain verification
let _ = seal_id;
```

❌ **Silent fallback to local state:**

```rust
#[cfg(not(feature = "rpc"))]
{
    // Without RPC, rely on local registry only
    let _ = seal_id;
}
```

❌ **Placeholder commitments:**

```rust
transfer.sanad_id, // Use sanad_id as commitment for now
```

❌ **Ok(true) in verification paths:**

```rust
Ok(VerificationResult {
    valid: true,
    // ... without actual verification
})
```

## Repository-Wide Application

This pattern should be applied to all chain adapters that have seal registry verification:

Status re-verified 2026-07-09 by grepping for `verify_seal_registry`:

- ✅ Ethereum: Completed (A-ETH-REGISTRY-001) — `seal_protocol.rs`, `verifier.rs`
- ❌ Bitcoin: not implemented
- ❌ Solana: not implemented (no reference implementation exists, contrary to the
  earlier note)
- ❌ Sui: not implemented
- ❌ Aptos: not implemented
- ❌ Celestia: not implemented

## Verification Commands

```bash
# Check compilation
cargo check -p <adapter>

# Run tests
cargo test -p <adapter>

# Search for anti-patterns
grep -r "TODO.*verify.*seal" csv-adapters/
grep -r "skip.*on-chain" csv-adapters/
grep -r "sanad_id.*commitment.*for now" csv-adapters/
```

## References

- Ticket: A-ETH-REGISTRY-001
- Agent rules: csv-adapters/.agents/AGENT.md
- Protocol invariants: csv-docs/PROTOCOL_INVARIANTS.md
- Threat model: csv-docs/THREAT_MODEL.md
