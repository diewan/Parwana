# RFC-0010: RPC Quorum Engine and Distributed Consistency

**Status:** Proposed
**Author:** Parwana Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC formalizes the RPC quorum engine for distributed data consistency and establishes a consistency constitution for multi-provider RPC queries.

## Motivation

The current RPC implementation has a basic quorum engine but lacks:

1. **Formal quorum protocol** — No documented quorum algorithm
2. **Provider health tracking** — No mechanism to detect and exclude unhealthy providers
3. **Consistency constitution** — No formal rules for data consistency across providers
4. **Adversarial testing** — No framework for testing quorum behavior under attack

## Design

### 1. Quorum Protocol

```rust
pub struct QuorumConfig {
    pub min_providers: usize,
    pub agreement_threshold: Fraction,  // e.g., 2/3
    pub timeout_ms: u64,
    pub max_retries: usize,
}

pub struct QuorumResult<T> {
    pub value: T,
    pub provider_count: usize,
    pub agreement_count: usize,
    pub disagreement_count: usize,
    pub providers: Vec<ProviderResponse<T>>,
}

pub struct ProviderResponse<T> {
    pub provider_id: String,
    pub result: Result<T, RpcError>,
    pub latency_ms: u64,
}
```

### 2. Provider Health Tracking

```rust
pub struct ProviderHealth {
    pub provider_id: String,
    pub success_rate: f64,
    pub avg_latency_ms: f64,
    pub last_seen: u64,
    pub consecutive_failures: usize,
    pub health_score: f64,  // 0.0 to 1.0
}

impl ProviderHealth {
    pub fn is_healthy(&self) -> bool {
        self.health_score > 0.5 && self.consecutive_failures < 3
    }
}
```

### 3. Consistency Constitution

The consistency constitution defines rules for data consistency:

**Rule 1 — Quorum Agreement:** Data is accepted only when ≥2/3 of providers agree.

**Rule 2 — Timeout Handling:** Providers that exceed timeout are excluded from quorum calculation.

**Rule 3 — Provider Rotation:** Providers are rotated periodically to prevent Sybil attacks.

**Rule 4 — Disagreement Logging:** All disagreements are logged with full response data.

**Rule 5 — Fallback Providers:** When quorum cannot be reached, fallback providers are queried.

### 4. Adversarial Test Framework

```rust
#[cfg(test)]
mod adversarial_tests {
    #[test]
    fn test_quorum_with_byzantine_providers() {
        // Simulate 1/3 byzantine providers returning wrong data
        // Verify quorum correctly rejects the wrong data
    }
    
    #[test]
    fn test_quorum_with_slow_providers() {
        // Simulate 1/3 slow providers
        // Verify quorum completes with fast providers
    }
    
    #[test]
    fn test_quorum_with_colluding_providers() {
        // Simulate 2/3 colluding providers
        // Verify quorum requires 3rd provider agreement
    }
}
```

## Implementation

### Changes to `csv-core/src/rpc/quorum_engine.rs`

- Formalize quorum protocol
- Add provider health tracking
- Add consistency constitution enforcement
- Add adversarial test framework

### New Module: `csv-core/src/rpc/provider_health.rs`

- `ProviderHealth` type
- Health score computation
- Provider exclusion logic

### New Module: `csv-core/src/rpc/consistency_constitution.rs`

- Consistency constitution rules
- Rule enforcement
- Violation reporting

## Security Impact

- **Byzantine fault tolerance** — Quorum correctly handles up to 1/3 byzantine providers
- **Provider accountability** — Health tracking enables automatic provider rotation
- **Consistency guarantees** — Constitution rules ensure data consistency

## References

- Protocol Invariants — RPC Trust Model
- `csv-core/src/rpc/quorum_engine.rs` — Current quorum implementation
- `csv-docs/THREAT_MODEL.md` — RPC-related threats
