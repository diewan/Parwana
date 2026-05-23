# Threat Model

## 1. Scope

This document covers the CSV (Cross-chain Sanad Validation) protocol, including:
- Core protocol logic in `csv-core`
- Chain adapters in `csv-bitcoin`, `csv-ethereum`, `csv-solana`, `csv-sui`, `csv-aptos`
- CLI tooling in `csv-cli`
- SDK in `csv-sdk`
- Wallet in `csv-wallet`
- MCP server in `csv-mcp-server`
- Smart contracts in `csv-contracts`

**Out of scope:** Chain-level consensus, external oracle services, user device security.

## 2. Trust Assumptions

| Entity | Trust Level | Assumptions |
|--------|-------------|-------------|
| Source chain validators | Semi-trusted | May collude but cannot forge proofs without majority |
| Destination chain validators | Semi-trusted | Verify proofs before minting |
| RPC providers | Untrusted | May return incorrect data; quorum required |
| Indexers | Untrusted | May be delayed or return stale data |
| Client (CLI/SDK) | Trusted | Runs on user-controlled hardware |
| Wallet | Trusted | Holds user keys; requires passphrase |

## 3. Adversarial Models

### 3.1 Byzantine Nodes

**Threat:** Source or destination chain nodes return invalid data.

**Impact:** Incorrect proof generation, failed transfers, or minting of invalid Sanads.

**Mitigation:**
- RPC quorum client (`csv-core/src/rpc.rs`) requires agreement from multiple providers
- Finality depth checks prevent acting on unconfirmed transactions
- Inclusion proofs are verified against on-chain state roots

### 3.2 Malicious Indexers

**Threat:** Indexers return stale, incorrect, or fabricated data.

**Impact:** Client acts on outdated state, leading to failed transfers or double-spends.

**Mitigation:**
- All indexer data is verified against on-chain state before use
- `csv-core/src/finality.rs` tracks finality state independently
- Reorg detection (`csv-core/src/reorg.rs`) handles chain reorganizations

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
- Timeout handling in `csv-core/src/cross_chain.rs`
- Recovery engine (`csv-core/src/recovery_engine.rs`) handles stuck transfers

### 3.5 Partial Chain Partitions

**Threat:** Network partition prevents communication with some chain nodes.

**Impact:** Transfer cannot complete; funds may be temporarily locked.

**Mitigation:**
- Multiple RPC endpoints per chain
- Timeout-based fallback to alternative providers
- Recovery engine can retry with different providers

## 4. Protocol-Specific Threats

### 4.1 Cross-Chain Double-Spend

**Threat:** Same Sanad transferred to multiple destination chains simultaneously.

**Impact:** Double-spend of Sanad; loss of destination chain integrity.

**Mitigation:**
- Source chain lock consumes the seal, preventing reuse
- Cross-chain registry (`CrossChainRegistry`) tracks all transfers
- Lease system prevents concurrent transfer attempts on same Sanad
- `csv-core/src/lease.rs` enforces exclusive access during transfer window

### 4.2 Replay Attacks

**Threat:** Replaying a valid transfer proof on a different chain or block height.

**Impact:** Unauthorized minting on destination chain.

**Mitigation:**
- Tagged hashing with domain separation (`csv_tagged_hash`)
- Chain-specific hash algorithms (`CrossChainHashAlgorithm`)
- Replay registry (`csv-core/src/replay_registry.rs`) tracks all processed proofs
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
- Canonical CBOR serialization (`csv-core/src/canonical.rs`) prevents encoding ambiguity
- Tagged hashing ensures proof data cannot be substituted
- Merkle proofs are verified against on-chain state roots
- All proof fields are cryptographically bound

### 4.5 Ownership Proof Forgery

**Threat:** Creating a fake ownership proof for a Sanad.

**Impact:** Unauthorized transfer of another user's Sanad.

**Mitigation:**
- Signature verification using chain-specific schemes (Secp256k1, Ed25519)
- Ownership proofs include the signer's public key
- `csv-core/src/signature.rs` validates signature scheme matches chain

### 4.6 Sanad Consumption

**Threat:** Consuming a Sanad's seal without completing the transfer.

**Impact:** Sanad locked on source chain with no destination mint; funds lost.

**Mitigation:**
- Recovery engine (`csv-core/src/recovery_engine.rs`) detects stuck transfers
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
- [x] Recovery engine handles stuck transfers
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

## 11. References

- [Protocol Constitution](./PROTOCOL_CONSTITUTION.md)
- [Protocol Invariants](./PROTOCOL_INVARIANTS.md)
- [Audit Implementation Specification](./audit/implementation.md)
- BIP-340: Tagged Hashing
- NIST SP 800-208: Authenticated Key Exchange
