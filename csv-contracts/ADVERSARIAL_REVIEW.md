# Contract Adversarial Review

Living adversarial-review record for every destination contract under `csv-contracts/`.
Each `security_critical` contract ticket (TRM-*-CTR-001) MUST land a completed review section
here before merge. The shared threat model and the six-step mint pattern are defined in
[csv-docs/contracts/REGISTRY_VERIFICATION_WIRING.md](../csv-docs/contracts/REGISTRY_VERIFICATION_WIRING.md);
the frozen digest byte layouts are in
[csv-docs/contracts/ABI_CONSTITUTION.md](../csv-docs/contracts/ABI_CONSTITUTION.md).

## Status

| Chain | Contract | Mint model | Review | Ticket |
|-------|----------|-----------|--------|--------|
| Ethereum | `csv-contracts/ethereum/contracts/src/CSVSeal.sol` | verifier-attested thin registry (RFC-0012 §9) | ✅ complete (below) | TRM-ETH-CTR-001 |
| Solana | `csv-contracts/solana/contracts/programs/csv-seal/` | ⚠️ legacy proof-root (rewrite pending) | ⛔ pending | TRM-SOL-CTR-001 |
| Sui | `csv-contracts/sui/sources/csv_seal.move` | ⚠️ legacy proof-root (rewrite pending) | ⛔ pending | TRM-SUI-CTR-001 |
| Aptos | `csv-contracts/aptos/contracts/sources/csv_seal.move` | ⚠️ legacy proof-root (rewrite pending) | ⛔ pending | TRM-APT-CTR-001 |

The legacy proof-root mint path is inoperable under RFC-0012 / ABI_CONSTITUTION and is a
rewrite target on each non-ETH chain, not a reference. Do NOT treat the pending rows as
reviewed. Each becomes ✅ only when its contract adopts the attested thin-registry pattern and
adds a review section below with a passing adversarial suite.

## Shared threat model (all chains)

The destination contract is a **thin registry**: cross-chain validity is decided off-chain by
the CSV verifier; the contract records a verified result and enforces local replay protection.
The authenticity boundary is a set of `M`-of-`N` verifier signatures over the frozen §9.2
attestation digest (SHA-256 preimage, secp256k1). Every chain's mint must resist:

- **T1 Forged attestation** — a signature from a key not in the verifier set.
- **T2 Wrong-payload signature** — a valid verifier signature over different mint fields.
- **T3 Insufficient signatures** — fewer than `threshold` distinct valid signers (incl. the
  empty vector).
- **T4 Signature malleability / duplicate-signer double count** — reusing one verifier's
  signature to fake distinct signers, or malleated encodings of the same signature.
- **T5 Cross-chain / cross-deploy replay** — a valid attestation for one chain or one
  deployment replayed against another.
- **T6 Expired attestation** — a signature past its `attestationExpiry` bound.
- **T7 Replay via uniqueness keys** — re-minting a `sanadId`, or reusing a `nullifier` or
  `lockEventId`; and minting with zero replay keys to bypass those checks.
- **T8 Griefing pre-registration** — squatting a `nullifier`/`lockEventId`/`sanadId` slot to
  block a legitimate future mint (permissionless `register_nullifier` was the vector).
- **T9 Permissionless / caller-authority confusion** — treating `msg.sender` as authority
  instead of the payload signatures.

### Residual (accepted) risk — all chains

This is a trusted-attestor model (RFC-0012 §9.4 / Model C). A compromised verifier set **can**
forge an on-chain mint *record* and wrongly trigger escrow settlement (bounded by §10). It
**cannot** forge a `ProofBundle` that a recipient's client-side validation accepts — that
requires the real single-use seal consumed on the finalized source chain. On-chain ownership
legibility degrades under compromise; the client-side ownership guarantee does not. `M`-of-`N`
reduces single-key risk; digest chain/contract binding and `attestationExpiry` bound replay.
Full removal of the trusted attestor is the ZK-prover seam (RFC-0012 §9.5), out of scope here.

---

## Ethereum — `CSVSeal.sol` (TRM-ETH-CTR-001) ✅

Reviewed at the thin-registry rewrite. Verify commands: `forge build`, `forge test`
(34 tests passing across the three suites below).

Suites:
- `test/Adversarial.t.sol` → `AdversarialMintTest` — mint authenticity (16 tests)
- `test/adversarial.t.sol` → `LifecycleAdversarialTest` — seal/lock/refund lifecycle (10 tests)
- `test/naming_constitution.t.sol` → `NamingConstitutionTest` — canonical events (8 tests)

### What could still fail → what prevents it

| # | Attack / failure mode | Mitigation in `CSVSeal.sol` | Test |
|---|-----------------------|-----------------------------|------|
| T1 | Forged attestation (non-verifier signer) | `_require_verifier_threshold` rejects any signature not recovering to a set member; `ecrecover→address(0)` is never a member | `testForgedAttestationRejected` |
| T2 | Valid signature over a different payload | Digest is recomputed on-chain from call args in `mint_attestation_digest`; a sig over other fields recovers a mismatched signer → reject | `testWrongPayloadSignatureRejected` |
| T3 | Insufficient / empty signatures | `threshold ≥ 1` always (constructor sets 1; `execute_verifier_update` rejects `0` or `> set size`); `sigs.length < M` and `distinct < M` both revert | `testNoSignaturesRejected`, `testDuplicateSignatureDoesNotReachThreshold` |
| T4 | Malleability / duplicate-signer double count | Dedupe by recovered address; EIP-2 low-`s` + canonical `v∈{27,28}`; wrong-length sig rejected | `testDuplicateSignatureDoesNotReachThreshold`, `testMalformedSignatureRejected` |
| T5 | Cross-deploy / cross-chain replay | Digest binds `destinationChainId = CHAIN_ETHEREUM` and `destinationContract = address(this)` (left-padded) | `testCrossDeployReplayRejected` |
| T6 | Expired attestation | `attestationExpiry != 0 && now > attestationExpiry` reverts `AttestationExpired`; expiry is in the digest | `testExpiredAttestationRejected`, `testFutureExpiryMints` |
| T7 | Duplicate/zeroed uniqueness keys | Hard rejects on `mintedSanads`/`nullifiers`/`usedLockEvents`; zero `sanadId`/`commitment`/`sourceChain`/`lockEventId`/`nullifier` rejected as `InvalidMintRequest` | `testDuplicateSanadRejected`, `testDuplicateNullifierRejected`, `testDuplicateLockEventRejected`, `testZeroKeysRejected` |
| T8 | Griefing nullifier pre-registration | `register_nullifier` gated to verifier/owner; authenticated mint folds nullifier registration in | `testRegisterNullifierGated`, `testVerifierCanRegisterNullifier` |
| T9 | Caller-authority confusion | No `msg.sender` allowlist on mint; any operator submits, authority is the payload signatures (gas-payer ≠ authority) | `testFreshDeployHappyMint` (pranked non-verifier sender) |
| — | Fresh-deploy liveness (the original bug) | No proof-root install required; a valid attestation mints immediately | `testFreshDeployHappyMint`, `testSanadMintedEmitsFullOwnerBytes` |
| — | Lifecycle: double consume/lock, nullifier reuse, unauthorized consume, timelocked ownership/verifier rotation | Owner/seal-owner checks, `usedSeals`, timelocks | `LifecycleAdversarialTest` (all 10) |

### Notes / follow-ups (Ethereum)

- Verifier-set rotation and threshold changes are owner/timelocked and **off** the mint hot
  path — they are never evaluated inside `mint_sanad`. The set can never be emptied below a
  satisfiable threshold (`execute_verifier_update` rejects `newThreshold == 0` or `> length`).
- `_require_verifier_threshold` is O(sigs²) via the dedupe inner loop; the array is
  operator-supplied and operator-paid, and any non-verifier entry reverts, so this is
  operator self-harm only, bounded by the block gas limit. Not exploitable against others.
- Non-authoritative `hashProofLeafV1` / merkle helpers are retained for future SPV and MUST
  NOT gate mint until the `bytes32`(contract) vs `u8`(Rust MCE) chain-identity mismatch is
  reconciled (RFC-0012 §5).
- `PINNED_ABI_HASH` / `PINNED_BYTECODE_HASH` were removed; re-pin at freeze (TRM-ETH-DEPLOY-001).

---

## Solana — `csv-seal` program (TRM-SOL-CTR-001) ⛔ pending

Contract still on the legacy proof-root model. Review to be completed at the thin-registry
rewrite. Must satisfy T1–T9 using `secp256k1_recover`, with the verifier stored as the
compressed 33-byte public key and `destinationContract` pinned to the program's native
32-byte identity (see the pattern note). Expected suite: `programs/csv-seal/tests/` +
existing adversarial tests, adapted to attested mint.

## Sui — `csv_seal.move` (TRM-SUI-CTR-001) ⛔ pending

Legacy proof-root model. Must satisfy T1–T9 using `ecdsa_k1::secp256k1_verify` (compressed
33-byte key; pin `destinationContract` form before ABI freeze). Adapt
`sources/test_adversarial.move`.

## Aptos — `csv_seal.move` (TRM-APT-CTR-001) ⛔ pending

Legacy proof-root model. Must satisfy T1–T9 using the `secp256k1` stdlib (compressed 33-byte
key; pin `destinationContract` form before ABI freeze). Adapt `contracts/test_adversarial.move`.
