# CSV Protocol Feature Freeze Policy

**Effective:** 2025-01-18
**Status:** ACTIVE
**Purpose:** Prevent semantic drift during Phase 0-Phase 1 restructuring

---

## Context

Per implementation.md Phase 0, the CSV protocol is in a **HARD FREEZE** state to enable critical architectural restructuring without introducing new features or protocol changes. This freeze is a prerequisite for Phase 1 repository restructuring and production approval.

---

## Allowed Changes

The following types of changes are **ALLOWED** during the freeze:

### 1. Refactors
- Code reorganization within existing crates
- Internal API improvements that do not change protocol semantics
- Dependency updates (non-breaking)
- Performance optimizations that do not change behavior

### 2. Invariant Fixes
- Fixes to protocol invariants that are clearly broken
- Corrections to state machine logic
- Replay protection bug fixes
- Finality logic corrections

### 3. Serialization Fixes
- Canonical serialization bug fixes
- CBOR encoding/decoding corrections
- Domain separation fixes
- Hash computation corrections

### 4. Proof Fixes
- Proof validation logic corrections
- Proof pipeline order fixes
- Verification error handling improvements
- Proof size limit enforcement

### 5. Testing
- New tests for existing functionality
- Test coverage improvements
- Golden test additions
- Property test additions
- Compile-fail test additions

### 6. Contracts Stabilization
- Smart contract bug fixes
- Contract ABI stabilization
- Event definition corrections
- Deployment script improvements

---

## Forbidden Changes

The following types of changes are **FORBIDDEN** during the freeze:

### 1. New Features
- New protocol types or structures
- New proof types
- New chain adapters
- New cryptographic primitives
- New sanad types
- New transfer modes

### 2. Protocol Semantics
- Changes to state machine transitions
- Changes to finality thresholds
- Changes to replay protection logic
- Changes to verification pipeline order
- Changes to domain separation strings

### 3. API Surface
- New public APIs in csv-core
- New SDK methods
- New CLI commands
- New wallet features

### 4. Contract Changes
- New smart contracts
- Contract upgrades that change semantics
- New event types
- New function signatures

---

## Enforcement

### PR Review Checklist

All PRs must pass the following checklist:

- [ ] Change type is in the "Allowed Changes" list above
- [ ] No new protocol types or structures
- [ ] No changes to protocol semantics
- [ ] No new public APIs
- [ ] All existing tests pass
- [ ] New tests added if applicable
- [ ] Documentation updated if applicable

### CI Checks

The following CI checks should be added:

1. **Feature Freeze Check**: Automated check to detect new protocol types
2. **Semantic Change Detection**: Check for changes to critical protocol files
3. **Test Coverage Gate**: Ensure test coverage does not decrease

---

## Exceptions

Exceptions to this freeze require:

1. Approval from protocol maintainers
2. Documented rationale in an RFC
3. Security review if the change affects cryptographic paths
4. Explicit sign-off in the PR description

---

## Duration

This freeze remains in effect until:

- Phase 1 repository restructuring is complete
- All critical error handling violations are fixed
- Verification report shows approval status
- Protocol maintainers explicitly lift the freeze

---

## References

- implementation.md Phase 0 — Hard Freeze & Protocol Lockdown
- VERIFICATION_REPORT.md — Current status and action items
- Implementation-2.md — Strict architectural rules

---

## Questions

Contact protocol maintainers for clarification on whether a specific change is allowed during the freeze.
