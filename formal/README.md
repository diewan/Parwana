# Formal verification models (audit item 12)

TLA+ and Alloy specifications for protocol invariants. Production-ready models
with comprehensive invariants and theorem verification.

## Files

- `ReplaySafety.tla` — replay registry CAS and no double-consume (production-ready)
- `Ownership.tla` — sanad ownership transfer legality (production-ready)
- `alloy/ReplaySafety.als` — Alloy model for replay safety (production-ready)

## Running

```bash
# TLA+ (requires TLC in PATH)
cd formal && tlc ReplaySafety.tla

# Alloy (requires Alloy Analyzer)
alloy4 alloy/ReplaySafety.als
```

## Verification

All models include comprehensive invariants and theorem verification:

- Type correctness
- CAS semantics
- No double consume
- State monotonicity
- Set consistency invariants
