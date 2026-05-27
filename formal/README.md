# Formal verification models (audit item 12)

TLA+ and Alloy specifications for protocol invariants. Production-ready models
with comprehensive invariants and theorem verification.

## Files

- `ReplaySafety.tla` — replay registry CAS and no double-consume (production-ready)
- `Ownership.tla` — sanad ownership transfer legality (production-ready)
- `alloy/ReplaySafety.als` — Alloy model for replay safety (production-ready)

## Running

```bash
# TLA+ (requires tla2tools.jar)
java -cp tla2tools.jar tlc2.TLC -deadlock -config formal/ReplaySafety.cfg formal/ReplaySafety.tla
java -cp tla2tools.jar tlc2.TLC -config formal/Ownership.cfg formal/Ownership.tla

# Alloy (requires the Alloy CLI distribution)
java -jar alloy.jar exec -q -f -o /tmp/csv-alloy-replay -c '*' formal/alloy/ReplaySafety.als
```

## Verification

All models include comprehensive invariants and theorem verification:

- Type correctness
- CAS semantics
- No double consume
- State monotonicity
- Set consistency invariants
