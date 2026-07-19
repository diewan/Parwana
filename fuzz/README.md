# Accountability verifier fuzzing

`accountability_verify` mutates the released first-slice fixture, verifier
statuses, evidence ordering, and bounded evidence-node counts. Inputs larger
than 64 KiB are rejected before parsing, while protocol node/depth/fanout and
bundle byte limits remain enforced by `csv-accountability`.

Run the checked-in corpus for a bounded CI smoke test:

```bash
cargo +nightly fuzz run accountability_verify fuzz/corpus/accountability_verify \
  -- -max_total_time=60 -max_len=65536
```

The target must not panic, perform I/O, or derive an unbounded allocation from
input bytes.
