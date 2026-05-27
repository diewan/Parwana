# csv-core — RETIRED

**Status:** Deleted from workspace. Migration complete.

**Removed:** This crate was a legacy protocol types container that has been fully migrated to the new architecture.

**Migration path:**
- Protocol types → `csv-protocol/src/`
- Hash types → `csv-hash/`
- Proof types → `csv-proof/`
- Verification → `csv-verifier/`
- Storage traits → `csv-storage/`
- Coordinator → `csv-coordinator/`
- Admission control → `csv-admission/`
- Algebra/typestate → `csv-algebra/`
- Wire/transport → `csv-wire/`
- Codec → `csv-codec/`
- Content → `csv-content/`
- Schema → `csv-schema/`

**Architecture enforcement:**
- `deny.toml` contains forbidden-edge rules preventing csv-runtime, csv-sdk, csv-cli from depending on csv-core
- `csv-architecture/tests/architecture_guard.rs` contains `no_csv_core_imports_in_workspace()` and `nothing_new_depends_on_csv_core()` tests
- All workspace members have been migrated away from csv-core

**See also:**
- `development/csv_core_elimination.md` — Migration plan
- `development/csv_migration_plan.md` — Full migration roadmap
- `UNWIRED.md` — Remaining architecture tasks
