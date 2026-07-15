# Release and Emergency Runbook

**Owner:** TBD.

`scripts/publish.sh` is dry-run-first. It refuses a dirty checkout, a missing
annotated release tag, unavailable SemVer checks, or a failed locked test suite.
It packages publishable crates in internal dependency order and writes a
checksum/provenance record under `target/release-provenance/`.

Releases may be scoped with `RELEASE_GROUP=core|runtime|adapters|tools`; the
default `workspace` validates every publishable crate. A scoped group preserves
the workspace dependency order and assumes any prerequisite group version has
already been released. Version changes remain per crate; a group is a reviewed
release unit, not a new repository.

## Normal release

1. Choose an annotated tag `vX.Y.Z` on the reviewed release commit.
2. Run `scripts/publish.sh`; review package contents and provenance.
3. Publish only after approval: `CSV_RELEASE_PUBLISH=1 scripts/publish.sh`.
4. Attach the provenance record, golden-corpus version, ABI/IDL checksums, and
   supported N/N-1 matrix to the release.

## Failed publication and rollback

Stop publication at the first failed crate. Do not force-push or rewrite the
tag. Publish a corrected coordinated version instead. If a published crate is
unsafe, yank the affected version with Cargo, publish the fixed coordinated
release, and update the compatibility matrix to reject the unsafe version.

## Embargoed security release

Prepare private fixes and artifacts first. Publish in dependency order: core
and verification, runtime, adapters/bindings, then tools. Announce only after
the dependent safe versions are available. If an old version is unsafe,
consumers must fail closed rather than downgrade.
