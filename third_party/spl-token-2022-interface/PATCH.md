# spl-token-2022-interface 2.1.0 (patched)

Vendored from crates.io 2.1.0 with explicit `PodU64` / `u64` conversions in
`src/extension/transfer_fee/mod.rs` to resolve `E0283` (ambiguous `Into` with
`solana_zero_copy`).

Remove this patch when `solana-account-decoder` pulls a fixed release.
