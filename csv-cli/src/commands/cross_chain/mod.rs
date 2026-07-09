//! Cross-chain transfer commands (Phase 5 Compliant)
//!
//! This module uses only the csv-sdk runtime API.
//! All chain operations are delegated through `CsvClient::transfers()`.

use anyhow::Result;
use clap::Subcommand;

use csv_hash::ChainId;

use crate::config::{Chain, Config};
use crate::state::UnifiedStateManager;

pub mod status;
pub mod transfer;

#[derive(Debug, Subcommand)]
pub enum CrossChainAction {
    /// Deprecated: a transfer mode must be chosen explicitly. Use `send`
    /// (interactive off-chain) or `materialize` (on-chain thin-registry mint).
    /// This verb always errors so existing scripts fail loudly rather than
    /// changing behavior without an explicit mode choice.
    #[command(hide = true)]
    Transfer {
        /// Ignored — captured only so old invocations reach the guidance error.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
    /// Interactive off-chain transfer: assign the Sanad to an invoice's
    /// recipient-controlled seal, close the source seal, and emit a consignment
    /// for off-band delivery. No destination-chain submission or attestor.
    /// (Lifecycle `resume`/`retry` do not apply — there is no destination phase.)
    Send {
        /// Source chain
        #[arg(long)]
        from: Chain,
        /// Sanad ID to send (hex)
        #[arg(long)]
        sanad_id: String,
        /// Recipient invoice blob (binds the destination seal)
        #[arg(long)]
        invoice: String,
        /// Output consignment file. Defaults to `consignment-<transfer_id>.cbor`.
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// On-chain transfer: materialize the Sanad as an on-chain object via the
    /// thin-registry mint. Has an asynchronous destination-finality phase, so
    /// the `resume`/`retry` lifecycle verbs apply primarily to this mode.
    Materialize {
        /// Source chain
        #[arg(long)]
        from: Chain,
        /// Destination chain
        #[arg(long)]
        to: Chain,
        /// Sanad ID to transfer (hex)
        #[arg(long)]
        sanad_id: String,
        /// Destination owner address (hex)
        #[arg(long)]
        dest_owner: Option<String>,
        /// Destination authenticity proof: `attestor` (RFC §9, available now)
        /// or `zk` (RFC §9.5, not yet available).
        #[arg(long, value_enum, default_value_t = transfer::ProofMode::Attestor)]
        proof: transfer::ProofMode,
        /// Override finality depth for source chain (for testing)
        #[arg(long)]
        finality_depth: Option<u64>,
        /// Poll-and-block: after locking, wait for the source-chain lock to
        /// reach finality and complete the transfer in this invocation. Without
        /// this flag the transfer locks, journals, and returns immediately with
        /// an "awaiting finality" status to be finished later via `resume`.
        #[arg(long)]
        wait: bool,
        /// Poll interval in seconds while `--wait` is set.
        #[arg(long, default_value_t = 60)]
        poll_interval_secs: u64,
        /// Give up waiting after this many seconds while `--wait` is set.
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Recipient: issue an invoice binding a single-use seal the recipient
    /// controls on the destination chain (the interactive-mode entry point).
    Invoice {
        /// Accepted Sanad schema / type (a type label, or a 0x-prefixed hash)
        #[arg(long)]
        schema: String,
        /// Chain-tagged destination seal the recipient controls, as
        /// `<chain>:<field>:<field>` — e.g. `bitcoin:<txid_hex>:<vout>`,
        /// `sui:<object_id_hex>:<version>`,
        /// `aptos:<resource_address_hex>:<key_hex>`, or
        /// `ethereum:<contract_hex>:<slot_hex>`. Verified against the wallet.
        #[arg(long)]
        seal: String,
    },
    /// Recipient: client-side validate a consignment and accept it into the
    /// wallet. No chain transaction (the interactive-mode completion point).
    Accept {
        /// Consignment file to validate and accept
        consignment: String,
    },
    /// Resume a locked transfer that is awaiting finality (no re-lock).
    /// Applies primarily to `materialize`.
    Resume {
        /// Transfer ID returned when the transfer was started
        transfer_id: String,
        /// Poll-and-block from here until the transfer completes.
        #[arg(long)]
        wait: bool,
        /// Poll interval in seconds while `--wait` is set.
        #[arg(long, default_value_t = 60)]
        poll_interval_secs: u64,
        /// Give up waiting after this many seconds while `--wait` is set.
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Check transfer status
    Status {
        /// Transfer ID (hex)
        transfer_id: String,
    },
    /// Query runtime-recorded source escrow settlement status/evidence
    SettlementStatus {
        /// Sanad ID (hex)
        sanad_id: String,
        /// Source chain. Optional when the local display cache has the transfer.
        #[arg(long, value_enum)]
        from: Option<Chain>,
        /// Destination chain. Optional when the local display cache has the transfer.
        #[arg(long, value_enum)]
        to: Option<Chain>,
    },
    /// List all transfers
    List {
        /// Filter by source chain
        #[arg(long, value_enum)]
        from: Option<Chain>,
        /// Filter by destination chain
        #[arg(long, value_enum)]
        to: Option<Chain>,
    },
    /// Retry a failed transfer. Applies primarily to `materialize`.
    Retry {
        /// Transfer ID (hex)
        transfer_id: String,
    },
}

pub async fn execute(
    action: CrossChainAction,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        CrossChainAction::Transfer { .. } => Err(transfer_deprecated_error()),
        CrossChainAction::Send {
            from,
            sanad_id,
            invoice,
            output,
        } => transfer::cmd_send(from, sanad_id, invoice, output, config, state).await,
        CrossChainAction::Materialize {
            from,
            to,
            sanad_id,
            dest_owner,
            proof,
            finality_depth,
            wait,
            poll_interval_secs,
            timeout_secs,
        } => {
            let opts = transfer::WaitOpts::new(wait, poll_interval_secs, timeout_secs);
            transfer::cmd_materialize(
                from,
                to,
                sanad_id,
                dest_owner,
                proof,
                finality_depth,
                opts,
                config,
                state,
            )
            .await
        }
        CrossChainAction::Invoice { schema, seal } => {
            transfer::cmd_invoice(schema, seal, config, state).await
        }
        CrossChainAction::Accept { consignment } => {
            transfer::cmd_accept(consignment, config, state).await
        }
        CrossChainAction::Resume {
            transfer_id,
            wait,
            poll_interval_secs,
            timeout_secs,
        } => {
            let opts = transfer::WaitOpts::new(wait, poll_interval_secs, timeout_secs);
            transfer::cmd_resume(transfer_id, opts, config, state).await
        }
        CrossChainAction::Status { transfer_id } => {
            status::cmd_status(transfer_id, config, state).await
        }
        CrossChainAction::SettlementStatus { sanad_id, from, to } => {
            status::cmd_settlement_status(sanad_id, from, to, config, state).await
        }
        CrossChainAction::List { from, to } => status::cmd_list(from, to, state),
        CrossChainAction::Retry { transfer_id } => status::cmd_retry(transfer_id, config, state),
    }
}

/// Convert CLI Chain enum to protocol ChainId
pub fn to_protocol_chain(chain: Chain) -> ChainId {
    ChainId::new(chain.as_str())
}

/// Error returned by the deprecated `transfer` shim. Names both mode verbs so
/// existing scripts fail loudly (non-zero exit) with actionable guidance rather
/// than changing behavior without an explicit mode choice.
fn transfer_deprecated_error() -> anyhow::Error {
    anyhow::anyhow!(
        "`cross-chain transfer` has been split into two explicit modes; pick one:\n  \
         • `csv cross-chain send`        — interactive off-chain transfer (off-band consignment)\n  \
         • `csv cross-chain materialize` — on-chain transfer via the thin-registry mint\n\
         Pick the verb that matches your intent — neither mode is chosen for you."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    /// Minimal parser wrapper so the `cross-chain` arg surface can be exercised
    /// without constructing the whole `csv` CLI.
    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        action: CrossChainAction,
    }

    fn parse(args: &[&str]) -> Result<CrossChainAction, clap::Error> {
        let argv = std::iter::once("cross-chain").chain(args.iter().copied());
        TestCli::try_parse_from(argv).map(|c| c.action)
    }

    #[test]
    fn send_verb_parses() {
        let action = parse(&[
            "send",
            "--from",
            "bitcoin",
            "--sanad-id",
            "0xab",
            "--invoice",
            "blob",
        ])
        .expect("send should parse");
        assert!(matches!(action, CrossChainAction::Send { .. }));
    }

    #[test]
    fn materialize_verb_parses_with_default_attestor_proof() {
        let action = parse(&[
            "materialize",
            "--from",
            "bitcoin",
            "--to",
            "sui",
            "--sanad-id",
            "0xab",
        ])
        .expect("materialize should parse");
        match action {
            CrossChainAction::Materialize { proof, .. } => {
                assert_eq!(proof, transfer::ProofMode::Attestor);
            }
            other => panic!(
                "expected Materialize, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn materialize_accepts_zk_proof_selection() {
        let action = parse(&[
            "materialize",
            "--from",
            "bitcoin",
            "--to",
            "sui",
            "--sanad-id",
            "0xab",
            "--proof",
            "zk",
        ])
        .expect("materialize --proof zk should parse");
        assert!(matches!(
            action,
            CrossChainAction::Materialize {
                proof: transfer::ProofMode::Zk,
                ..
            }
        ));
    }

    #[test]
    fn invoice_and_accept_verbs_parse() {
        assert!(matches!(
            parse(&["invoice", "--schema", "payment", "--seal", "0xab"]).unwrap(),
            CrossChainAction::Invoice { .. }
        ));
        assert!(matches!(
            parse(&["accept", "consignment.json"]).unwrap(),
            CrossChainAction::Accept { .. }
        ));
    }

    #[test]
    fn bare_transfer_parses_but_yields_deprecation_error() {
        // Old-style invocation still parses (args are captured) …
        let action = parse(&["transfer", "--from", "bitcoin", "--to", "sui"])
            .expect("transfer args are captured by the shim");
        assert!(matches!(action, CrossChainAction::Transfer { .. }));

        // … and the shim points at both mode verbs so scripts fail loudly.
        let err = transfer_deprecated_error().to_string();
        assert!(err.contains("send"), "shim error must name `send`: {err}");
        assert!(
            err.contains("materialize"),
            "shim error must name `materialize`: {err}"
        );
    }

    #[test]
    fn lifecycle_verbs_still_parse() {
        assert!(matches!(
            parse(&["resume", "abc123"]).unwrap(),
            CrossChainAction::Resume { .. }
        ));
        assert!(matches!(
            parse(&["status", "abc123"]).unwrap(),
            CrossChainAction::Status { .. }
        ));
        assert!(matches!(
            parse(&[
                "settlement-status",
                &"11".repeat(32),
                "--from",
                "bitcoin",
                "--to",
                "sui"
            ])
            .unwrap(),
            CrossChainAction::SettlementStatus { .. }
        ));
        assert!(matches!(
            parse(&["list"]).unwrap(),
            CrossChainAction::List { .. }
        ));
        assert!(matches!(
            parse(&["retry", "abc123"]).unwrap(),
            CrossChainAction::Retry { .. }
        ));
    }

    #[test]
    fn help_documents_both_mode_verbs() {
        let mut cmd = TestCli::command();
        let help = cmd.render_long_help().to_string();
        for verb in ["send", "materialize", "invoice", "accept"] {
            assert!(help.contains(verb), "help should document `{verb}`: {help}");
        }
    }

    #[test]
    fn no_mode_flag_exists() {
        // The mode is the verb, never a flag: a `--mode` option must not exist.
        let result = parse(&[
            "materialize",
            "--mode",
            "attestor",
            "--from",
            "bitcoin",
            "--to",
            "sui",
            "--sanad-id",
            "0xab",
        ]);
        let err = match result {
            Ok(_) => panic!("--mode must be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
