//! Runtime subcommand — monitoring and diagnostics for the CSV runtime engine

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use clap::Subcommand;
use colored::Colorize;
use csv_admission::AdmissionController;
use csv_observability::runtime_health::{DegradedReason, RuntimeHealth};
use csv_runtime::adapter_registry::AdapterRegistryImpl;
use csv_runtime::{CircuitBreakerState, HealthMonitor, RuntimeMode};
use csv_sdk::CsvClient;
use csv_sdk::contract;

use crate::commands::cross_chain::to_protocol_chain;
use crate::config::{Chain, Config, parse_chain};
use crate::contract_view;
use crate::output;
use crate::state::UnifiedStateManager;
use crate::wallet_identity::WalletIdentity;

#[derive(Subcommand)]
pub enum RuntimeAction {
    /// Show runtime health status and operational mode
    Status,
    /// Show per-component health checks
    Health,
    /// Show admission control pressure and limits
    Admission,
    /// List recent runtime events
    Events {
        /// Number of events to show
        #[arg(short, long, default_value = "20")]
        count: usize,
    },
    /// Serve chain actions to remote clients (WASM-REMOTE-001).
    ///
    /// Runs this native daemon as the chain-execution host for browser / thin
    /// clients: it decodes remote-dispatch envelopes and forwards each call to
    /// its local adapter registry. Client-side validation, proof verification,
    /// and finality checks stay in the remote coordinator — this host is a dumb
    /// port-forwarder over its registry.
    Serve {
        /// Address to bind the host endpoint to.
        #[arg(long, default_value = "127.0.0.1:8645")]
        bind: String,
        /// Bearer token clients must present. Falls back to the
        /// `CSV_REMOTE_HOST_TOKEN` environment variable. The host is
        /// user-owned, not a public service, so run it authenticated (bearer
        /// token, or terminate mTLS in front).
        #[arg(long)]
        token: Option<String>,
        /// Comma-separated chains to serve (default: bitcoin,ethereum,sui,aptos,solana).
        #[arg(long)]
        chains: Option<String>,
    },
}

pub async fn execute(
    action: RuntimeAction,
    config: &Config,
    state: Option<&UnifiedStateManager>,
) -> Result<()> {
    match action {
        RuntimeAction::Status => cmd_status(),
        RuntimeAction::Health => cmd_health(),
        RuntimeAction::Admission => cmd_admission(),
        RuntimeAction::Events { count } => cmd_events(count),
        RuntimeAction::Serve {
            bind,
            token,
            chains,
        } => {
            let state = state.ok_or_else(|| {
                anyhow::anyhow!("`runtime serve` requires wallet state to build chain adapters")
            })?;
            cmd_serve(config, state, bind, token, chains).await
        }
    }
}

/// Shared axum state for the remote-dispatch host endpoint.
#[derive(Clone)]
struct ServeState {
    registry: Arc<AdapterRegistryImpl>,
    /// Expected bearer token. `None` disables auth (mTLS / private socket only).
    token: Option<Arc<String>>,
}

/// The single POST handler: authenticate, then port-forward the envelope to the
/// local registry via the shared dispatch logic in `csv-remote`.
async fn dispatch_handler(
    State(serve_state): State<ServeState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(expected) = &serve_state.token {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if presented != Some(expected.as_str()) {
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }

    // The dispatch logic (and every `.mint_sanad` / `.lock_sanad` call) lives in
    // csv-remote's host module, not here: the CLI holds no protocol authority.
    let response = csv_sdk::csv_remote::host::dispatch_bytes(serve_state.registry.as_ref(), &body)
        .await;
    ([(header::CONTENT_TYPE, "application/cbor")], response).into_response()
}

fn resolve_chains(chains: Option<String>) -> Result<Vec<Chain>> {
    let names = chains.unwrap_or_else(|| "bitcoin,ethereum,sui,aptos,solana".to_string());
    let mut out = Vec::new();
    for name in names.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        out.push(parse_chain(name)?);
    }
    if out.is_empty() {
        return Err(anyhow::anyhow!("no chains to serve"));
    }
    Ok(out)
}

/// Build a native client with concrete adapters registered for `chains`, so its
/// registry can be served to remote clients.
async fn build_host_client(
    config: &Config,
    state: &UnifiedStateManager,
    chains: &[Chain],
) -> Result<CsvClient> {
    let mut sdk_config = csv_sdk::config::Config::default();
    sdk_config.data_dir = Some(config.data_dir.clone());
    let identity = WalletIdentity::from_state(state)?;
    let mut builder = CsvClient::builder();
    let mut key_specs: Vec<(&Chain, u32, u32)> = Vec::new();

    for chain in chains {
        let chain_config = config
            .chain(chain)
            .map_err(|e| anyhow::anyhow!("chain {} not configured: {e}", chain.as_str()))?;
        let is_btc = chain.as_str() == "bitcoin";

        let utxos = if is_btc {
            state
                .storage
                .wallet
                .utxos
                .iter()
                .map(|u| csv_sdk::config::UtxoConfig {
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value: u.value,
                    account: u.account,
                    index: u.index,
                    script_pubkey: u.script_pubkey.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };

        let sanad_seals = if is_btc {
            state
                .storage
                .wallet
                .sanad_seals
                .iter()
                .map(|s| csv_sdk::config::SanadSealConfig {
                    sanad_id: s.sanad_id.clone(),
                    anchor_txid: s.anchor_txid.clone(),
                    vout: s.vout,
                    commitment: state
                        .storage
                        .sanads
                        .iter()
                        .find(|r| r.id == s.sanad_id)
                        .map(|r| r.commitment.clone()),
                })
                .collect()
        } else {
            Vec::new()
        };

        let chain_cfg = csv_sdk::config::ChainConfig {
            rpc: crate::config::sdk_rpc_config(chain.as_str(), chain_config),
            finality_depth: chain_config.finality_depth as u32,
            enabled: true,
            xpub: None,
            seed: is_btc.then(|| identity.bitcoin_seed_hex()),
            contract_address: chain_config.contract_address.clone(),
            program_id: chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos,
            sanad_seals,
        };
        sdk_config.chains.insert(chain.to_string(), chain_cfg);
        builder = builder.with_chain(to_protocol_chain(chain.clone()));
        key_specs.push((chain, 0, 0));
    }

    let private_keys = identity.signing_map(&key_specs, state)?;

    builder
        .with_config(sdk_config)
        .with_private_keys(private_keys)
        .with_runtime_coordinator()
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to build host client: {e}"))
}

async fn cmd_serve(
    config: &Config,
    state: &UnifiedStateManager,
    bind: String,
    token: Option<String>,
    chains: Option<String>,
) -> Result<()> {
    output::header("Remote Chain-Dispatch Host");

    let token = token.or_else(|| std::env::var("CSV_REMOTE_HOST_TOKEN").ok());
    if token.is_none() {
        output::warning(
            "No bearer token configured (--token or CSV_REMOTE_HOST_TOKEN). The host will accept \
             unauthenticated requests — only run this behind mTLS or on a private socket.",
        );
    }

    let chain_list = resolve_chains(chains)?;
    // Keep `client` alive for the lifetime of the server: it owns the runtime
    // stores the adapters were built against.
    let client = build_host_client(config, state, &chain_list).await?;

    let registry = {
        let handle = client.adapter_registry();
        let guard = handle.lock().unwrap_or_else(|e| e.into_inner());
        Arc::new(guard.shared_snapshot())
    };

    let served: Vec<String> = chain_list.iter().map(|c| c.as_str().to_string()).collect();
    output::kv("Chains", &served.join(", "));
    output::kv("Auth", if token.is_some() { "bearer token" } else { "none" });
    output::kv("Bind", &bind);

    let serve_state = ServeState {
        registry,
        token: token.map(Arc::new),
    };
    let app = Router::new()
        .route("/", post(dispatch_handler))
        .with_state(serve_state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {bind}: {e}"))?;
    output::success(&format!("Remote dispatch host listening on {bind}"));
    output::info("Press Ctrl-C to stop.");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| anyhow::anyhow!("server error: {e}"))?;

    // Keep the client bound until shutdown so its adapters/stores stay alive.
    drop(client);
    Ok(())
}

fn cmd_status() -> Result<()> {
    output::header("Runtime Status");

    let monitor = HealthMonitor::new();
    let health = monitor.health();
    let mode = monitor.mode();

    output::kv("Health", health_display(&health));
    output::kv("Mode", mode_display(mode));
    output::kv(
        "Circuit Breaker",
        circuit_breaker_state_display(CircuitBreakerState::Closed),
    );

    match &health {
        RuntimeHealth::Healthy => {
            output::success("Runtime is operating normally");
        }
        RuntimeHealth::Degraded { reason } => {
            output::warning(&format!("Runtime is degraded: {}", reason_display(reason)));
            output::info("Some operations may be slower or limited");
        }
        RuntimeHealth::Unsafe => {
            output::danger("Runtime is in unsafe mode — operator intervention required");
        }
    }

    Ok(())
}

fn cmd_health() -> Result<()> {
    output::header("Component Health Checks");

    let monitor = HealthMonitor::new();
    let checks = monitor.checks();

    if checks.is_empty() {
        output::info("No health checks configured");
        output::info("Health checks are registered when the runtime starts");
        println!();
        output::info("The CSV runtime monitors these components:");
        println!("  • RPC connectivity (per-chain)");
        println!("  • Replay registry availability");
        println!("  • Event persistence lag");
        println!("  • Clock drift detection");
        println!("  • Circuit breaker state");
        println!("  • Admission control pressure");
        println!();
        output::info("To see runtime health, start a runtime instance with:");
        println!("  csv cross-chain materialize --from <chain> --to <chain> ...");
        println!("  or use csv runtime status for overall runtime state");
        return Ok(());
    }

    // Render the same health artifact the wallet renders. Building it through the
    // contract is what stops the CLI from quietly reporting an overall-healthy
    // runtime while a component is failing — the contract rejects that report.
    let report = contract::health_report(&monitor.health(), checks)?;
    contract_view::health_report(&report);

    Ok(())
}

fn cmd_admission() -> Result<()> {
    output::header("Admission Control");

    let controller = AdmissionController::default();
    let limits = controller.limits();
    let snapshot = controller.snapshot();

    output::kv(
        "Max In-Flight Transfers",
        &limits.max_in_flight_transfers.to_string(),
    );
    output::kv(
        "Max In-Flight Per Chain",
        &limits.max_in_flight_per_chain.to_string(),
    );
    output::kv(
        "Current In-Flight",
        &snapshot.in_flight_transfers.to_string(),
    );

    if !snapshot.in_flight_by_chain.is_empty() {
        println!("\n  {}:", "In-Flight by Chain".bold());
        for (chain, count) in &snapshot.in_flight_by_chain {
            println!("    {:<20} {}", format!("{}:", chain).dimmed(), count);
        }
    }

    let utilization = if limits.max_in_flight_transfers > 0 {
        (snapshot.in_flight_transfers as f64 / limits.max_in_flight_transfers as f64) * 100.0
    } else {
        0.0
    };

    output::kv("Capacity Utilization", &format!("{:.1}%", utilization));

    if utilization > 90.0 {
        output::danger("Admission capacity nearly exhausted — transfers may be rejected");
    } else if utilization > 70.0 {
        output::warning("Admission capacity above 70%");
    } else {
        output::success("Admission capacity healthy");
    }

    Ok(())
}

fn cmd_events(_count: usize) -> Result<()> {
    output::header("Runtime Events");

    output::info("Runtime event streaming requires a running runtime instance");
    output::info("Events are published to the EventBus and can be queried via the runtime API");

    println!("\n  {}:", "Event Types".bold());
    println!("    TransferPhaseEntered — A transfer entered a new phase");
    println!("    TransferPhaseCompleted — A transfer phase completed");
    println!("    TransferPhaseFailed — A transfer phase failed");
    println!("    LeaseAcquired — A transfer lease was acquired");
    println!("    LeaseReleased — A transfer lease was released");
    println!("    CircuitBreakerOpen — A circuit breaker opened");
    println!("    CircuitBreakerClosed — A circuit breaker closed");
    println!("    AdmissionRejected — A transfer was rejected by admission control");

    Ok(())
}

fn health_display(health: &RuntimeHealth) -> &'static str {
    match health {
        RuntimeHealth::Healthy => "Healthy",
        RuntimeHealth::Degraded { .. } => "Degraded",
        RuntimeHealth::Unsafe => "Unsafe",
    }
}

fn mode_display(mode: RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::Normal => "Normal",
        RuntimeMode::Degraded => "Degraded",
        RuntimeMode::Unsafe => "Unsafe",
    }
}

fn circuit_breaker_state_display(state: CircuitBreakerState) -> &'static str {
    match state {
        CircuitBreakerState::Closed => "Closed (normal)",
        CircuitBreakerState::Open => "Open (blocking)",
        CircuitBreakerState::HalfOpen => "HalfOpen (testing)",
    }
}

fn reason_display(reason: &DegradedReason) -> &'static str {
    match reason {
        DegradedReason::RpcDisagreement => "RPC provider disagreement",
        DegradedReason::QuorumCollapse => "Quorum collapse",
        DegradedReason::HistoricalContinuityFailure => "Historical continuity failure",
        DegradedReason::ReplayRegistryUnavailable => "Replay registry unavailable",
        DegradedReason::EventPersistenceLag => "Event persistence lag",
        DegradedReason::ClockDrift => "Clock drift detected",
        DegradedReason::PartialPartition => "Partial network partition",
        DegradedReason::TrustPackageExpiry => "Trust package expired",
    }
}
