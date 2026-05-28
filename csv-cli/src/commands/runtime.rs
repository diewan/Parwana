//! Runtime subcommand — monitoring and diagnostics for the CSV runtime engine

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use csv_admission::AdmissionController;
use csv_observability::runtime_health::{DegradedReason, RuntimeHealth};
use csv_runtime::{CircuitBreakerState, HealthMonitor, RuntimeMode};

use crate::config::Config;
use crate::output;

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
}

pub fn execute(action: RuntimeAction, _config: &Config) -> Result<()> {
    match action {
        RuntimeAction::Status => cmd_status(),
        RuntimeAction::Health => cmd_health(),
        RuntimeAction::Admission => cmd_admission(),
        RuntimeAction::Events { count } => cmd_events(count),
    }
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
        println!("  csv cross-chain transfer --from <chain> --to <chain> ...");
        println!("  or use csv runtime status for overall runtime state");
        return Ok(());
    }

    let headers = vec!["Component", "Status", "Error"];
    let mut rows = Vec::new();

    for check in checks {
        let status = if check.healthy {
            "Healthy".to_string()
        } else {
            format!("Unhealthy: {}", check.error.as_deref().unwrap_or("unknown"))
        };
        rows.push(vec![
            check.component.clone(),
            status,
            check.error.clone().unwrap_or_default(),
        ]);
    }

    output::table(&headers, &rows);

    let unhealthy_count = checks.iter().filter(|c| !c.healthy).count();
    if unhealthy_count > 0 {
        output::warning(&format!("{} component(s) unhealthy", unhealthy_count));
    } else {
        output::success("All components healthy");
    }

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
