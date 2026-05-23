//! Runtime Mode Module
//!
//! This module defines the operational modes of the CSV runtime.
//! The runtime can operate in different modes based on system health,
//! RPC availability, and operational requirements.
//!
//! # Modes
//!
//! - **Normal**: Full functionality, all RPC calls required, strict finality
//! - **Degraded**: Limited functionality, some RPC failures tolerated, relaxed finality
//! - **Unsafe**: Emergency mode, minimal checks, operator intervention required
//!
//! # Mode Transitions
//!
//! Mode transitions are triggered by:
//! - RPC failure rates exceeding thresholds
//! - Health check failures
//! - Manual operator commands
//! - Automatic recovery detection

use std::time::{Duration, SystemTime};

/// Runtime operational mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuntimeMode {
    /// Normal operation: full functionality, strict requirements
    Normal,
    /// Degraded operation: limited functionality, relaxed requirements
    Degraded,
    /// Unsafe operation: emergency mode, minimal checks
    Unsafe,
}

impl RuntimeMode {
    /// Returns true if the mode allows RPC fallback
    pub fn allows_rpc_fallback(&self) -> bool {
        match self {
            RuntimeMode::Normal => false,
            RuntimeMode::Degraded => true,
            RuntimeMode::Unsafe => true,
        }
    }

    /// Returns true if the mode enforces strict finality
    pub fn enforces_strict_finality(&self) -> bool {
        match self {
            RuntimeMode::Normal => true,
            RuntimeMode::Degraded => false,
            RuntimeMode::Unsafe => false,
        }
    }

    /// Returns the maximum allowed retry count for this mode
    pub fn max_retries(&self) -> u32 {
        match self {
            RuntimeMode::Normal => 3,
            RuntimeMode::Degraded => 5,
            RuntimeMode::Unsafe => 1,
        }
    }

    /// Returns the retry delay for this mode
    pub fn retry_delay(&self) -> Duration {
        match self {
            RuntimeMode::Normal => Duration::from_secs(5),
            RuntimeMode::Degraded => Duration::from_secs(10),
            RuntimeMode::Unsafe => Duration::from_secs(1),
        }
    }

    /// Returns true if this mode requires operator confirmation for critical operations
    pub fn requires_operator_confirmation(&self) -> bool {
        match self {
            RuntimeMode::Normal => false,
            RuntimeMode::Degraded => false,
            RuntimeMode::Unsafe => true,
        }
    }
}

/// Circuit breaker state for RPC failure tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Circuit is closed: requests flow normally
    Closed,
    /// Circuit is open: requests are blocked
    Open,
    /// Circuit is half-open: testing if service has recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit
    pub failure_threshold: u32,
    /// Duration to keep circuit open before attempting recovery
    pub open_timeout: Duration,
    /// Number of successful requests required to close circuit in half-open state
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_timeout: Duration::from_secs(60),
            success_threshold: 2,
        }
    }
}

/// Circuit breaker for RPC failure tracking
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    state: CircuitBreakerState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<SystemTime>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default configuration
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom configuration
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            config,
        }
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        match self.state {
            CircuitBreakerState::Closed => {
                self.failure_count = 0;
            }
            CircuitBreakerState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.success_threshold {
                    self.state = CircuitBreakerState::Closed;
                    self.success_count = 0;
                    self.failure_count = 0;
                }
            }
            CircuitBreakerState::Open => {
                // Should not happen - open circuit blocks requests
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(SystemTime::now());

        if self.failure_count >= self.config.failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }

    /// Check if a request should be allowed
    pub fn allow_request(&self) -> bool {
        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::HalfOpen => true,
            CircuitBreakerState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if let Ok(elapsed) = SystemTime::now().duration_since(last_failure) {
                        if elapsed >= self.config.open_timeout {
                            return true; // Allow request to test recovery
                        }
                    }
                }
                false
            }
        }
    }

    /// Attempt to transition from open to half-open state
    pub fn attempt_recovery(&mut self) -> bool {
        if self.state == CircuitBreakerState::Open {
            if let Some(last_failure) = self.last_failure_time {
                if let Ok(elapsed) = SystemTime::now().duration_since(last_failure) {
                    if elapsed >= self.config.open_timeout {
                        self.state = CircuitBreakerState::HalfOpen;
                        self.success_count = 0;
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get the current circuit breaker state
    pub fn state(&self) -> CircuitBreakerState {
        self.state
    }

    /// Get the current failure count
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Reset the circuit breaker to closed state
    pub fn reset(&mut self) {
        self.state = CircuitBreakerState::Closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.last_failure_time = None;
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime health status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some systems degraded but operational
    Degraded,
    /// Critical systems non-operational
    Critical,
}

/// Health check result for a specific component
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Component name
    pub component: String,
    /// Whether the component is healthy
    pub healthy: bool,
    /// Optional error message if unhealthy
    pub error: Option<String>,
    /// Timestamp of the check
    pub timestamp: SystemTime,
}

/// Runtime health monitor
#[derive(Debug, Clone)]
pub struct HealthMonitor {
    /// Current overall health status
    status: HealthStatus,
    /// Individual component health checks
    checks: Vec<HealthCheck>,
    /// Current runtime mode
    mode: RuntimeMode,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            checks: Vec::new(),
            mode: RuntimeMode::Normal,
        }
    }

    /// Record a health check result
    pub fn record_check(&mut self, check: HealthCheck) {
        // Remove any existing check for this component
        self.checks.retain(|c| c.component != check.component);
        self.checks.push(check);
        self.update_status();
        self.update_mode();
    }

    /// Update overall health status based on component checks
    fn update_status(&mut self) {
        if self.checks.is_empty() {
            self.status = HealthStatus::Healthy;
            return;
        }

        let unhealthy_count = self.checks.iter().filter(|c| !c.healthy).count();
        let total_count = self.checks.len();

        if unhealthy_count == 0 {
            self.status = HealthStatus::Healthy;
        } else if unhealthy_count < total_count {
            self.status = HealthStatus::Degraded;
        } else {
            self.status = HealthStatus::Critical;
        }
    }

    /// Update runtime mode based on health status
    fn update_mode(&mut self) {
        self.mode = match self.status {
            HealthStatus::Healthy => RuntimeMode::Normal,
            HealthStatus::Degraded => RuntimeMode::Degraded,
            HealthStatus::Critical => RuntimeMode::Unsafe,
        };
    }

    /// Get the current health status
    pub fn status(&self) -> HealthStatus {
        self.status.clone()
    }

    /// Get the current runtime mode
    pub fn mode(&self) -> RuntimeMode {
        self.mode
    }

    /// Get all component health checks
    pub fn checks(&self) -> &[HealthCheck] {
        &self.checks
    }

    /// Check if a specific component is healthy
    pub fn is_component_healthy(&self, component: &str) -> bool {
        self.checks
            .iter()
            .find(|c| c.component == component)
            .map(|c| c.healthy)
            .unwrap_or(true)
    }

    /// Reset all health checks
    pub fn reset(&mut self) {
        self.checks.clear();
        self.status = HealthStatus::Healthy;
        self.mode = RuntimeMode::Normal;
    }

    /// Manually set the runtime mode (for emergency overrides)
    pub fn set_mode(&mut self, mode: RuntimeMode) {
        self.mode = mode;
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_mode_properties() {
        assert!(!RuntimeMode::Normal.allows_rpc_fallback());
        assert!(RuntimeMode::Normal.enforces_strict_finality());
        assert_eq!(RuntimeMode::Normal.max_retries(), 3);

        assert!(RuntimeMode::Degraded.allows_rpc_fallback());
        assert!(!RuntimeMode::Degraded.enforces_strict_finality());
        assert_eq!(RuntimeMode::Degraded.max_retries(), 5);

        assert!(RuntimeMode::Unsafe.allows_rpc_fallback());
        assert!(!RuntimeMode::Unsafe.enforces_strict_finality());
        assert_eq!(RuntimeMode::Unsafe.max_retries(), 1);
        assert!(RuntimeMode::Unsafe.requires_operator_confirmation());
    }

    #[test]
    fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
        assert!(breaker.allow_request());

        // Record failures until threshold
        for _ in 0..5 {
            breaker.record_failure();
        }
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        assert!(!breaker.allow_request());

        // Attempt recovery after timeout
        std::thread::sleep(std::time::Duration::from_millis(100));
        breaker.config = CircuitBreakerConfig {
            failure_threshold: 5,
            open_timeout: Duration::from_millis(50),
            success_threshold: 2,
        };
        assert!(breaker.attempt_recovery());
        assert_eq!(breaker.state(), CircuitBreakerState::HalfOpen);

        // Record successes to close circuit
        breaker.record_success();
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_health_monitor() {
        let mut monitor = HealthMonitor::new();
        assert_eq!(monitor.status(), HealthStatus::Healthy);
        assert_eq!(monitor.mode(), RuntimeMode::Normal);

        monitor.record_check(HealthCheck {
            component: "rpc".to_string(),
            healthy: true,
            error: None,
            timestamp: SystemTime::now(),
        });
        assert_eq!(monitor.status(), HealthStatus::Healthy);
        assert_eq!(monitor.mode(), RuntimeMode::Normal);

        monitor.record_check(HealthCheck {
            component: "database".to_string(),
            healthy: false,
            error: Some("Connection failed".to_string()),
            timestamp: SystemTime::now(),
        });
        assert_eq!(monitor.status(), HealthStatus::Degraded);
        assert_eq!(monitor.mode(), RuntimeMode::Degraded);

        // Test manual mode override
        monitor.set_mode(RuntimeMode::Unsafe);
        assert_eq!(monitor.mode(), RuntimeMode::Unsafe);
    }
}
