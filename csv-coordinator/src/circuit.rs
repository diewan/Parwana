use std::time::{Duration, Instant};

/// Circuit breaker state for a chain cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout: Duration,
    pub half_open_max_calls: u32,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_calls: 3,
        }
    }
}

/// Per-cell circuit breaker.
pub struct CellCircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    config: CircuitConfig,
}

impl CellCircuitBreaker {
    pub fn new(config: CircuitConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            config,
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == CircuitState::Open
    }

    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.success_threshold {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Open => {
                // Should not record success when open
            }
        }
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());

        if self.failure_count >= self.config.failure_threshold {
            self.state = CircuitState::Open;
        }
    }

    pub fn attempt_reset(&mut self) -> bool {
        if self.state != CircuitState::Open {
            return false;
        }

        if let Some(last_failure) = self.last_failure_time {
            if last_failure.elapsed() >= self.config.timeout {
                self.state = CircuitState::HalfOpen;
                self.success_count = 0;
                return true;
            }
        }

        false
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }
}
