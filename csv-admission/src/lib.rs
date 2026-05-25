//! CSV Admission Control
//!
//! This crate provides admission control for runtime work. It is the runtime's
//! pressure boundary, rejecting excess work before protocol state is mutated.
//! This prevents RPC stalls or adversarial traffic from amplifying into replay
//! consumption, proof backlog, or mint starvation.
//!
//! This crate has zero dependencies on chain adapters.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Runtime admission limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Maximum transfers that may execute concurrently across the runtime.
    pub max_in_flight_transfers: usize,
    /// Maximum transfers that may use any one chain concurrently.
    pub max_in_flight_per_chain: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_in_flight_transfers: 128,
            max_in_flight_per_chain: 32,
        }
    }
}

/// Snapshot of current admission pressure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    /// Current total in-flight transfers.
    pub in_flight_transfers: usize,
    /// Current in-flight transfer count by chain.
    pub in_flight_by_chain: HashMap<String, usize>,
}

/// Admission rejection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// Runtime-wide transfer capacity is exhausted.
    #[error(
        "runtime admission rejected transfer: total in-flight {in_flight} reached limit {limit}"
    )]
    TransferLimit {
        /// Current in-flight count.
        in_flight: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Chain-specific capacity is exhausted.
    #[error(
        "runtime admission rejected transfer: chain {chain_id} in-flight {in_flight} reached limit {limit}"
    )]
    ChainLimit {
        /// Chain whose capacity is exhausted.
        chain_id: String,
        /// Current in-flight count for the chain.
        in_flight: usize,
        /// Configured limit.
        limit: usize,
    },
}

#[derive(Debug, Default)]
struct AdmissionState {
    in_flight_transfers: usize,
    in_flight_by_chain: HashMap<String, usize>,
}

/// Runtime admission controller.
#[derive(Debug, Clone)]
pub struct AdmissionController {
    limits: AdmissionLimits,
    state: Arc<Mutex<AdmissionState>>,
}

impl AdmissionController {
    /// Create a controller with explicit limits.
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(AdmissionState::default())),
        }
    }

    /// Return configured limits.
    pub fn limits(&self) -> &AdmissionLimits {
        &self.limits
    }

    /// Acquire permission to execute a transfer touching source and destination chains.
    pub fn acquire_transfer(
        &self,
        source_chain: &str,
        destination_chain: &str,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if state.in_flight_transfers >= self.limits.max_in_flight_transfers {
            return Err(AdmissionError::TransferLimit {
                in_flight: state.in_flight_transfers,
                limit: self.limits.max_in_flight_transfers,
            });
        }

        let chains = unique_chains(source_chain, destination_chain);
        for chain_id in &chains {
            let in_flight = state
                .in_flight_by_chain
                .get(chain_id.as_str())
                .copied()
                .unwrap_or(0);
            if in_flight >= self.limits.max_in_flight_per_chain {
                return Err(AdmissionError::ChainLimit {
                    chain_id: chain_id.clone(),
                    in_flight,
                    limit: self.limits.max_in_flight_per_chain,
                });
            }
        }

        state.in_flight_transfers += 1;
        for chain_id in &chains {
            *state
                .in_flight_by_chain
                .entry(chain_id.clone())
                .or_insert(0) += 1;
        }

        Ok(AdmissionPermit {
            controller: self.clone(),
            chains,
            released: false,
        })
    }

    /// Return a pressure snapshot.
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        AdmissionSnapshot {
            in_flight_transfers: state.in_flight_transfers,
            in_flight_by_chain: state.in_flight_by_chain.clone(),
        }
    }

    fn release_transfer(&self, chains: &[String]) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.in_flight_transfers = state.in_flight_transfers.saturating_sub(1);
        for chain_id in chains {
            if let Some(count) = state.in_flight_by_chain.get_mut(chain_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.in_flight_by_chain.remove(chain_id);
                }
            }
        }
    }
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new(AdmissionLimits::default())
    }
}

/// RAII permit for admitted runtime work.
#[derive(Debug)]
pub struct AdmissionPermit {
    controller: AdmissionController,
    chains: Vec<String>,
    released: bool,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if !self.released {
            self.controller.release_transfer(&self.chains);
            self.released = true;
        }
    }
}

fn unique_chains(source_chain: &str, destination_chain: &str) -> Vec<String> {
    if source_chain == destination_chain {
        vec![source_chain.to_string()]
    } else {
        vec![source_chain.to_string(), destination_chain.to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_when_total_capacity_is_exhausted() {
        let controller = AdmissionController::new(AdmissionLimits {
            max_in_flight_transfers: 1,
            max_in_flight_per_chain: 2,
        });
        let _permit = controller.acquire_transfer("bitcoin", "ethereum").unwrap();

        let err = controller
            .acquire_transfer("solana", "sui")
            .expect_err("second transfer should be rejected");
        assert!(matches!(err, AdmissionError::TransferLimit { .. }));
    }

    #[test]
    fn rejects_when_chain_capacity_is_exhausted() {
        let controller = AdmissionController::new(AdmissionLimits {
            max_in_flight_transfers: 4,
            max_in_flight_per_chain: 1,
        });
        let _permit = controller.acquire_transfer("bitcoin", "ethereum").unwrap();

        let err = controller
            .acquire_transfer("bitcoin", "solana")
            .expect_err("second bitcoin transfer should be rejected");
        assert!(
            matches!(err, AdmissionError::ChainLimit { chain_id, .. } if chain_id == "bitcoin")
        );
    }

    #[test]
    fn releases_capacity_when_permit_drops() {
        let controller = AdmissionController::new(AdmissionLimits {
            max_in_flight_transfers: 1,
            max_in_flight_per_chain: 1,
        });
        {
            let _permit = controller.acquire_transfer("bitcoin", "ethereum").unwrap();
            assert_eq!(controller.snapshot().in_flight_transfers, 1);
        }

        assert_eq!(controller.snapshot().in_flight_transfers, 0);
        assert!(controller.acquire_transfer("bitcoin", "ethereum").is_ok());
    }
}
