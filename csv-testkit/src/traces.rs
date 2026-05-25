//! Canonical trace fixtures for testing.
//!
//! This module provides canonical trace fixtures that are recorded sequences
//! of real chain interactions with known-good expected outputs. Tests that pass
//! against a CanonicalTrace are testing the protocol, not the mock.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A recorded RPC interaction from a real chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedRpcInteraction {
    /// RPC method called.
    pub method: String,
    /// Parameters sent to the RPC.
    pub params: serde_json::Value,
    /// Response received from the RPC.
    pub response: serde_json::Value,
    /// Timestamp of the interaction.
    pub timestamp: u64,
}

/// Expected output after processing a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutput {
    /// Expected verification result.
    pub verification_result: bool,
    /// Expected error message (if any).
    pub expected_error: Option<String>,
    /// Expected proof hash (if applicable).
    pub expected_proof_hash: Option<String>,
}

/// An injected fault for adversarial testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedFault {
    /// Type of fault.
    pub fault_type: String,
    /// Description of the fault.
    pub description: String,
    /// At which interaction index to inject the fault.
    pub inject_at: usize,
}

/// A canonical trace is a recorded sequence of real chain interactions
/// with known-good expected outputs.
///
/// Tests that pass against a CanonicalTrace are testing the protocol,
/// not the mock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalTrace {
    /// Recorded real RPC responses (captured from testnet, then frozen).
    pub rpc_responses: Vec<RecordedRpcInteraction>,
    /// Expected outputs after processing this trace.
    pub expected_outputs: Vec<ExpectedOutput>,
    /// Known violations in this trace (for adversarial testing).
    pub injected_faults: Vec<InjectedFault>,
}

impl CanonicalTrace {
    /// Load a canonical trace from the fixtures directory.
    ///
    /// These files are checked into version control and never change
    /// without an explicit RFC + review.
    pub fn load(name: &str) -> Self {
        let path = format!("csv-testkit/fixtures/{}.trace.json", name);
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("Failed to load trace file: {}", path));
        serde_json::from_str(&content).unwrap_or_else(|_| {
            panic!(
                "Failed to parse trace file: {}. Ensure it's valid JSON.",
                path
            )
        })
    }

    /// Save a canonical trace to the fixtures directory.
    ///
    /// This should only be done when capturing new real chain interactions
    /// for testing purposes.
    pub fn save(&self, name: &str) {
        let path = format!("csv-testkit/fixtures/{}.trace.json", name);
        let content = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(&path, content).unwrap_or_else(|_| {
            panic!("Failed to save trace file: {}", path)
        });
    }

    /// Create a new empty canonical trace.
    pub fn new() -> Self {
        Self {
            rpc_responses: Vec::new(),
            expected_outputs: Vec::new(),
            injected_faults: Vec::new(),
        }
    }

    /// Add an RPC interaction to the trace.
    pub fn add_rpc_interaction(&mut self, interaction: RecordedRpcInteraction) {
        self.rpc_responses.push(interaction);
    }

    /// Add an expected output to the trace.
    pub fn add_expected_output(&mut self, output: ExpectedOutput) {
        self.expected_outputs.push(output);
    }

    /// Add an injected fault to the trace.
    pub fn add_injected_fault(&mut self, fault: InjectedFault) {
        self.injected_faults.push(fault);
    }

    /// Check if a trace file exists.
    pub fn exists(name: &str) -> bool {
        let path = format!("csv-testkit/fixtures/{}.trace.json", name);
        Path::new(&path).exists()
    }
}

impl Default for CanonicalTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_empty_trace() {
        let trace = CanonicalTrace::new();
        assert!(trace.rpc_responses.is_empty());
        assert!(trace.expected_outputs.is_empty());
        assert!(trace.injected_faults.is_empty());
    }

    #[test]
    fn test_add_rpc_interaction() {
        let mut trace = CanonicalTrace::new();
        let interaction = RecordedRpcInteraction {
            method: "get_block".to_string(),
            params: serde_json::json!({ "height": 100 }),
            response: serde_json::json!({ "hash": "0x1234" }),
            timestamp: 1234567890,
        };
        trace.add_rpc_interaction(interaction);
        assert_eq!(trace.rpc_responses.len(), 1);
    }

    #[test]
    fn test_add_expected_output() {
        let mut trace = CanonicalTrace::new();
        let output = ExpectedOutput {
            verification_result: true,
            expected_error: None,
            expected_proof_hash: Some("0xabcd".to_string()),
        };
        trace.add_expected_output(output);
        assert_eq!(trace.expected_outputs.len(), 1);
    }

    #[test]
    fn test_add_injected_fault() {
        let mut trace = CanonicalTrace::new();
        let fault = InjectedFault {
            fault_type: "InvalidSignature".to_string(),
            description: "Inject invalid BLS signature".to_string(),
            inject_at: 5,
        };
        trace.add_injected_fault(fault);
        assert_eq!(trace.injected_faults.len(), 1);
    }
}
