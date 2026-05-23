//! State machine verification with transition graph per Phase 12
//!
//! This module provides state machine verification with explicit transition graphs
//! to ensure protocol invariants are maintained throughout state transitions.

use std::collections::{HashMap, HashSet};
use csv_hash::Hash;
use csv_core::abi_constitution::{SealState, StateMachineInvariants};
use serde::{Deserialize, Serialize};

/// State in the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Seal created
    Created,
    /// Seal locked for cross-chain transfer
    Locked,
    /// Seal consumed
    Consumed,
    /// Seal minted on destination chain
    Minted,
    /// Seal refunded
    Refunded,
    /// Seal failed
    Failed,
}

/// Transition between states.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transition {
    /// From state
    pub from: State,
    /// To state
    pub to: State,
    /// Transition label
    pub label: String,
}

/// Transition graph for state machine verification.
#[derive(Debug, Clone)]
pub struct TransitionGraph {
    /// Valid transitions
    pub transitions: HashSet<Transition>,
    /// States in the graph
    pub states: HashSet<State>,
}

impl TransitionGraph {
    /// Create a new transition graph.
    pub fn new() -> Self {
        Self {
            transitions: HashSet::new(),
            states: HashSet::new(),
        }
    }

    /// Add a transition to the graph.
    pub fn add_transition(&mut self, from: State, to: State, label: &str) {
        self.states.insert(from);
        self.states.insert(to);
        self.transitions.insert(Transition {
            from,
            to,
            label: label.to_string(),
        });
    }

    /// Check if a transition is valid.
    pub fn is_valid_transition(&self, from: State, to: State) -> bool {
        self.transitions.contains(&Transition {
            from,
            to,
            label: String::new(), // Label not checked for validity
        })
    }

    /// Get all valid next states from a given state.
    pub fn get_next_states(&self, from: State) -> Vec<State> {
        self.transitions
            .iter()
            .filter(|t| t.from == from)
            .map(|t| t.to)
            .collect()
    }

    /// Get all valid previous states to a given state.
    pub fn get_prev_states(&self, to: State) -> Vec<State> {
        self.transitions
            .iter()
            .filter(|t| t.to == to)
            .map(|t| t.from)
            .collect()
    }

    /// Check if the graph has any cycles (excluding self-loops).
    pub fn has_cycles(&self) -> bool {
        // Simple cycle detection using DFS
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();

        for state in &self.states {
            if self.has_cycle_dfs(*state, &mut visited, &mut recursion_stack) {
                return true;
            }
        }

        false
    }

    fn has_cycle_dfs(
        &self,
        state: State,
        visited: &mut HashSet<State>,
        recursion_stack: &mut HashSet<State>,
    ) -> bool {
        visited.insert(state);
        recursion_stack.insert(state);

        for next in self.get_next_states(state) {
            if !visited.contains(&next) {
                if self.has_cycle_dfs(next, visited, recursion_stack) {
                    return true;
                }
            } else if recursion_stack.contains(&next) {
                return true;
            }
        }

        recursion_stack.remove(&state);
        false
    }
}

/// State machine verifier.
pub struct StateMachineVerifier {
    /// Transition graph
    pub graph: TransitionGraph,
    /// Current state
    pub current_state: State,
    /// State history
    pub history: Vec<State>,
}

impl StateMachineVerifier {
    /// Create a new state machine verifier with the CSV protocol transition graph.
    pub fn new_csv_protocol() -> Self {
        let mut graph = TransitionGraph::new();

        // Define valid transitions for CSV protocol
        graph.add_transition(State::Created, State::Locked, "lock");
        graph.add_transition(State::Created, State::Consumed, "consume");
        graph.add_transition(State::Locked, State::Minted, "mint");
        graph.add_transition(State::Locked, State::Refunded, "refund");
        graph.add_transition(State::Locked, State::Failed, "timeout");
        graph.add_transition(State::Minted, State::Consumed, "consume");
        graph.add_transition(State::Refunded, State::Created, "recreate");
        graph.add_transition(State::Failed, State::Created, "retry");

        Self {
            graph,
            current_state: State::Created,
            history: vec![State::Created],
        }
    }

    /// Attempt a state transition.
    pub fn transition(&mut self, to: State, label: &str) -> Result<(), StateMachineError> {
        if !self.graph.is_valid_transition(self.current_state, to) {
            return Err(StateMachineError::InvalidTransition {
                from: self.current_state,
                to,
                label: label.to_string(),
            });
        }

        self.current_state = to;
        self.history.push(to);
        Ok(())
    }

    /// Get the current state.
    pub fn current_state(&self) -> State {
        self.current_state
    }

    /// Get the state history.
    pub fn history(&self) -> &[State] {
        &self.history
    }

    /// Verify the state machine is in a valid state.
    pub fn verify(&self) -> Result<(), StateMachineError> {
        // Check for cycles
        if self.graph.has_cycles() {
            return Err(StateMachineError::CycleDetected);
        }

        // Check current state is in the graph
        if !self.graph.states.contains(&self.current_state) {
            return Err(StateMachineError::InvalidState(self.current_state));
        }

        Ok(())
    }

    /// Reset the state machine to initial state.
    pub fn reset(&mut self) {
        self.current_state = State::Created;
        self.history = vec![State::Created];
    }
}

/// State machine verification errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum StateMachineError {
    #[error("Invalid transition from {from:?} to {to:?} with label '{label}'")]
    InvalidTransition {
        from: State,
        to: State,
        label: String,
    },

    #[error("Invalid state: {0:?}")]
    InvalidState(State),

    #[error("Cycle detected in transition graph")]
    CycleDetected,

    #[error("State machine verification failed: {0}")]
    VerificationFailed(String),
}

/// State machine test case.
#[derive(Debug, Clone)]
pub struct StateMachineTestCase {
    /// Test name
    pub name: String,
    /// Initial state
    pub initial_state: State,
    /// Transitions to apply
    pub transitions: Vec<(State, String)>,
    /// Expected final state
    pub expected_final_state: State,
    /// Whether the test should succeed
    pub should_succeed: bool,
}

/// State machine test runner.
pub struct StateMachineTestRunner {
    /// Test cases
    pub test_cases: Vec<StateMachineTestCase>,
    /// Test results
    pub results: Vec<StateMachineTestResult>,
}

impl StateMachineTestRunner {
    /// Create a new test runner.
    pub fn new() -> Self {
        Self {
            test_cases: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Add a test case.
    pub fn add_test_case(&mut self, test_case: StateMachineTestCase) {
        self.test_cases.push(test_case);
    }

    /// Run all test cases.
    pub fn run_all(&mut self) -> Vec<StateMachineTestResult> {
        self.results.clear();

        for test_case in &self.test_cases {
            let result = self.run_test(test_case);
            self.results.push(result);
        }

        self.results.clone()
    }

    /// Run a single test case.
    pub fn run_test(&self, test_case: &StateMachineTestCase) -> StateMachineTestResult {
        let mut verifier = StateMachineVerifier::new_csv_protocol();
        verifier.current_state = test_case.initial_state;
        verifier.history = vec![test_case.initial_state];

        let mut succeeded = true;
        let mut error = None;

        for (to, label) in &test_case.transitions {
            match verifier.transition(*to, label) {
                Ok(_) => {}
                Err(e) => {
                    succeeded = false;
                    error = Some(e.to_string());
                    break;
                }
            }
        }

        let final_state_correct = verifier.current_state == test_case.expected_final_state;
        let test_passed = if test_case.should_succeed {
            succeeded && final_state_correct
        } else {
            !succeeded
        };

        StateMachineTestResult {
            name: test_case.name.clone(),
            passed: test_passed,
            final_state: verifier.current_state,
            expected_final_state: test_case.expected_final_state,
            error,
        }
    }
}

/// State machine test result.
#[derive(Debug, Clone)]
pub struct StateMachineTestResult {
    /// Test name
    pub name: String,
    /// Whether the test passed
    pub passed: bool,
    /// Actual final state
    pub final_state: State,
    /// Expected final state
    pub expected_final_state: State,
    /// Error if failed
    pub error: Option<String>,
}

/// Test valid state transitions.
#[test]
fn test_valid_transitions() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    // Valid transition: Created -> Locked
    assert!(verifier.transition(State::Locked, "lock").is_ok());
    assert_eq!(verifier.current_state(), State::Locked);

    // Valid transition: Locked -> Minted
    assert!(verifier.transition(State::Minted, "mint").is_ok());
    assert_eq!(verifier.current_state(), State::Minted);
}

/// Test invalid state transitions.
#[test]
fn test_invalid_transitions() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    // Invalid transition: Created -> Minted (must go through Locked)
    assert!(verifier.transition(State::Minted, "mint").is_err());

    // Invalid transition: Locked -> Created (cannot go back directly)
    verifier.transition(State::Locked, "lock").unwrap();
    assert!(verifier.transition(State::Created, "recreate").is_err());
}

/// Test state machine verification.
#[test]
fn test_state_machine_verification() {
    let verifier = StateMachineVerifier::new_csv_protocol();
    assert!(verifier.verify().is_ok());
}

/// Test transition graph cycle detection.
#[test]
fn test_cycle_detection() {
    let mut graph = TransitionGraph::new();
    graph.add_transition(State::Created, State::Locked, "lock");
    graph.add_transition(State::Locked, State::Created, "unlock"); // Creates cycle

    assert!(graph.has_cycles());
}

/// Test state machine test runner.
#[test]
fn test_state_machine_test_runner() {
    let mut runner = StateMachineTestRunner::new();

    // Valid transition test
    runner.add_test_case(StateMachineTestCase {
        name: "Valid lock and mint".to_string(),
        initial_state: State::Created,
        transitions: vec![(State::Locked, "lock".to_string()), (State::Minted, "mint".to_string())],
        expected_final_state: State::Minted,
        should_succeed: true,
    });

    // Invalid transition test
    runner.add_test_case(StateMachineTestCase {
        name: "Invalid direct mint".to_string(),
        initial_state: State::Created,
        transitions: vec![(State::Minted, "mint".to_string())],
        expected_final_state: State::Created,
        should_succeed: false,
    });

    let results = runner.run_all();
    assert_eq!(results.len(), 2);
    assert!(results[0].passed);
    assert!(results[1].passed);
}

/// Test refund transition.
#[test]
fn test_refund_transition() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    verifier.transition(State::Locked, "lock").unwrap();
    verifier.transition(State::Refunded, "refund").unwrap();

    assert_eq!(verifier.current_state(), State::Refunded);

    // After refund, can recreate
    verifier.transition(State::Created, "recreate").unwrap();
    assert_eq!(verifier.current_state(), State::Created);
}

/// Test failed transition.
#[test]
fn test_failed_transition() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    verifier.transition(State::Locked, "lock").unwrap();
    verifier.transition(State::Failed, "timeout").unwrap();

    assert_eq!(verifier.current_state(), State::Failed);

    // After failure, can retry
    verifier.transition(State::Created, "retry").unwrap();
    assert_eq!(verifier.current_state(), State::Created);
}

/// Test state history tracking.
#[test]
fn test_state_history() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    verifier.transition(State::Locked, "lock").unwrap();
    verifier.transition(State::Minted, "mint").unwrap();

    let history = verifier.history();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0], State::Created);
    assert_eq!(history[1], State::Locked);
    assert_eq!(history[2], State::Minted);
}

/// Test get next states.
#[test]
fn test_get_next_states() {
    let verifier = StateMachineVerifier::new_csv_protocol();
    let next_states = verifier.graph.get_next_states(State::Locked);

    // From Locked, can go to Minted, Refunded, or Failed
    assert!(next_states.contains(&State::Minted));
    assert!(next_states.contains(&State::Refunded));
    assert!(next_states.contains(&State::Failed));
}

/// Test get previous states.
#[test]
fn test_get_prev_states() {
    let verifier = StateMachineVerifier::new_csv_protocol();
    let prev_states = verifier.graph.get_prev_states(State::Minted);

    // To Minted, must come from Locked
    assert!(prev_states.contains(&State::Locked));
}

/// Test state machine reset.
#[test]
fn test_state_machine_reset() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    verifier.transition(State::Locked, "lock").unwrap();
    verifier.transition(State::Minted, "mint").unwrap();

    verifier.reset();

    assert_eq!(verifier.current_state(), State::Created);
    assert_eq!(verifier.history().len(), 1);
}

/// Test complex transition sequence.
#[test]
fn test_complex_transition_sequence() {
    let mut verifier = StateMachineVerifier::new_csv_protocol();

    // Created -> Locked -> Refunded -> Created -> Locked -> Minted
    verifier.transition(State::Locked, "lock").unwrap();
    verifier.transition(State::Refunded, "refund").unwrap();
    verifier.transition(State::Created, "recreate").unwrap();
    verifier.transition(State::Locked, "lock").unwrap();
    verifier.transition(State::Minted, "mint").unwrap();

    assert_eq!(verifier.current_state(), State::Minted);
    assert_eq!(verifier.history().len(), 6);
}
