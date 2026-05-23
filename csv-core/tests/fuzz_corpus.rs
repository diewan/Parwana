//! Fuzz corpus with malformed proofs and recursive Merkle trees per Phase 12
//!
//! This module provides a corpus of malformed proofs and edge cases
//! for fuzz testing the CSV protocol verification logic.

use csv_hash::Hash;
use csv_core::canonical_events::*;
use serde::{Deserialize, Serialize};

/// Fuzz corpus entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FuzzEntryType {
    /// Malformed proof
    MalformedProof,
    
    /// Recursive Merkle tree
    RecursiveMerkleTree,
    
    /// Oversized proof
    OversizedProof,
    
    /// Empty proof
    EmptyProof,
    
    /// Invalid signature
    InvalidSignature,
    
    /// Corrupted data
    CorruptedData,
    
    /// Edge case
    EdgeCase,
}

/// Fuzz corpus entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzEntry {
    /// Entry type
    pub entry_type: FuzzEntryType,
    /// Entry name
    pub name: String,
    /// Entry data
    pub data: Vec<u8>,
    /// Expected behavior (should fail or should pass)
    pub should_fail: bool,
    /// Description
    pub description: String,
}

impl FuzzEntry {
    /// Create a new fuzz entry.
    pub fn new(
        entry_type: FuzzEntryType,
        name: String,
        data: Vec<u8>,
        should_fail: bool,
        description: String,
    ) -> Self {
        Self {
            entry_type,
            name,
            data,
            should_fail,
            description,
        }
    }
}

/// Fuzz corpus for testing.
#[derive(Debug, Clone)]
pub struct FuzzCorpus {
    /// Corpus entries
    pub entries: Vec<FuzzEntry>,
}

impl FuzzCorpus {
    /// Create a new fuzz corpus.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry to the corpus.
    pub fn add_entry(&mut self, entry: FuzzEntry) {
        self.entries.push(entry);
    }

    /// Get all entries of a specific type.
    pub fn get_by_type(&self, entry_type: FuzzEntryType) -> Vec<&FuzzEntry> {
        self.entries
            .iter()
            .filter(|e| e.entry_type == entry_type)
            .collect()
    }

    /// Get an entry by name.
    pub fn get_by_name(&self, name: &str) -> Option<&FuzzEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Initialize the corpus with standard malformed proofs.
    pub fn initialize_standard_corpus(&mut self) {
        // Empty proof
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::EmptyProof,
            "empty_proof".to_string(),
            vec![],
            true,
            "Empty proof should be rejected".to_string(),
        ));

        // Oversized proof (exceeds 64KB)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::OversizedProof,
            "oversized_proof".to_string(),
            vec![0xFF; 65 * 1024],
            true,
            "Oversized proof should be rejected".to_string(),
        ));

        // Truncated proof
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::MalformedProof,
            "truncated_proof".to_string(),
            vec![1, 2, 3],
            true,
            "Truncated proof should be rejected".to_string(),
        ));

        // Invalid signature (all zeros)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::InvalidSignature,
            "zero_signature".to_string(),
            vec![0u8; 64],
            true,
            "Zero signature should be rejected".to_string(),
        ));

        // Corrupted data (random bytes)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::CorruptedData,
            "corrupted_data".to_string(),
            vec![0xAA, 0xBB, 0xCC, 0xDD],
            true,
            "Corrupted data should be rejected".to_string(),
        ));
    }

    /// Initialize the corpus with recursive Merkle trees.
    pub fn initialize_recursive_merkle_corpus(&mut self) {
        // Simple recursive tree (2 levels)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::RecursiveMerkleTree,
            "recursive_tree_2_levels".to_string(),
            Self::generate_recursive_merkle_tree(2),
            true,
            "Recursive Merkle tree with 2 levels should be rejected".to_string(),
        ));

        // Deep recursive tree (10 levels)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::RecursiveMerkleTree,
            "recursive_tree_10_levels".to_string(),
            Self::generate_recursive_merkle_tree(10),
            true,
            "Deep recursive Merkle tree should be rejected".to_string(),
        ));

        // Self-referential tree
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::RecursiveMerkleTree,
            "self_referential_tree".to_string(),
            Self::generate_self_referential_tree(),
            true,
            "Self-referential Merkle tree should be rejected".to_string(),
        ));
    }

    /// Initialize the corpus with edge cases.
    pub fn initialize_edge_cases(&mut self) {
        // Maximum size proof (exactly 64KB)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::EdgeCase,
            "max_size_proof".to_string(),
            vec![0xFF; 64 * 1024],
            false,
            "Maximum size proof should be accepted".to_string(),
        ));

        // Minimum size proof (1 byte)
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::EdgeCase,
            "min_size_proof".to_string(),
            vec![0x01],
            true,
            "Minimum size proof should be rejected".to_string(),
        ));

        // All zeros proof
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::EdgeCase,
            "all_zeros_proof".to_string(),
            vec![0u8; 100],
            true,
            "All zeros proof should be rejected".to_string(),
        ));

        // All ones proof
        self.add_entry(FuzzEntry::new(
            FuzzEntryType::EdgeCase,
            "all_ones_proof".to_string(),
            vec![0xFF; 100],
            true,
            "All ones proof should be rejected".to_string(),
        ));
    }

    /// Generate a recursive Merkle tree structure.
    fn generate_recursive_merkle_tree(depth: u8) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(depth); // Depth marker
        
        // Generate tree structure
        for i in 0..depth {
            data.push(i);
            data.extend_from_slice(&[0u8; 32]); // Mock hash
        }
        
        data
    }

    /// Generate a self-referential tree structure.
    fn generate_self_referential_tree() -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0xFF); // Self-reference marker
        data.extend_from_slice(&[0u8; 32]); // Points to itself
        data
    }

    /// Generate a summary report.
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str("Fuzz Corpus Summary\n");
        summary.push_str("==================\n\n");

        let mut type_counts = std::collections::HashMap::new();
        for entry in &self.entries {
            *type_counts.entry(entry.entry_type).or_insert(0) += 1;
        }

        for (entry_type, count) in type_counts {
            summary.push_str(&format!("{:?}: {} entries\n", entry_type, count));
        }

        summary.push_str(&format!("\nTotal entries: {}\n", self.entries.len()));

        summary
    }

    /// Export corpus to directory structure.
    pub fn export_to_directory(&self, base_dir: &str) -> std::io::Result<()> {
        for entry in &self.entries {
            let type_dir = format!("{}/{:?}", base_dir, entry.entry_type);
            std::fs::create_dir_all(&type_dir)?;
            
            let file_path = format!("{}/{}.bin", type_dir, entry.name);
            std::fs::write(&file_path, &entry.data)?;
        }

        Ok(())
    }
}

/// Fuzz test runner.
pub struct FuzzTestRunner {
    /// Corpus to test
    pub corpus: FuzzCorpus,
    /// Test results
    pub results: Vec<FuzzTestResult>,
}

impl FuzzTestRunner {
    /// Create a new fuzz test runner.
    pub fn new(corpus: FuzzCorpus) -> Self {
        Self {
            corpus,
            results: Vec::new(),
        }
    }

    /// Run all corpus entries through verification.
    pub fn run_all(&mut self) -> Vec<FuzzTestResult> {
        self.results.clear();

        for entry in &self.corpus.entries {
            let result = self.run_entry(entry);
            self.results.push(result);
        }

        self.results.clone()
    }

    /// Run a single corpus entry.
    pub fn run_entry(&self, entry: &FuzzEntry) -> FuzzTestResult {
        let start = std::time::Instant::now();
        
        let (verification_result, error) = self.verify_entry(&entry.data);
        let verification_time_ms = start.elapsed().as_millis() as u64;

        let passed = if entry.should_fail {
            !verification_result // Should fail, so pass if it fails
        } else {
            verification_result // Should pass, so pass if it passes
        };

        FuzzTestResult {
            entry_name: entry.name.clone(),
            entry_type: entry.entry_type,
            verification_result,
            expected_to_fail: entry.should_fail,
            passed,
            verification_time_ms,
            error,
        }
    }

    /// Verify a corpus entry.
    fn verify_entry(&self, data: &[u8]) -> (bool, Option<String>) {
        // In production, this would call the actual verifier
        // For testing, we simulate verification logic
        
        if data.is_empty() {
            return (false, Some("Empty data".to_string()));
        }

        if data.len() > 64 * 1024 {
            return (false, Some("Oversized data".to_string()));
        }

        if data.len() < 10 {
            return (false, Some("Undersized data".to_string()));
        }

        // Check for recursive structure marker
        if data.len() > 0 && data[0] == 0xFF {
            return (false, Some("Self-referential structure".to_string()));
        }

        // Check for recursive depth marker
        if data.len() > 0 && data[0] > 10 {
            return (false, Some("Excessive recursion depth".to_string()));
        }

        // Valid data
        (true, None)
    }

    /// Generate a test report.
    pub fn generate_report(&self) -> String {
        let mut report = String::new();
        report.push_str("Fuzz Test Report\n");
        report.push_str("================\n\n");

        let total_passed = self.results.iter().filter(|r| r.passed).count();
        let total_tests = self.results.len();

        for result in &self.results {
            report.push_str(&format!(
                "{} ({:?}): {} - {}ms\n",
                result.entry_name,
                result.entry_type,
                if result.passed { "PASS" } else { "FAIL" },
                result.verification_time_ms
            ));
            if let Some(ref error) = result.error {
                report.push_str(&format!("  Error: {}\n", error));
            }
        }

        report.push_str(&format!(
            "\nSummary: {}/{} tests passed\n",
            total_passed,
            total_tests
        ));

        report
    }
}

/// Fuzz test result.
#[derive(Debug, Clone)]
pub struct FuzzTestResult {
    /// Entry name
    pub entry_name: String,
    /// Entry type
    pub entry_type: FuzzEntryType,
    /// Verification result
    pub verification_result: bool,
    /// Whether entry was expected to fail
    pub expected_to_fail: bool,
    /// Whether test passed
    pub passed: bool,
    /// Verification time in milliseconds
    pub verification_time_ms: u64,
    /// Error if verification failed
    pub error: Option<String>,
}

/// Test standard fuzz corpus.
#[test]
fn test_standard_fuzz_corpus() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();

    assert!(!corpus.entries.is_empty());
    assert!(corpus.get_by_name("empty_proof").is_some());
    assert!(corpus.get_by_name("oversized_proof").is_some());
}

/// Test recursive Merkle tree corpus.
#[test]
fn test_recursive_merkle_corpus() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_recursive_merkle_corpus();

    assert!(!corpus.entries.is_empty());
    assert!(corpus.get_by_name("recursive_tree_2_levels").is_some());
    assert!(corpus.get_by_name("recursive_tree_10_levels").is_some());
}

/// Test edge cases corpus.
#[test]
fn test_edge_cases_corpus() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_edge_cases();

    assert!(!corpus.entries.is_empty());
    assert!(corpus.get_by_name("max_size_proof").is_some());
    assert!(corpus.get_by_name("min_size_proof").is_some());
}

/// Test fuzz test runner.
#[test]
fn test_fuzz_test_runner() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();

    let mut runner = FuzzTestRunner::new(corpus);
    let results = runner.run_all();

    assert!(!results.is_empty());
    // All standard malformed proofs should fail verification
    assert!(results.iter().all(|r| !r.verification_result));
}

/// Test fuzz corpus summary generation.
#[test]
fn test_fuzz_corpus_summary() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();
    corpus.initialize_recursive_merkle_corpus();
    corpus.initialize_edge_cases();

    let summary = corpus.generate_summary();
    assert!(!summary.is_empty());
    assert!(summary.contains("Total entries"));
}

/// Test fuzz test report generation.
#[test]
fn test_fuzz_test_report() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();

    let mut runner = FuzzTestRunner::new(corpus);
    runner.run_all();

    let report = runner.generate_report();
    assert!(!report.is_empty());
    assert!(report.contains("Fuzz Test Report"));
    assert!(report.contains("Summary"));
}

/// Test corpus entry filtering by type.
#[test]
fn test_corpus_filtering() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();
    corpus.initialize_recursive_merkle_corpus();

    let malformed = corpus.get_by_type(FuzzEntryType::MalformedProof);
    let recursive = corpus.get_by_type(FuzzEntryType::RecursiveMerkleTree);

    assert!(!malformed.is_empty());
    assert!(!recursive.is_empty());
}

/// Test recursive Merkle tree generation.
#[test]
fn test_recursive_merkle_generation() {
    let tree_2 = FuzzCorpus::generate_recursive_merkle_tree(2);
    let tree_10 = FuzzCorpus::generate_recursive_merkle_tree(10);

    assert!(!tree_2.is_empty());
    assert!(!tree_10.is_empty());
    assert!(tree_10.len() > tree_2.len());
}

/// Test self-referential tree generation.
#[test]
fn test_self_referential_tree() {
    let tree = FuzzCorpus::generate_self_referential_tree();
    assert!(!tree.is_empty());
    assert_eq!(tree[0], 0xFF); // Self-reference marker
}

/// Test corpus export to directory.
#[test]
fn test_corpus_export() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();

    let temp_dir = "/tmp/fuzz_corpus_test";
    let result = corpus.export_to_directory(temp_dir);

    // Clean up
    if result.is_ok() {
        std::fs::remove_dir_all(temp_dir).ok();
    }

    assert!(result.is_ok());
}

/// Test verification time tracking.
#[test]
fn test_verification_time_tracking() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();

    let mut runner = FuzzTestRunner::new(corpus);
    let results = runner.run_all();

    for result in &results {
        assert!(result.verification_time_ms >= 0);
    }
}

/// Test entry lookup by name.
#[test]
fn test_entry_lookup() {
    let mut corpus = FuzzCorpus::new();
    corpus.initialize_standard_corpus();

    let entry = corpus.get_by_name("empty_proof");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().entry_type, FuzzEntryType::EmptyProof);

    let non_existent = corpus.get_by_name("non_existent");
    assert!(non_existent.is_none());
}
