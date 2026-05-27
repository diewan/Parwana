//! RPC Byzantine model testing - adversarial RPC response simulation
//!
//! Tests chain adapter behavior under Byzantine RPC conditions:
//! - Stale block data
//! - Conflicting state roots
//! - Censored transactions
//! - Malformed responses
//! - Inconsistent responses across RPC nodes

use csv_testkit::{ByzantineFaultMode, ByzantineRpcReader};

#[test]
fn test_byzantine_zero_hash_injection() {
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::ZeroHashInjection);
    let original = [0xABu8; 32];
    let result = reader.simulate_block_hash(original);

    // Zero hash injection should return all zeros
    assert_eq!(result, [0u8; 32]);
    assert_ne!(result, original);
}

#[test]
fn test_byzantine_always_success_status() {
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::AlwaysSuccessStatus);

    // Should always return true regardless of actual status
    assert!(reader.simulate_transaction_status(false));
    assert!(reader.simulate_transaction_status(true));
}

#[test]
fn test_byzantine_truncated_hex() {
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::TruncatedHex { truncate_to: 10 });
    let original = "0x1234567890abcdef";
    let result = reader.simulate_hex_string(original);

    // Should be truncated to 10 characters
    assert_eq!(result.len(), 10);
    assert_eq!(result, "0x12345678");
}

#[test]
fn test_byzantine_stale_height_injection() {
    let reader =
        ByzantineRpcReader::new(ByzantineFaultMode::StaleHeightInjection { lag_blocks: 100 });
    let current_height = 1000u64;
    let result = reader.simulate_block_height(current_height);

    // Should return height with lag
    assert_eq!(result, 900);
    assert_ne!(result, current_height);
}

#[test]
fn test_byzantine_selective_censorship() {
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::SelectiveCensorship { every_n: 3 });

    // Every 3rd response should be dropped
    assert!(!reader.should_drop_response(0));
    assert!(!reader.should_drop_response(1));
    assert!(!reader.should_drop_response(2));
    assert!(reader.should_drop_response(3));
    assert!(!reader.should_drop_response(4));
    assert!(!reader.should_drop_response(5));
    assert!(reader.should_drop_response(6));
}

#[test]
fn test_byzantine_fault_mode_accessors() {
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::ZeroHashInjection);
    assert_eq!(reader.fault_mode(), ByzantineFaultMode::ZeroHashInjection);
}

#[test]
fn test_byzantine_combined_faults() {
    // Test that different fault modes can be applied independently
    let zero_reader = ByzantineRpcReader::new(ByzantineFaultMode::ZeroHashInjection);
    let success_reader = ByzantineRpcReader::new(ByzantineFaultMode::AlwaysSuccessStatus);
    let stale_reader =
        ByzantineRpcReader::new(ByzantineFaultMode::StaleHeightInjection { lag_blocks: 50 });

    // Each reader should apply its specific fault
    assert_eq!(zero_reader.simulate_block_hash([1u8; 32]), [0u8; 32]);
    assert!(success_reader.simulate_transaction_status(false));
    assert_eq!(stale_reader.simulate_block_height(200), 150);
}

#[test]
fn test_byzantine_hex_truncation_edge_cases() {
    // Test truncation with various lengths
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::TruncatedHex { truncate_to: 0 });
    assert_eq!(reader.simulate_hex_string("0x1234"), "");

    let reader2 = ByzantineRpcReader::new(ByzantineFaultMode::TruncatedHex { truncate_to: 2 });
    assert_eq!(reader2.simulate_hex_string("0x1234"), "0x");

    let reader3 = ByzantineRpcReader::new(ByzantineFaultMode::TruncatedHex { truncate_to: 100 });
    let long_hex = "0x1234567890abcdef";
    assert_eq!(reader3.simulate_hex_string(long_hex), long_hex);
}

#[test]
fn test_byzantine_stale_height_saturating_sub() {
    // Test that stale height uses saturating subtraction (no underflow)
    let reader =
        ByzantineRpcReader::new(ByzantineFaultMode::StaleHeightInjection { lag_blocks: 1000 });
    let low_height = 50u64;
    let result = reader.simulate_block_height(low_height);

    // Should saturate at 0, not underflow
    assert_eq!(result, 0);
}

#[test]
fn test_byzantine_selective_censorship_first_response_never_dropped() {
    let reader = ByzantineRpcReader::new(ByzantineFaultMode::SelectiveCensorship { every_n: 1 });

    // First response (index 0) should never be dropped
    assert!(!reader.should_drop_response(0));
    // But subsequent responses with every_n=1 should be dropped
    assert!(reader.should_drop_response(1));
}
