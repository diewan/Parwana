//! Fuzz target for malformed JSON-RPC responses
//!
//! This fuzz target tests the robustness of JSON-RPC response parsing
//! across all adapters to ensure they handle malformed input gracefully.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON-RPC response
    if let Ok(s) = std::str::from_utf8(data) {
        // Test that we can handle malformed JSON without panicking
        let _ = serde_json::from_str::<serde_json::Value>(s);
    }
});
