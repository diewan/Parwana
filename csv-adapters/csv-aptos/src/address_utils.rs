//! Aptos address parsing and formatting utilities
//!
//! This module provides centralized address parsing and formatting functions
//! to eliminate duplication across the codebase.

/// Format an Aptos address as hex string with "0x" prefix
pub fn format_address(addr: [u8; 32]) -> String {
    format!("0x{}", hex::encode(addr))
}

/// Parse an Aptos address string (e.g., "0x1" or "0xabc...")
///
/// Accepts both short forms (e.g., "0x1") and full 32-byte hex strings.
/// Short forms are left-padded with zeros to 32 bytes.
pub fn parse_aptos_address(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s.trim_start_matches("0x");
    
    // Reject addresses longer than 32 bytes (64 hex chars)
    if hex_str.len() > 64 {
        return Err(format!("Address too long: {} hex chars (max 64)", hex_str.len()));
    }
    
    let mut padded = String::new();
    
    // Left-pad with zeros to ensure 32-byte length
    for _ in 0..(64 - hex_str.len()) {
        padded.push('0');
    }
    padded.push_str(hex_str);
    
    hex::decode(&padded)
        .map_err(|e| format!("Invalid hex address: {}", e))
        .and_then(|bytes| {
            if bytes.len() != 32 {
                Err(format!("Address must be 32 bytes, got {}", bytes.len()))
            } else {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&bytes);
                Ok(addr)
            }
        })
}

/// Validate an Aptos address string without parsing
pub fn is_valid_address(s: &str) -> bool {
    parse_aptos_address(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_address() {
        let addr = [0x01; 32];
        let formatted = format_address(addr);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 66); // "0x" + 64 hex chars
    }

    #[test]
    fn test_parse_aptos_address_short() {
        let addr = parse_aptos_address("0x1").unwrap();
        assert_eq!(addr[31], 1);
        for (i, byte) in addr.iter().take(31).enumerate() {
            assert_eq!(*byte, 0, "Byte at index {} should be 0", i);
        }
    }

    #[test]
    fn test_parse_aptos_address_full() {
        let full = "0xdeadbeef00000000000000000000000000000000000000000000000000000001";
        let addr = parse_aptos_address(full).unwrap();
        assert_eq!(addr[0], 0xDE);
        assert_eq!(addr[1], 0xAD);
        assert_eq!(addr[31], 0x01);
    }

    #[test]
    fn test_parse_aptos_address_invalid_hex() {
        let result = parse_aptos_address("0xxyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aptos_address_too_long() {
        let too_long = "0xdeadbeef0000000000000000000000000000000000000000000000000000000001";
        let result = parse_aptos_address(too_long);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_address() {
        assert!(is_valid_address("0x1"));
        assert!(is_valid_address("0xdeadbeef00000000000000000000000000000000000000000000000000000001"));
        assert!(!is_valid_address("0xxyz"));
        assert!(!is_valid_address("invalid"));
    }

    #[test]
    fn test_format_parse_roundtrip() {
        let original = [0xAB, 0xCD, 0xEF];
        let mut full_addr = [0u8; 32];
        full_addr[0] = 0xAB;
        full_addr[1] = 0xCD;
        full_addr[2] = 0xEF;
        let formatted = format_address(full_addr);
        let parsed = parse_aptos_address(&formatted).unwrap();
        assert_eq!(full_addr, parsed);
    }
}
