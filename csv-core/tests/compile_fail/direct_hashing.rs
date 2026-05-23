//! Compile-fail test: Direct hashing forbidden
//!
//! This test ensures that direct hashing calls are caught at compile time.
//! All hashing must go through DomainSeparatedHash.

use sha2::{Digest, Sha256};

fn main() {
    let data = b"test data";
    
    // This should fail to compile - direct Sha256::digest is forbidden
    let hash = Sha256::digest(data); // ERROR: forbidden pattern
    
    // This should fail to compile - direct Sha256::new is forbidden
    let mut hasher = Sha256::new(); // ERROR: forbidden pattern
    hasher.update(data);
}
