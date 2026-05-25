#![no_std]
// If this file compiles, the algebra layer is pure.
// If any dependency requires std, this line produces a compile error.
// No README. No convention. Compiler-enforced.

extern crate alloc;

pub mod error;
pub mod finality;
pub mod proof;
pub mod replay;
pub mod state;
pub mod transfer;
