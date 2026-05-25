/// RPC-specific wire format conversions.
/// 
/// Each chain adapter implements TryFrom from its RPC types to csv-algebra types here.
/// This is the anti-corruption layer that prevents chain-specific semantics from leaking.

pub mod aptos;
pub mod ethereum;
pub mod solana;
pub mod bitcoin;
