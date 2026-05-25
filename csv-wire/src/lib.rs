/// Wire encoding and transport layer.
/// 
/// This crate owns ALL serde, ALL transport encoding, and ALL RPC wire format conversions.
/// It depends on csv-algebra. The inverse is forbidden by deny.toml.

pub mod canonical;
pub mod proof;
pub mod transfer;
pub mod rpc;
