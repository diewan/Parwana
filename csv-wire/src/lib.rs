//! Wire encoding and transport layer.
//!
//! This crate owns ALL serde, ALL transport encoding, and ALL RPC wire format conversions.
//! It depends on csv-algebra. The inverse is forbidden by deny.toml.

pub mod canonical;
pub mod consignment;
pub mod hexbytes;
pub mod invoice;
pub mod primitives;
pub mod proof;
pub mod rpc;
pub mod seal;
pub mod transfer;
pub mod transfer_state;

pub use canonical::CanonicalProofWire;
pub use consignment::{CONSIGNMENT_VERSION, Consignment};
pub use invoice::{INVOICE_VERSION, Invoice};
pub use primitives::{CommitmentWire, HashWire, SanadIdWire};
pub use proof::ProofBundleWire;
pub use seal::{SealDefinition, SealPointWire};
pub use transfer::TransferWire;
pub use transfer_state::{
    AwaitingFinalityWire, LockedWire, ProofBuildingWire, ProofValidatedWire, TransferDataWire,
};
