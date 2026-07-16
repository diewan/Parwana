//! CSV Schema - Schema registry and validation
//!
//! This crate provides schema validation and registry for Parwana types.
//! Supports JSON Schema compilation, field-level validation, schema versioning,
//! diffing, and canonical schema hashing.

#![warn(missing_docs)]

pub mod accountability;
pub mod registry;
pub mod validation;

// Re-exports
pub use accountability::{ACCOUNTABILITY_SCHEMA_NAMES, accountability_schema};
pub use registry::{
    CompiledSchema, FieldConstraint, FieldType, Schema, SchemaDiff, SchemaDiffOp, SchemaError,
    SchemaField, SchemaRegistry, ValidationError,
};
pub use validation::SchemaValidator;
