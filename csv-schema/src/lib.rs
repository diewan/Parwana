//! CSV Schema - Schema registry and validation
//!
//! This crate provides schema validation and registry for CSV protocol types.
//! Supports JSON Schema compilation, field-level validation, schema versioning,
//! diffing, and canonical schema hashing.

#![warn(missing_docs)]

pub mod registry;
pub mod validation;

// Re-exports
pub use registry::{
    CompiledSchema, FieldConstraint, FieldType, Schema, SchemaDiff, SchemaDiffOp, SchemaError,
    SchemaField, SchemaRegistry, ValidationError,
};
pub use validation::SchemaValidator;