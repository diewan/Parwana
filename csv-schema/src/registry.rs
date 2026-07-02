//! Schema registry
//!
//! This module provides a registry for CSV protocol schemas with
//! version management, schema compilation, and diffing capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Schema field type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    /// String type
    String,
    /// Integer type (u64)
    Integer,
    /// Boolean type
    Boolean,
    /// Bytes type (hex-encoded)
    Bytes,
    /// Hash type (32-byte hex)
    Hash,
    /// Array of a specific type
    Array(Box<FieldType>),
    /// Object with nested fields
    Object(HashMap<String, FieldType>),
    /// Optional type (nullable)
    Optional(Box<FieldType>),
    /// Enum with allowed values
    Enum(Vec<String>),
}

/// Field constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldConstraint {
    /// Minimum length for strings
    MinLength(usize),
    /// Maximum length for strings
    MaxLength(usize),
    /// Minimum value for integers
    MinValue(u64),
    /// Maximum value for integers
    MaxValue(u64),
    /// Pattern for strings (regex)
    Pattern(String),
    /// Enum of allowed values
    Allowed(Vec<String>),
}

/// Schema field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct SchemaField {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Whether the field is required
    pub required: bool,
    /// Field constraints
    pub constraints: Vec<FieldConstraint>,
    /// Field description
    pub description: Option<String>,
}

/// Compiled schema (internal representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct CompiledSchema {
    /// Schema name
    pub name: String,
    /// Schema version
    pub version: String,
    /// Fields keyed by name
    pub fields: HashMap<String, SchemaField>,
    /// Field ordering
    pub field_order: Vec<String>,
    /// Schema hash (canonical hash of the schema definition)
    pub schema_hash: String,
}

/// Schema definition (user-facing)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct Schema {
    /// Schema name
    pub name: String,
    /// Schema version
    pub version: String,
    /// Schema definition (JSON Schema or custom format)
    pub definition: String,
}

/// Schema diff operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum SchemaDiffOp {
    /// Field added
    FieldAdded { name: String, field_type: FieldType },
    /// Field removed
    FieldRemoved { name: String },
    /// Field type changed
    FieldTypeChanged {
        name: String,
        old_type: FieldType,
        new_type: FieldType,
    },
    /// Field constraint changed
    FieldConstraintChanged { name: String, constraint: String },
    /// Field required status changed
    FieldRequiredChanged {
        name: String,
        was_required: bool,
        now_required: bool,
    },
    /// Version bump
    VersionBump {
        old_version: String,
        new_version: String,
    },
}

/// Schema diff result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    /// List of changes
    pub changes: Vec<SchemaDiffOp>,
    /// Whether the change is backward compatible
    pub is_backward_compatible: bool,
    /// Summary of the diff
    pub summary: String,
}

/// Schema registry with version management
pub struct SchemaRegistry {
    /// Registered schemas keyed by name
    schemas: HashMap<String, Vec<Schema>>,
    /// Compiled schemas keyed by name
    compiled: HashMap<String, Vec<CompiledSchema>>,
}

impl SchemaRegistry {
    /// Create a new schema registry
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
            compiled: HashMap::new(),
        }
    }

    /// Register a schema
    pub fn register(&mut self, schema: Schema) -> Result<(), SchemaError> {
        // Validate the schema definition
        if schema.name.is_empty() {
            return Err(SchemaError::InvalidName(
                "Schema name cannot be empty".to_string(),
            ));
        }
        if schema.version.is_empty() {
            return Err(SchemaError::InvalidVersion(
                "Schema version cannot be empty".to_string(),
            ));
        }

        // Try to compile the schema
        let compiled = compile_schema_definition(&schema)?;

        self.schemas
            .entry(schema.name.clone())
            .or_default()
            .push(schema);
        self.compiled
            .entry(compiled.name.clone())
            .or_default()
            .push(compiled);

        Ok(())
    }

    /// Get a schema by name (latest version)
    pub fn get(&self, name: &str) -> Option<&Schema> {
        self.schemas.get(name).and_then(|versions| versions.last())
    }

    /// Get a schema by name and version
    pub fn get_version(&self, name: &str, version: &str) -> Option<&Schema> {
        self.schemas
            .get(name)?
            .iter()
            .find(|s| s.version == version)
    }

    /// Get compiled schema by name (latest version)
    pub fn get_compiled(&self, name: &str) -> Option<&CompiledSchema> {
        self.compiled.get(name).and_then(|versions| versions.last())
    }

    /// Get compiled schema by name and version
    pub fn get_compiled_version(&self, name: &str, version: &str) -> Option<&CompiledSchema> {
        self.compiled
            .get(name)?
            .iter()
            .find(|s| s.version == version)
    }

    /// List all registered schemas
    pub fn list(&self) -> Vec<&Schema> {
        self.schemas
            .values()
            .flat_map(|versions| versions.iter())
            .collect()
    }

    /// List schema names
    pub fn list_names(&self) -> Vec<String> {
        self.schemas.keys().cloned().collect()
    }

    /// List versions of a schema
    pub fn list_versions(&self, name: &str) -> Vec<String> {
        self.schemas
            .get(name)
            .map(|versions| versions.iter().map(|s| s.version.clone()).collect())
            .unwrap_or_default()
    }

    /// Compile a schema from raw JSON Schema
    pub fn compile(
        &self,
        name: &str,
        version: &str,
        json_schema: &str,
    ) -> Result<CompiledSchema, SchemaError> {
        let schema = Schema {
            name: name.to_string(),
            version: version.to_string(),
            definition: json_schema.to_string(),
        };
        compile_schema_definition(&schema)
    }

    /// Diff two schema versions
    pub fn diff(
        &self,
        name: &str,
        version_a: &str,
        version_b: &str,
    ) -> Result<SchemaDiff, SchemaError> {
        let schema_a = self
            .get_version(name, version_a)
            .ok_or_else(|| SchemaError::VersionNotFound(name.to_string(), version_a.to_string()))?;
        let schema_b = self
            .get_version(name, version_b)
            .ok_or_else(|| SchemaError::VersionNotFound(name.to_string(), version_b.to_string()))?;

        let compiled_a = compile_schema_definition(schema_a)?;
        let compiled_b = compile_schema_definition(schema_b)?;

        diff_compiled_schemas(&compiled_a, &compiled_b)
    }

    /// Validate data against a schema
    pub fn validate(&self, name: &str, data: &str) -> Result<(), ValidationError> {
        let compiled = self
            .get_compiled(name)
            .ok_or_else(|| ValidationError::SchemaNotFound(name.to_string()))?;
        validate_against_compiled(compiled, data)
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema registry error
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// Invalid schema name
    #[error("Invalid schema name: {0}")]
    InvalidName(String),
    /// Invalid schema version
    #[error("Invalid schema version: {0}")]
    InvalidVersion(String),
    /// Schema not found
    #[error("Schema not found: {0}")]
    NotFound(String),
    /// Version not found
    #[error("Version '{1}' not found for schema '{0}'")]
    VersionNotFound(String, String),
    /// Invalid schema definition
    #[error("Invalid schema definition: {0}")]
    InvalidDefinition(String),
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Validation error
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// Schema not found
    #[error("Schema not found: {0}")]
    SchemaNotFound(String),
    /// Type mismatch
    #[error("Type mismatch for field '{0}': expected {1}, got {2}")]
    TypeMismatch(String, String, String),
    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
    /// Invalid value
    #[error("Invalid value for field '{0}': {1}")]
    InvalidValue(String, String),
    /// Constraint violation
    #[error("Constraint violation for field '{0}': {1}")]
    ConstraintViolation(String, String),
    /// JSON parse error
    #[error("JSON parse error: {0}")]
    JsonError(String),
}

// ============================================================
// Schema compilation
// ============================================================

/// Compile a schema definition into a compiled schema
fn compile_schema_definition(schema: &Schema) -> Result<CompiledSchema, SchemaError> {
    // Try to parse as JSON Schema first
    let json_value: serde_json::Value = serde_json::from_str(&schema.definition).map_err(|e| {
        SchemaError::ParseError(format!("Failed to parse schema definition: {}", e))
    })?;

    let fields = if let Some(properties) = json_value.get("properties").and_then(|v| v.as_object())
    {
        let mut fields = HashMap::new();
        let mut field_order = Vec::new();
        let required_fields: Vec<String> = json_value
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for (name, prop) in properties {
            let field_type = json_value_to_field_type(prop)?;
            let constraints = extract_constraints(prop);
            let required = required_fields.contains(name);

            fields.insert(
                name.clone(),
                SchemaField {
                    name: name.clone(),
                    field_type,
                    required,
                    constraints,
                    description: prop
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                },
            );
            field_order.push(name.clone());
        }

        fields
    } else {
        HashMap::new()
    };

    // Compute schema hash from the canonical definition
    let hash_input = format!("{}:{}:{}", schema.name, schema.version, schema.definition);
    let schema_hash = hex::encode(sha256_hash(hash_input.as_bytes()));

    let field_order: Vec<String> = fields.keys().cloned().collect();

    Ok(CompiledSchema {
        name: schema.name.clone(),
        version: schema.version.clone(),
        fields,
        field_order,
        schema_hash,
    })
}

/// Convert a JSON Schema property to a FieldType
fn json_value_to_field_type(value: &serde_json::Value) -> Result<FieldType, SchemaError> {
    match value.get("type").and_then(|v| v.as_str()) {
        Some("string") => {
            if let Some(format) = value.get("format").and_then(|v| v.as_str()) {
                match format {
                    "hash" => Ok(FieldType::Hash),
                    "bytes" => Ok(FieldType::Bytes),
                    _ => Ok(FieldType::String),
                }
            } else if let Some(enum_values) = value.get("enum").and_then(|v| v.as_array()) {
                let variants: Vec<String> = enum_values
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                Ok(FieldType::Enum(variants))
            } else {
                Ok(FieldType::String)
            }
        }
        Some("integer") | Some("number") => Ok(FieldType::Integer),
        Some("boolean") => Ok(FieldType::Boolean),
        Some("array") => {
            let items = value.get("items").ok_or_else(|| {
                SchemaError::InvalidDefinition("Array type must have items definition".to_string())
            })?;
            let inner = json_value_to_field_type(items)?;
            Ok(FieldType::Array(Box::new(inner)))
        }
        Some("object") => {
            let mut fields = HashMap::new();
            if let Some(properties) = value.get("properties").and_then(|v| v.as_object()) {
                for (name, prop) in properties {
                    let field_type = json_value_to_field_type(prop)?;
                    fields.insert(name.clone(), field_type);
                }
            }
            Ok(FieldType::Object(fields))
        }
        Some(other) => Err(SchemaError::InvalidDefinition(format!(
            "Unsupported type: {}",
            other
        ))),
        None => {
            // Check for enum shorthand
            if let Some(enum_values) = value.get("enum").and_then(|v| v.as_array()) {
                let variants: Vec<String> = enum_values
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                Ok(FieldType::Enum(variants))
            } else {
                // Default to string
                Ok(FieldType::String)
            }
        }
    }
}

/// Extract constraints from a JSON Schema property
fn extract_constraints(value: &serde_json::Value) -> Vec<FieldConstraint> {
    let mut constraints = Vec::new();

    if let Some(min_length) = value.get("minLength").and_then(|v| v.as_u64()) {
        constraints.push(FieldConstraint::MinLength(min_length as usize));
    }
    if let Some(max_length) = value.get("maxLength").and_then(|v| v.as_u64()) {
        constraints.push(FieldConstraint::MaxLength(max_length as usize));
    }
    if let Some(minimum) = value.get("minimum").and_then(|v| v.as_u64()) {
        constraints.push(FieldConstraint::MinValue(minimum));
    }
    if let Some(maximum) = value.get("maximum").and_then(|v| v.as_u64()) {
        constraints.push(FieldConstraint::MaxValue(maximum));
    }
    if let Some(pattern) = value.get("pattern").and_then(|v| v.as_str()) {
        constraints.push(FieldConstraint::Pattern(pattern.to_string()));
    }
    if let Some(allowed) = value.get("enum").and_then(|v| v.as_array()) {
        let values: Vec<String> = allowed
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !values.is_empty() {
            constraints.push(FieldConstraint::Allowed(values));
        }
    }

    constraints
}

/// Validate data against a compiled schema
fn validate_against_compiled(compiled: &CompiledSchema, data: &str) -> Result<(), ValidationError> {
    let json_value: serde_json::Value =
        serde_json::from_str(data).map_err(|e| ValidationError::JsonError(e.to_string()))?;

    let obj = json_value.as_object().ok_or_else(|| {
        ValidationError::TypeMismatch(
            "root".to_string(),
            "object".to_string(),
            json_value.to_string(),
        )
    })?;

    // Check for required fields
    for field in compiled.fields.values() {
        if field.required && !obj.contains_key(&field.name) {
            return Err(ValidationError::MissingField(field.name.clone()));
        }
    }

    // Validate each field
    for (name, value) in obj {
        let field = compiled.fields.get(name).ok_or_else(|| {
            ValidationError::InvalidValue(name.clone(), "Unknown field".to_string())
        })?;

        validate_field_value(name, value, &field.field_type, &field.constraints)?;
    }

    Ok(())
}

/// Validate a single field value against its type and constraints
fn validate_field_value(
    name: &str,
    value: &serde_json::Value,
    field_type: &FieldType,
    constraints: &[FieldConstraint],
) -> Result<(), ValidationError> {
    match field_type {
        FieldType::String => {
            let s = value.as_str().ok_or_else(|| {
                ValidationError::TypeMismatch(
                    name.to_string(),
                    "string".to_string(),
                    value.to_string(),
                )
            })?;
            for constraint in constraints {
                match constraint {
                    FieldConstraint::MinLength(min) if s.len() < *min => {
                        return Err(ValidationError::ConstraintViolation(
                            name.to_string(),
                            format!("Minimum length is {}, got {}", min, s.len()),
                        ));
                    }
                    FieldConstraint::MaxLength(max) if s.len() > *max => {
                        return Err(ValidationError::ConstraintViolation(
                            name.to_string(),
                            format!("Maximum length is {}, got {}", max, s.len()),
                        ));
                    }
                    FieldConstraint::Pattern(pattern)
                        if !s.contains(pattern.trim_matches('^').trim_matches('$')) =>
                    {
                        return Err(ValidationError::ConstraintViolation(
                            name.to_string(),
                            format!("Does not match pattern: {}", pattern),
                        ));
                    }
                    FieldConstraint::Allowed(allowed) if !allowed.contains(&s.to_string()) => {
                        return Err(ValidationError::ConstraintViolation(
                            name.to_string(),
                            format!("Value '{}' is not in allowed set", s),
                        ));
                    }
                    _ => {}
                }
            }
        }
        FieldType::Integer => {
            if !value.is_u64() && !value.is_i64() {
                return Err(ValidationError::TypeMismatch(
                    name.to_string(),
                    "integer".to_string(),
                    value.to_string(),
                ));
            }
            let num = value.as_u64().unwrap_or(0);
            for constraint in constraints {
                match constraint {
                    FieldConstraint::MinValue(min) if num < *min => {
                        return Err(ValidationError::ConstraintViolation(
                            name.to_string(),
                            format!("Minimum value is {}, got {}", min, num),
                        ));
                    }
                    FieldConstraint::MaxValue(max) if num > *max => {
                        return Err(ValidationError::ConstraintViolation(
                            name.to_string(),
                            format!("Maximum value is {}, got {}", max, num),
                        ));
                    }
                    _ => {}
                }
            }
        }
        FieldType::Boolean => {
            if !value.is_boolean() {
                return Err(ValidationError::TypeMismatch(
                    name.to_string(),
                    "boolean".to_string(),
                    value.to_string(),
                ));
            }
        }
        FieldType::Bytes => {
            let s = value.as_str().ok_or_else(|| {
                ValidationError::TypeMismatch(
                    name.to_string(),
                    "bytes (hex string)".to_string(),
                    value.to_string(),
                )
            })?;
            // Validate hex encoding
            if s.len() % 2 != 0 {
                return Err(ValidationError::InvalidValue(
                    name.to_string(),
                    "Bytes must be hex-encoded with even length".to_string(),
                ));
            }
            hex::decode(s).map_err(|_| {
                ValidationError::InvalidValue(name.to_string(), "Invalid hex encoding".to_string())
            })?;
        }
        FieldType::Hash => {
            let s = value.as_str().ok_or_else(|| {
                ValidationError::TypeMismatch(
                    name.to_string(),
                    "hash (32-byte hex)".to_string(),
                    value.to_string(),
                )
            })?;
            if s.len() != 64 {
                return Err(ValidationError::InvalidValue(
                    name.to_string(),
                    format!("Hash must be 64 hex characters (32 bytes), got {}", s.len()),
                ));
            }
            hex::decode(s).map_err(|_| {
                ValidationError::InvalidValue(name.to_string(), "Invalid hex encoding".to_string())
            })?;
        }
        FieldType::Array(inner) => {
            let arr = value.as_array().ok_or_else(|| {
                ValidationError::TypeMismatch(
                    name.to_string(),
                    "array".to_string(),
                    value.to_string(),
                )
            })?;
            for (i, item) in arr.iter().enumerate() {
                let item_name = format!("{}[{}]", name, i);
                validate_field_value(&item_name, item, inner, &[])?;
            }
        }
        FieldType::Object(fields) => {
            let obj = value.as_object().ok_or_else(|| {
                ValidationError::TypeMismatch(
                    name.to_string(),
                    "object".to_string(),
                    value.to_string(),
                )
            })?;
            for (field_name, field_type) in fields {
                if let Some(field_value) = obj.get(field_name) {
                    let full_name = format!("{}.{}", name, field_name);
                    validate_field_value(&full_name, field_value, field_type, &[])?;
                }
            }
        }
        FieldType::Optional(inner) => {
            if !value.is_null() {
                validate_field_value(name, value, inner, constraints)?;
            }
        }
        FieldType::Enum(variants) => {
            let s = value.as_str().ok_or_else(|| {
                ValidationError::TypeMismatch(
                    name.to_string(),
                    format!("enum {:?}", variants),
                    value.to_string(),
                )
            })?;
            if !variants.contains(&s.to_string()) {
                return Err(ValidationError::InvalidValue(
                    name.to_string(),
                    format!(
                        "Value '{}' is not a valid enum variant. Allowed: {:?}",
                        s, variants
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Diff two compiled schemas
fn diff_compiled_schemas(
    a: &CompiledSchema,
    b: &CompiledSchema,
) -> Result<SchemaDiff, SchemaError> {
    let mut changes = Vec::new();
    let mut is_backward_compatible = true;

    // Check version
    if a.version != b.version {
        changes.push(SchemaDiffOp::VersionBump {
            old_version: a.version.clone(),
            new_version: b.version.clone(),
        });
    }

    // Check for removed fields (breaking change)
    for name in a.fields.keys() {
        if !b.fields.contains_key(name) {
            changes.push(SchemaDiffOp::FieldRemoved { name: name.clone() });
            is_backward_compatible = false;
        }
    }

    // Check for added and changed fields
    for (name, field_b) in &b.fields {
        match a.fields.get(name) {
            None => {
                // Field added — backward compatible if optional
                if field_b.required {
                    is_backward_compatible = false;
                }
                changes.push(SchemaDiffOp::FieldAdded {
                    name: name.clone(),
                    field_type: field_b.field_type.clone(),
                });
            }
            Some(field_a) => {
                // Check type change
                if field_a.field_type != field_b.field_type {
                    changes.push(SchemaDiffOp::FieldTypeChanged {
                        name: name.clone(),
                        old_type: field_a.field_type.clone(),
                        new_type: field_b.field_type.clone(),
                    });
                    is_backward_compatible = false;
                }

                // Check required status change
                if field_a.required != field_b.required {
                    changes.push(SchemaDiffOp::FieldRequiredChanged {
                        name: name.clone(),
                        was_required: field_a.required,
                        now_required: field_b.required,
                    });
                    if field_b.required && !field_a.required {
                        is_backward_compatible = false;
                    }
                }

                // Check constraint changes
                if field_a.constraints != field_b.constraints {
                    changes.push(SchemaDiffOp::FieldConstraintChanged {
                        name: name.clone(),
                        constraint: "Constraints modified".to_string(),
                    });
                }
            }
        }
    }

    let summary = if changes.is_empty() {
        "No changes".to_string()
    } else {
        let compatibility = if is_backward_compatible {
            "backward compatible"
        } else {
            "BREAKING CHANGE"
        };
        format!("{} change(s) detected ({})", changes.len(), compatibility)
    };

    Ok(SchemaDiff {
        changes,
        is_backward_compatible,
        summary,
    })
}

/// Simple SHA-256 hash for schema hashing
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_registration() {
        let mut registry = SchemaRegistry::new();
        let schema = Schema {
            name: "Sanad".to_string(),
            version: "1.0.0".to_string(),
            definition: r#"{
                "type": "object",
                "properties": {
                    "content_hash": { "type": "string", "format": "hash" },
                    "timestamp": { "type": "integer" },
                    "signer": { "type": "string" }
                },
                "required": ["content_hash", "timestamp"]
            }"#
            .to_string(),
        };

        assert!(registry.register(schema).is_ok());
        assert!(registry.get("Sanad").is_some());
        assert_eq!(registry.list_names(), vec!["Sanad"]);
    }

    #[test]
    fn test_schema_validation() {
        let mut registry = SchemaRegistry::new();
        let schema = Schema {
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            definition: r#"{
                "type": "object",
                "properties": {
                    "name": { "type": "string", "minLength": 1, "maxLength": 100 },
                    "age": { "type": "integer", "minimum": 0, "maximum": 150 },
                    "active": { "type": "boolean" },
                    "hash": { "type": "string", "format": "hash" }
                },
                "required": ["name", "age"]
            }"#
            .to_string(),
        };

        registry.register(schema).unwrap();

        // Valid data
        assert!(registry
            .validate(
                "Test",
                r#"{"name": "Alice", "age": 30, "active": true, "hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}"#
            )
            .is_ok());

        // Missing required field
        assert_eq!(
            registry.validate("Test", r#"{"name": "Alice"}"#),
            Err(ValidationError::MissingField("age".to_string()))
        );

        // Wrong type
        assert!(matches!(
            registry.validate("Test", r#"{"name": "Alice", "age": "thirty"}"#),
            Err(ValidationError::TypeMismatch(..))
        ));

        // Constraint violation
        assert!(matches!(
            registry.validate("Test", r#"{"name": "Alice", "age": 200}"#),
            Err(ValidationError::ConstraintViolation(..))
        ));
    }

    #[test]
    fn test_schema_diff() {
        let mut registry = SchemaRegistry::new();

        let v1 = Schema {
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            definition: r#"{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"}},"required":["name"]}"#.to_string(),
        };
        let v2 = Schema {
            name: "Test".to_string(),
            version: "2.0.0".to_string(),
            definition: r#"{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"integer"},"email":{"type":"string","format":"email"}},"required":["name","email"]}"#.to_string(),
        };

        registry.register(v1).unwrap();
        registry.register(v2).unwrap();

        let diff = registry.diff("Test", "1.0.0", "2.0.0").unwrap();
        assert!(!diff.changes.is_empty());
        assert!(!diff.is_backward_compatible); // email is required in v2
    }

    #[test]
    fn test_compile_schema() {
        let registry = SchemaRegistry::new();
        let compiled = registry
            .compile(
                "Sanad",
                "1.0.0",
                r#"{
                    "type": "object",
                    "properties": {
                        "content_hash": { "type": "string", "format": "hash" }
                    },
                    "required": ["content_hash"]
                }"#,
            )
            .unwrap();

        assert_eq!(compiled.name, "Sanad");
        assert_eq!(compiled.version, "1.0.0");
        assert!(!compiled.schema_hash.is_empty());
        assert!(compiled.fields.contains_key("content_hash"));
    }
}
