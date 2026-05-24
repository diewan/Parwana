//! Schema validation
//!
//! This module provides schema validation utilities using the
//! registry's compiled schemas and field-level validation.

use crate::registry::{CompiledSchema, FieldConstraint, FieldType, ValidationError};

/// Schema validator wrapping a compiled schema
pub struct SchemaValidator {
    /// Compiled schema for validation
    compiled: CompiledSchema,
}

impl SchemaValidator {
    /// Create a new schema validator from a compiled schema
    pub fn new(compiled: CompiledSchema) -> Self {
        Self { compiled }
    }

    /// Get a reference to the compiled schema
    pub fn schema(&self) -> &CompiledSchema {
        &self.compiled
    }

    /// Validate JSON data against the compiled schema
    pub fn validate_json(&self, json_data: &str) -> Result<(), ValidationError> {
        let json_value: serde_json::Value = serde_json::from_str(json_data)
            .map_err(|e| ValidationError::JsonError(e.to_string()))?;

        let obj = json_value.as_object().ok_or_else(|| {
            ValidationError::TypeMismatch(
                "root".to_string(),
                "object".to_string(),
                json_value.to_string(),
            )
        })?;

        // Check for required fields
        for field in self.compiled.fields.values() {
            if field.required && !obj.contains_key(&field.name) {
                return Err(ValidationError::MissingField(field.name.clone()));
            }
        }

        // Validate each field
        for (name, value) in obj {
            let field = self.compiled.fields.get(name).ok_or_else(|| {
                ValidationError::InvalidValue(name.clone(), "Unknown field".to_string())
            })?;

            validate_field_value(name, value, &field.field_type, &field.constraints)?;
        }

        Ok(())
    }

    /// Validate a single JSON value against a field type
    pub fn validate_field_value(
        &self,
        name: &str,
        value: &serde_json::Value,
        field_type: &FieldType,
    ) -> Result<(), ValidationError> {
        validate_field_value(name, value, field_type, &[])
    }
}

/// Validate a single field value against its type and constraints
pub(crate) fn validate_field_value(
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
                    FieldConstraint::MinLength(min) => {
                        if s.len() < *min {
                            return Err(ValidationError::ConstraintViolation(
                                name.to_string(),
                                format!("Minimum length is {}, got {}", min, s.len()),
                            ));
                        }
                    }
                    FieldConstraint::MaxLength(max) => {
                        if s.len() > *max {
                            return Err(ValidationError::ConstraintViolation(
                                name.to_string(),
                                format!("Maximum length is {}, got {}", max, s.len()),
                            ));
                        }
                    }
                    FieldConstraint::Pattern(pattern) => {
                        if !s.contains(pattern.trim_matches('^').trim_matches('$')) {
                            return Err(ValidationError::ConstraintViolation(
                                name.to_string(),
                                format!("Does not match pattern: {}", pattern),
                            ));
                        }
                    }
                    FieldConstraint::Allowed(allowed) => {
                        if !allowed.contains(&s.to_string()) {
                            return Err(ValidationError::ConstraintViolation(
                                name.to_string(),
                                format!("Value '{}' is not in allowed set", s),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        FieldType::Integer => {
            if !value.is_u64() && !value.is_i64() && !value.is_f64() {
                return Err(ValidationError::TypeMismatch(
                    name.to_string(),
                    "integer".to_string(),
                    value.to_string(),
                ));
            }
            if let Some(num) = value.as_u64() {
                for constraint in constraints {
                    match constraint {
                        FieldConstraint::MinValue(min) => {
                            if num < *min {
                                return Err(ValidationError::ConstraintViolation(
                                    name.to_string(),
                                    format!("Minimum value is {}, got {}", min, num),
                                ));
                            }
                        }
                        FieldConstraint::MaxValue(max) => {
                            if num > *max {
                                return Err(ValidationError::ConstraintViolation(
                                    name.to_string(),
                                    format!("Maximum value is {}, got {}", max, num),
                                ));
                            }
                        }
                        _ => {}
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{CompiledSchema, SchemaField};
    use std::collections::HashMap;

    fn make_test_schema() -> CompiledSchema {
        let mut fields = HashMap::new();
        fields.insert(
            "name".to_string(),
            SchemaField {
                name: "name".to_string(),
                field_type: FieldType::String,
                required: true,
                constraints: vec![
                    FieldConstraint::MinLength(1),
                    FieldConstraint::MaxLength(100),
                ],
                description: None,
            },
        );
        fields.insert(
            "age".to_string(),
            SchemaField {
                name: "age".to_string(),
                field_type: FieldType::Integer,
                required: true,
                constraints: vec![FieldConstraint::MinValue(0), FieldConstraint::MaxValue(150)],
                description: None,
            },
        );
        CompiledSchema {
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            fields,
            field_order: vec!["name".to_string(), "age".to_string()],
            schema_hash: "abc".to_string(),
        }
    }

    #[test]
    fn test_validator_valid() {
        let compiled = make_test_schema();
        let validator = SchemaValidator::new(compiled);
        assert!(
            validator
                .validate_json(r#"{"name": "Alice", "age": 30}"#)
                .is_ok()
        );
    }

    #[test]
    fn test_validator_missing_required() {
        let compiled = make_test_schema();
        let validator = SchemaValidator::new(compiled);
        let result = validator.validate_json(r#"{"name": "Alice"}"#);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingField(_)
        ));
    }

    #[test]
    fn test_validator_wrong_type() {
        let compiled = make_test_schema();
        let validator = SchemaValidator::new(compiled);
        let result = validator.validate_json(r#"{"name": "Alice", "age": "thirty"}"#);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::TypeMismatch(..)
        ));
    }
}
