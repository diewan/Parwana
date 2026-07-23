//! Generated public schemas for accountability transport surfaces.

use crate::Schema;

/// Names of the generated accountability schemas.
pub const ACCOUNTABILITY_SCHEMA_NAMES: &[&str] = &[
    "action-intent-wire",
    "canonical-accountability-object",
    "preservation-envelope",
];

/// Returns a versioned JSON Schema for a supported accountability wire type.
pub fn accountability_schema(name: &str) -> Option<Schema> {
    let definition = match name {
        "action-intent-wire" => include_str!("../schemas/action-intent-wire-v1.json"),
        "canonical-accountability-object" => {
            include_str!("../schemas/canonical-accountability-object-v1.json")
        }
        "preservation-envelope" => include_str!("../schemas/preservation-envelope-v1.json"),
        _ => return None,
    };
    Some(Schema {
        name: name.to_string(),
        version: "1".to_string(),
        definition: definition.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchemaRegistry;

    #[test]
    fn every_accountability_schema_compiles() {
        for name in ACCOUNTABILITY_SCHEMA_NAMES {
            let schema = accountability_schema(name).unwrap();
            SchemaRegistry::new()
                .compile(&schema.name, &schema.version, &schema.definition)
                .unwrap();
        }
    }
}
