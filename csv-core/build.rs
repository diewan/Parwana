//! Build script to generate version constants from Cargo.toml
//!
//! This ensures all version strings come from a single source of truth:
//! the workspace Cargo.toml [workspace.package] version field.

#![allow(clippy::use_debug)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    // Tell cargo to rerun if Cargo.toml changes
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Get the workspace root
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .ok_or("CARGO_MANIFEST_DIR has no parent directory")?;
    let workspace_cargo_toml = workspace_root.join("Cargo.toml");

    // Read workspace version
    let version = if workspace_cargo_toml.exists() {
        let content = fs::read_to_string(&workspace_cargo_toml)?;
        parse_version_from_toml(&content).unwrap_or(env::var("CARGO_PKG_VERSION")?)
    } else {
        // Fallback: use CARGO_PKG_VERSION
        env::var("CARGO_PKG_VERSION")?
    };

    // Parse version components
    let parts: Vec<&str> = version.split('.').collect();
    let major = parts
        .first()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let patch = parts
        .get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    // Generate version.rs
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir).join("version.rs");

    let version_code = format!(
        r#"// Auto-generated version constants
// Generated from workspace Cargo.toml version = "{}"

/// The current protocol version as a string (e.g., "0.3.0")
pub const PROTOCOL_VERSION_STR: &str = "{}";

/// The current protocol version as a string (with 'v' prefix, e.g., "v0.3.0")
pub const PROTOCOL_VERSION_DISPLAY: &str = "v{}";

/// Major version number
pub const VERSION_MAJOR: u32 = {};

/// Minor version number
pub const VERSION_MINOR: u32 = {};

/// Patch version number
pub const VERSION_PATCH: u32 = {};

/// Full version components
pub const VERSION: (u32, u32, u32) = ({}, {}, {});

/// The current deprecation marker for features deprecated in this version
pub const DEPRECATION_SINCE: &str = "{}";

/// Example version string for documentation/examples
pub const EXAMPLE_VERSION: &str = "{}";
"#,
        version, version, version, major, minor, patch, major, minor, patch, version, version
    );

    fs::write(&dest_path, version_code)?;

    // Also emit as cargo environment variable for dependent crates
    println!("cargo:rustc-env=CSV_PROTOCOL_VERSION={}", version);

    Ok(())
}

fn parse_version_from_toml(content: &str) -> Option<String> {
    content
        .lines()
        .find(|line| line.trim().starts_with("version ="))
        .and_then(|line| line.split('"').nth(1).map(|s| s.to_string()))
}
