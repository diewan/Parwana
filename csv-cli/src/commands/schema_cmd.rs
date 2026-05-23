//! Schema tooling (`csv schema validate|compile|diff`).

use anyhow::{Context, Result};
use clap::Subcommand;
use csv_schema::{Schema, SchemaRegistry};
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum SchemaAction {
    /// Validate a schema JSON file (parses and compiles)
    Validate {
        /// Path to schema JSON (`name`, `version`, `definition`)
        #[arg(long)]
        file: PathBuf,
    },
    /// Compile schema to canonical hashed form
    Compile {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Diff two schema versions (same `name`, different `version`)
    Diff {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
    },
}

pub fn execute(action: SchemaAction) -> Result<()> {
    match action {
        SchemaAction::Validate { file } => validate_schema(file),
        SchemaAction::Compile { file, out } => compile_schema(file, out),
        SchemaAction::Diff { left, right } => diff_schemas(left, right),
    }
}

fn load_schema(path: &PathBuf) -> Result<Schema> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).context("parse schema JSON")
}

fn validate_schema(file: PathBuf) -> Result<()> {
    let schema = load_schema(&file)?;
    let reg = SchemaRegistry::new();
    reg.compile(&schema.name, &schema.version, &schema.definition)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("schema valid: {} v{}", schema.name, schema.version);
    Ok(())
}

fn compile_schema(file: PathBuf, out: Option<PathBuf>) -> Result<()> {
    let schema = load_schema(&file)?;
    let reg = SchemaRegistry::new();
    let compiled = reg
        .compile(&schema.name, &schema.version, &schema.definition)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let json = serde_json::to_string_pretty(&compiled).context("serialize compiled schema")?;
    if let Some(path) = out {
        fs::write(&path, &json).with_context(|| format!("write {}", path.display()))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

fn diff_schemas(left: PathBuf, right: PathBuf) -> Result<()> {
    let a = load_schema(&left)?;
    let b = load_schema(&right)?;
    anyhow::ensure!(
        a.name == b.name,
        "schema diff requires the same name ({} vs {})",
        a.name,
        b.name
    );
    let mut reg = SchemaRegistry::new();
    reg.register(a.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    reg.register(b.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let diff = reg
        .diff(&a.name, &a.version, &b.version)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", serde_json::to_string_pretty(&diff)?);
    Ok(())
}
