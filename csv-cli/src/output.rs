//! Output formatting helpers

use colored::Colorize;

pub fn success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

pub fn error(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg);
}

pub fn warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}

pub fn danger(msg: &str) {
    eprintln!("{} {}", "☠".red().bold(), msg);
}

pub fn info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

pub fn header(title: &str) {
    println!("\n{}", title.bold().underline());
    println!("{}", "─".repeat(60).dimmed());
}

pub fn kv(key: &str, value: &str) {
    println!("  {:<25} {}", format!("{}:", key).bold(), value);
}

pub fn kv_hash(key: &str, hash: &[u8]) {
    println!(
        "  {:<25} {}",
        format!("{}:", key).bold(),
        hex::encode(hash).dimmed()
    );
}

pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print headers
    let header_line: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("  {:<width$}", h, width = widths[i]))
        .collect();
    println!("{}", header_line.bold());
    println!(
        "{}",
        "─"
            .repeat(widths.iter().sum::<usize>() + widths.len() * 2)
            .dimmed()
    );

    // Print rows
    for row in rows {
        let row_line: String = row
            .iter()
            .enumerate()
            .map(|(i, c)| format!("  {:<width$}", c, width = widths[i]))
            .collect();
        println!("{}", row_line);
    }
}

/// Print JSON or canonical CBOR hex depending on CLI flags.
pub fn emit<T: serde::Serialize>(data: &T, canonical: bool) {
    if canonical {
        match csv_hash::canonical::to_canonical_cbor(data) {
            Ok(bytes) => println!("{}", hex::encode(bytes)),
            Err(e) => error(&format!("canonical encode failed: {e}")),
        }
        return;
    }
    json(data);
}

/// Print proof bundle with optional DAG tree layout.
pub fn proof_tree<T: serde::Serialize>(data: &T, proof_tree: bool, canonical: bool) {
    if proof_tree {
        let wrapper = serde_json::json!({
            "proof_tree": {
                "format": "csv-proof-dag-v1",
                "root": data,
            }
        });
        emit(&wrapper, canonical);
        return;
    }
    emit(data, canonical);
}

pub fn json<T: serde::Serialize>(data: &T) {
    match serde_json::to_string_pretty(data) {
        Ok(s) => println!("{}", s),
        Err(e) => error(&format!("Failed to serialize: {}", e)),
    }
}

pub fn secret(msg: &str) {
    println!("  {} {}", "SECRET".red().bold(), msg.yellow());
    println!(
        "  {} Store this securely and never share it!",
        "WARNING".yellow().bold()
    );
}

pub fn progress(step: usize, total: usize, msg: &str) {
    let bar = format!("[{}/{}]", step, total).dimmed();
    println!("  {} {}", bar, msg);
}
