//! Output formatting helpers

use colored::Colorize;
use std::io::Write;

/// Neutralize terminal controls in text that may originate in proofs, evidence,
/// provider responses, configuration, or error chains. Human output must never
/// let untrusted bytes move the cursor, alter the title, forge a new line, or
/// inject a color/style sequence.
fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            use std::fmt::Write as _;
            let _ = write!(safe, "\\u{{{:04x}}}", character as u32);
        } else {
            safe.push(character);
        }
    }
    safe
}

pub fn success(msg: &str) {
    println!("{} {}", "✓".green().bold(), terminal_safe(msg));
}

pub fn error(msg: &str) {
    let _ = std::io::stdout().flush();
    eprintln!("{} {}", "✗".red().bold(), terminal_safe(msg));
}

pub fn warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), terminal_safe(msg));
}

pub fn warn(msg: &str) {
    warning(msg);
}

pub fn danger(msg: &str) {
    eprintln!("{} {}", "☠".red().bold(), terminal_safe(msg));
}

pub fn info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), terminal_safe(msg));
}

pub fn header(title: &str) {
    println!("\n{}", terminal_safe(title).bold().underline());
    println!("{}", "─".repeat(60).dimmed());
}

pub fn kv(key: &str, value: &str) {
    println!(
        "  {:<25} {}",
        format!("{}:", terminal_safe(key)).bold(),
        terminal_safe(value)
    );
}

pub fn kv_hash(key: &str, hash: &[u8]) {
    println!(
        "  {:<25} {}",
        format!("{}:", key).bold(),
        hex::encode(hash).dimmed()
    );
}

pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let safe_headers: Vec<String> = headers.iter().map(|value| terminal_safe(value)).collect();
    let safe_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|value| terminal_safe(value)).collect())
        .collect();
    // Calculate column widths
    let mut widths: Vec<usize> = safe_headers.iter().map(|h| h.len()).collect();
    for row in &safe_rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print headers
    let header_line: String = safe_headers
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
    for row in &safe_rows {
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
    println!(
        "  {} {}",
        "SECRET".red().bold(),
        terminal_safe(msg).yellow()
    );
    println!(
        "  {} Store this securely and never share it!",
        "WARNING".yellow().bold()
    );
}

pub fn progress(step: usize, total: usize, msg: &str) {
    let bar = format!("[{}/{}]", step, total).dimmed();
    println!("  {} {}", bar, terminal_safe(msg));
}

#[cfg(test)]
mod tests {
    use super::terminal_safe;

    #[test]
    fn malicious_terminal_sequences_are_rendered_as_inert_text() {
        let malicious = "claim\x1b[2J\x1b]0;forged title\x07\rforged\nline\u{009b}31m";
        let safe = terminal_safe(malicious);
        assert_eq!(
            safe,
            "claim\\u{001b}[2J\\u{001b}]0;forged title\\u{0007}\\u{000d}forged\\u{000a}line\\u{009b}31m"
        );
        assert!(!safe.chars().any(char::is_control));
    }

    #[test]
    fn ordinary_unicode_operator_text_is_unchanged() {
        assert_eq!(terminal_safe("evidence ✓ — محفوظ"), "evidence ✓ — محفوظ");
    }
}
