#!/usr/bin/env python3
"""
Build a minimal context pack for one atomic AI-agent ticket.

Usage:
    python3 development/agent-workflow/generate_context_pack.py \
        development/tickets/F-CODEC-001.md

Optional:
    --repo-root .
    --radius 30
    --no-occurrence-scan
    --output-dir development/agent-workflow/context_packs

No third-party Python dependencies are required. If ripgrep (`rg`) exists,
it is used; otherwise the script falls back to Python file scanning.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

MAX_FULL_FILE_CHARS = 80_000
MAX_OCCURRENCES_PER_PATTERN = 200
DEFAULT_RADIUS = 25


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_frontmatter(text: str) -> Tuple[Dict[str, object], str]:
    """Parse a very small YAML subset: flat scalars and simple lists."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text

    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}, text

    meta: Dict[str, object] = {}
    current_key: Optional[str] = None

    for raw in lines[1:end]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue

        item = re.match(r"^\s*-\s*(.*)$", raw)
        if item and current_key:
            meta.setdefault(current_key, [])
            assert isinstance(meta[current_key], list)
            value = strip_quotes(item.group(1))
            if value:
                meta[current_key].append(value)
            continue

        pair = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", raw)
        if pair:
            key, value = pair.group(1), pair.group(2).strip()
            if value == "":
                meta[key] = []
                current_key = key
            else:
                meta[key] = strip_quotes(value)
                current_key = None
            continue

    body = "\n".join(lines[end + 1 :])
    return meta, body


REQUIRED_TICKET_FIELDS: Tuple[str, ...] = (
    "target_file",
    "interface_files",
    "reference_file",
    "target_patterns",
    "forbidden_patterns",
    "verify_commands",
    "security_critical",
    "context_radius",
    "cross_boundary_check",
)

MAX_CONTEXT_PACK_TOKENS = 60_000


def lint_ticket_frontmatter(meta: Dict[str, object]) -> List[str]:
    """Check that the ticket declares the fields DEV-WORKFLOW-001 requires.

    Returns human-readable warnings rather than raising, so a stale/incomplete
    ticket still produces a usable (but flagged) context pack instead of
    blocking the agent entirely.
    """
    warnings: List[str] = []
    for field in REQUIRED_TICKET_FIELDS:
        if field not in meta:
            warnings.append(f"missing required field `{field}`")
            continue
        value = meta[field]
        if isinstance(value, list) and not any(str(v).strip() for v in value):
            warnings.append(f"field `{field}` is present but empty")
        elif isinstance(value, str) and not value.strip():
            warnings.append(f"field `{field}` is present but empty")
    return warnings


def meta_str(meta: Dict[str, object], key: str, default: str = "") -> str:
    val = meta.get(key, default)
    if isinstance(val, list):
        return default
    return str(val)


def meta_bool(meta: Dict[str, object], key: str, default: bool = False) -> bool:
    val = meta.get(key, default)
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"true", "yes", "1", "on"}


def meta_list(meta: Dict[str, object], key: str) -> List[str]:
    val = meta.get(key, [])
    if isinstance(val, list):
        return [str(v).strip() for v in val if str(v).strip()]
    if isinstance(val, str) and val.strip():
        return [val.strip()]
    return []


def have_rg() -> bool:
    try:
        subprocess.run(["rg", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return True
    except FileNotFoundError:
        return False


HAS_RG = have_rg()


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def load_file_limited(path: Path, repo_root: Path) -> str:
    if not path.exists():
        return f"[missing file: {rel(path, repo_root)}]"
    text = read_text(path)
    if len(text) <= MAX_FULL_FILE_CHARS:
        return text
    half = MAX_FULL_FILE_CHARS // 2
    return text[:half] + "\n\n[... file truncated by context-pack generator ...]\n\n" + text[-half:]


def guess_lang(path: str) -> str:
    ext = Path(path).suffix.lstrip(".")
    return {
        "rs": "rust",
        "toml": "toml",
        "md": "markdown",
        "py": "python",
        "sh": "bash",
        "ts": "typescript",
        "sol": "solidity",
        "move": "move",
    }.get(ext, "text")


def numbered_snippet_from_text(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    start = max(start, 1)
    end = min(end, len(lines))
    width = len(str(end))
    return "\n".join(f"{i:{width}d}: {lines[i-1]}" for i in range(start, end + 1))


def find_literal_in_file(path: Path, pattern: str, radius: int) -> Optional[Tuple[int, str]]:
    if not path.exists():
        return None
    text = read_text(path)
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if pattern in line:
            start = max(1, idx - radius)
            end = min(len(lines), idx + radius)
            return idx, numbered_snippet_from_text(text, start, end)
    return None


def iter_source_files(root: Path) -> Iterable[Path]:
    ignored_dirs = {".git", "target", "node_modules", "dist", "pkg", "public", "assets"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignored_dirs]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix in {".rs", ".md", ".toml", ".move", ".sol", ".ts", ".py", ".sh"}:
                yield path


def occurrence_scan(repo_root: Path, pattern: str) -> List[str]:
    if not pattern:
        return []
    if HAS_RG:
        try:
            result = subprocess.run(
                ["rg", "-n", "-F", "--no-heading", pattern, str(repo_root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
            lines = [line for line in result.stdout.splitlines() if line.strip()]
            normalized = []
            for line in lines[:MAX_OCCURRENCES_PER_PATTERN]:
                normalized.append(line.replace(str(repo_root) + os.sep, ""))
            if len(lines) > MAX_OCCURRENCES_PER_PATTERN:
                normalized.append(f"[truncated: {len(lines) - MAX_OCCURRENCES_PER_PATTERN} more occurrences]")
            return normalized
        except Exception:
            pass

    hits: List[str] = []
    for path in iter_source_files(repo_root):
        try:
            for i, line in enumerate(read_text(path).splitlines(), start=1):
                if pattern in line:
                    hits.append(f"{rel(path, repo_root)}:{i}:{line.strip()}")
                    if len(hits) >= MAX_OCCURRENCES_PER_PATTERN:
                        hits.append("[truncated]")
                        return hits
        except OSError:
            continue
    return hits


def default_agent_file(repo_root: Path, crate: str, explicit: str) -> Optional[str]:
    candidates: List[str] = []
    if explicit:
        candidates.append(explicit)
    if crate.startswith("csv-adapters/"):
        candidates.append("csv-adapters/.agents/AGENT.md")
    if crate:
        candidates.append(f"{crate}/.agents/AGENT.md")
    candidates.extend([".agents/AGENT.md", "AGENTS.md"])
    for candidate in candidates:
        if (repo_root / candidate).exists():
            return candidate
    return None


def git_rev(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return result.stdout.strip() or "not-a-git-repo"
    except Exception:
        return "not-a-git-repo"


def add_file_section(sections: List[str], title: str, repo_root: Path, file_path: str) -> None:
    if not file_path:
        return
    path = repo_root / file_path
    lang = guess_lang(file_path)
    sections.append(f"## {title}: `{file_path}`\n\n```{lang}\n{load_file_limited(path, repo_root)}\n```")


def add_target_section(
    sections: List[str],
    repo_root: Path,
    title: str,
    file_path: str,
    patterns: List[str],
    radius: int,
) -> None:
    if not file_path:
        return
    path = repo_root / file_path
    lang = guess_lang(file_path)
    text_parts = [f"## {title}: `{file_path}`"]
    if not path.exists():
        text_parts.append(f"\n[missing target file: `{file_path}`]")
        sections.append("\n".join(text_parts))
        return

    if not patterns:
        text_parts.append(f"\nNo `target_patterns` supplied; including full file up to generator limit.\n\n```{lang}\n{load_file_limited(path, repo_root)}\n```")
    else:
        for pattern in patterns:
            found = find_literal_in_file(path, pattern, radius)
            text_parts.append(f"\n### Pattern: `{pattern}`")
            if found:
                line_no, snippet = found
                text_parts.append(f"Found near line {line_no}.\n\n```{lang}\n{snippet}\n```")
            else:
                text_parts.append("Not found in this file. The backlog may be stale or this item may already be fixed. Verify before editing.")
    sections.append("\n".join(text_parts))


def _scan_pre_existing_errors(repo_root: Path, crate: str, verify_cmds: List[str]) -> List[str]:
    """Run cargo check/test on the target crate and capture pre-existing errors.

    Returns a list of error lines that exist before the agent starts working.
    """
    if not crate:
        return []

    errors: List[str] = []

    # Run cargo check on the target crate
    try:
        result = subprocess.run(
            ["cargo", "check", "-p", crate, "--all-features"],
            cwd=str(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
        if result.returncode != 0:
            # Extract error lines (filter out warnings and info)
            for line in result.stderr.splitlines():
                if "error[" in line or "error:" in line or "E0" in line:
                    errors.append(line.strip())
    except subprocess.TimeoutExpired:
        errors.append("[cargo check timed out — agent should run it manually]")
    except Exception as e:
        errors.append(f"[cargo check failed: {e}]")

    # Also run cargo clippy if verify_commands includes it
    has_clippy = any("clippy" in cmd for cmd in verify_cmds)
    if has_clippy:
        try:
            result = subprocess.run(
                ["cargo", "clippy", "-p", crate, "--all-features", "--", "-D", "warnings"],
                cwd=str(repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=120,
            )
            if result.returncode != 0:
                for line in result.stderr.splitlines():
                    if "error[" in line or "error:" in line or "E0" in line or "clippy::" in line:
                        errors.append(line.strip())
        except Exception:
            pass

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for e in errors:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    return unique[:50]  # Cap at 50 lines to avoid context bloat


def build_context_pack(ticket_path: Path, repo_root: Path, radius_override: Optional[int], occurrence: bool) -> str:
    raw = read_text(ticket_path)
    meta, body = parse_frontmatter(raw)
    ticket_id = meta_str(meta, "id", ticket_path.stem)
    title = meta_str(meta, "title", "")
    crate = meta_str(meta, "crate", "")
    radius = radius_override if radius_override is not None else int(meta_str(meta, "context_radius", str(DEFAULT_RADIUS)) or DEFAULT_RADIUS)

    sections: List[str] = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections.append(
        "# Context Pack: {ticket_id}\n\n"
        "**Title:** {title}\n"
        "**Generated:** {timestamp}\n"
        "**Git revision:** `{rev}`\n"
        "**Crate:** `{crate}`\n"
        "**Priority:** `{priority}`\n"
        "**Security critical:** `{security}`\n"
        "**Model hint:** `{model}`\n".format(
            ticket_id=ticket_id,
            title=title,
            timestamp=timestamp,
            rev=git_rev(repo_root),
            crate=crate,
            priority=meta_str(meta, "priority", ""),
            security=meta_str(meta, "security_critical", "false"),
            model=meta_str(meta, "model_hint", "sonnet"),
        )
    )

    hygiene_warnings = lint_ticket_frontmatter(meta)
    if hygiene_warnings:
        sections.append(
            "## Ticket hygiene warnings\n\n"
            "DEV-WORKFLOW-001 requires every ticket to declare target_file, interface_files, "
            "reference_file, target_patterns, forbidden_patterns, verify_commands, security_critical, "
            "context_radius, and cross_boundary_check. This ticket is missing some of them:\n\n"
            + "\n".join(f"- {w}" for w in hygiene_warnings)
            + "\n\nFix the ticket frontmatter before treating this pack as complete context."
        )

    sections.append(f"## Ticket\n\n```markdown\n{raw}\n```")

    if meta_bool(meta, "security_critical", False):
        sections.append(
            "## Adversarial review required\n\n"
            "This ticket is `security_critical: true`. Per the agent-workflow README, use a stronger "
            "model where available and run a second adversarial review pass (what could still fail, and "
            "which test prevents it) before treating this ticket as done."
        )

    agent_path = default_agent_file(repo_root, crate, meta_str(meta, "agent_md", ""))
    if agent_path:
        add_file_section(sections, "Agent rules", repo_root, agent_path)
    else:
        sections.append("## Agent rules\n\nAGENTS.md at project root is available.")

    add_target_section(
        sections,
        repo_root,
        "Primary target snippets",
        meta_str(meta, "target_file", ""),
        meta_list(meta, "target_patterns"),
        radius,
    )
    add_target_section(
        sections,
        repo_root,
        "Secondary target snippets",
        meta_str(meta, "target_file_2", ""),
        meta_list(meta, "target_patterns_2"),
        radius,
    )

    if occurrence:
        patterns = meta_list(meta, "target_patterns") + meta_list(meta, "target_patterns_2")
        occ_sections = ["## Repo-wide occurrence scan\n\nThis satisfies the repository-wide search step before the agent edits production code."]
        for pattern in patterns:
            occ_sections.append(f"\n### `{pattern}`")
            hits = occurrence_scan(repo_root, pattern)
            if hits:
                occ_sections.append("```text\n" + "\n".join(hits) + "\n```")
            else:
                occ_sections.append("No occurrences found. The ticket may be stale or already fixed.")
        sections.append("\n".join(occ_sections))

    interface_files = meta_list(meta, "interface_files")
    for file_path in interface_files:
        add_file_section(sections, "Interface/context file", repo_root, file_path)

    ref_file = meta_str(meta, "reference_file", "")
    ref_patterns = meta_list(meta, "reference_patterns")
    if ref_file:
        add_target_section(sections, repo_root, "Reference implementation snippets", ref_file, ref_patterns, radius)

    pattern_notes_dir = repo_root / "development" / "agent-workflow" / "pattern_notes"
    if pattern_notes_dir.exists():
        matched_notes = []
        for note in sorted(pattern_notes_dir.glob("*.md")):
            content = read_text(note)
            if ticket_id in content or note.stem == ticket_id:
                matched_notes.append((note, content))
        for note, content in matched_notes:
            sections.append(f"## Pattern note: `{rel(note, repo_root)}`\n\n```markdown\n{content}\n```")

    commands = meta_list(meta, "verify_commands")
    if commands:
        sections.append("## Verify commands\n\n```bash\n" + "\n".join(commands) + "\n```")

    # Pre-scan: capture known pre-existing errors so agents don't try to fix them
    pre_errors = _scan_pre_existing_errors(repo_root, crate, meta_list(meta, "verify_commands"))
    if pre_errors:
        sections.append(
            "## Known pre-existing errors\n\n"
            "These errors exist BEFORE you start. Do NOT create new placeholders/stubs to fix them. "
            "They are tracked in separate tickets. Only fix errors introduced by your own changes.\n\n"
            "```bash\n" + "\n".join(pre_errors) + "\n```\n\n"
            "Rule: If a compiler error is unrelated to the ticket's target file(s), DO NOT fix it. "
            "Document it and move on. Creating a new stub to silence an unrelated error is a violation."
        )

    # Forbidden patterns: new stubs/placeholders the agent must not introduce
    forbidden = meta_list(meta, "forbidden_patterns")
    if forbidden:
        sections.append(
            "## Forbidden patterns\n\n"
            "DO NOT introduce any of these patterns. If you need them, the ticket scope is wrong.\n\n"
            + "\n".join(f"- `{p}`" for p in forbidden)
        )

    # Cross-boundary check: include contract analysis when offchain code references contract features
    contract_files = meta_list(meta, "contract_files")
    cross_boundary = meta_bool(meta, "cross_boundary_check", False)
    if cross_boundary or contract_files:
        contract_sections = ["## Contract compatibility check\n\n"]
        if contract_files:
            contract_sections.append("The following contract files are relevant to this ticket. "
                                   "Before implementing any offchain feature, verify the contract supports it.\n\n")
            for cf in contract_files:
                if cf and (repo_root / cf).exists():
                    contract_sections.append(f"### `{cf}`\n\n```solidity\n{load_file_limited(repo_root / cf, repo_root)}\n```\n")
                elif cf:
                    contract_sections.append(f"### `{cf}`\n\n[missing contract file — verify path]\n")
        else:
            contract_sections.append("No contract files specified. If this ticket touches offchain code that "
                                   "calls contract functions, you MUST verify the contract supports the feature.\n\n"
                                   "Contract locations:\n"
                                   "- Ethereum: `csv-contracts/ethereum/contracts/src/CSVSeal.sol`\n"
                                   "- Solana: `csv-contracts/solana/contracts/programs/csv-seal/src/`\n"
                                   "- Sui: `csv-contracts/sui/sources/csv_seal.move`\n"
                                   "- Aptos: `csv-contracts/aptos/contracts/sources/csv_seal.move`\n")

        contract_sections.append(
            "\n### Cross-boundary rule (STRICT)\n\n"
            "When replacing a stub that says \"not implemented\" or \"unavailable\":\n"
            "1. **Check the contract FIRST**: Does the contract already have a function for this feature?\n"
            "2. **If yes**: Wire the offchain code to call the contract function. Do NOT return an error.\n"
            "3. **If no**: Check if the contract CAN be extended (it usually can). If so, add the function to the contract AND wire the offchain code.\n"
            "4. **If the contract is intentionally minimal**: Return a typed error with a clear message like "
            "\"Feature X requires contract update — see ticket Y\".\n\n"
            "NEVER return \"not implemented\" in offchain code when the contract already supports the feature. "
            "This makes the CLI useless and bugs impossible to trace.\n\n"
            "Examples of features the Ethereum contract CSVSeal.sol ALREADY supports:\n"
            "- `create_seal` — anchor commitment on-chain\n"
            "- `consume_seal` — mark seal as used with nullifier\n"
            "- `lock_sanad` / `lock_sanad_with_metadata` — cross-chain lock\n"
            "- `mint_sanad` / `mint_sanad_with_proof_leaf` — cross-chain mint\n"
            "- `refund_sanad` — refund after timeout\n"
            "- `transfer_sanad` — same-chain ownership transfer\n"
            "- `get_sanad_state` / `get_seal_state` — view functions\n"
            "- `is_seal_available` / `is_seal_consumed` — availability checks\n"
            "- `register_nullifier` — replay protection\n"
            "- `anchor_commitment` — commitment anchoring\n"
            "- `record_sanad_metadata` — metadata recording\n\n"
            "If your stub references any of these, wire it to the contract. Do NOT stub it out."
        )
        sections.append("\n".join(contract_sections))

    sections.append(
        "## Agent instruction\n\n"
        "Work only this ticket. Do not broaden scope unless the occurrence scan proves an equivalent production bypass must be patched in the same commit. "
        "Preserve protocol invariants. Add/adjust tests. Run the verify commands. Finish with a short adversarial review: what could still fail, and which tests prevent it?\n\n"
        "## Agent rules (strict)\n\n"
        "1. **Scope lock**: Only edit files/patterns listed in `target_file`, `target_file_2`, etc. "
        "Do NOT edit other files even if they have compiler errors.\n"
        "2. **No new stubs**: Never introduce `todo!()`, `unimplemented!()`, `panic!()`, `unreachable!()`, "
        "`#[allow(dead_code)]`, `#[allow(unused)]`, `#[allow(clippy::)]` to silence warnings. "
        "If the code cannot compile without a stub, return a typed error instead.\n"
        "3. **No simplifying working code**: If a function already works correctly, do NOT simplify it "
        "to make compilation easier. Only modify the specific stubs/placeholders listed in target_patterns.\n"
        "4. **No ignoring errors**: If `cargo check` or `cargo test` fails, analyze whether the error "
        "is caused by your changes. If yes, fix it. If no (pre-existing), DO NOT fix it — document it "
        "and move on. Creating a placeholder to silence a pre-existing error is a violation.\n"
        "5. **No adding attributes**: Do NOT add `#[allow(...)]` attributes to silence linter warnings. "
        "Fix the warning or add a test. If the warning is unavoidable, document why in a code comment "
        "and create a follow-up ticket.\n"
        "6. **Fail closed, not closed-minded**: When replacing a stub, prefer returning a typed error "
        "over returning fake data. `Err(Error::NotImplemented)` is better than `Ok(fake_value)`.\n"
        "7. **Post-check**: After your changes, run `cargo check` on the target crate. "
        "If it introduces NEW errors in files you didn't edit, you broke something — revert.\n"
        "8. **Scan for new placeholders**: After your changes, run a repo-wide search for "
        "`placeholder`, `stub`, `for now`, `TODO` in files you edited. If you introduced any, fix them.\n"
        "9. **Cross-boundary verification**: If your ticket touches offchain code that references contract features, "
        "read the contract files listed in `contract_files` (or the default contract locations). "
        "Verify the contract supports the feature before implementing. If the contract doesn't support it, "
        "either extend the contract or return a typed error with a clear message."
    )

    return "\n\n---\n\n".join(sections).rstrip() + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a minimal context pack for an AI-agent ticket.")
    parser.add_argument("ticket", help="Path to development/tickets/<ID>.md")
    parser.add_argument("--repo-root", default=".", help="Repository root. Default: current directory")
    parser.add_argument("--radius", type=int, default=None, help="Line radius around each matched pattern")
    parser.add_argument("--no-occurrence-scan", action="store_true", help="Skip repo-wide literal occurrence scan")
    parser.add_argument("--output-dir", default="development/agent-workflow/context_packs", help="Output directory relative to repo root unless absolute")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    ticket_path = Path(args.ticket)
    if not ticket_path.is_absolute():
        ticket_path = (repo_root / ticket_path).resolve()

    if not ticket_path.exists():
        print(f"error: ticket not found: {ticket_path}", file=sys.stderr)
        return 2

    pack = build_context_pack(ticket_path, repo_root, args.radius, not args.no_occurrence_scan)
    meta, _ = parse_frontmatter(read_text(ticket_path))
    ticket_id = meta_str(meta, "id", ticket_path.stem)

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = repo_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{ticket_id}_context.md"
    output_path.write_text(pack, encoding="utf-8")

    approx_tokens = max(1, len(pack) // 4)
    print(f"wrote {output_path}")
    print(f"approx chars: {len(pack):,}; rough tokens: {approx_tokens:,}")
    if approx_tokens > MAX_CONTEXT_PACK_TOKENS:
        print(
            f"warning: context pack is ~{approx_tokens:,} tokens, over the "
            f"{MAX_CONTEXT_PACK_TOKENS:,}-token target (DEV-WORKFLOW-001). "
            "Split this ticket or narrow its target_patterns/interface_files.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
