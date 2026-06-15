#!/usr/bin/env python3
"""
generate_context_pack.py — Build a minimal, self-contained context bundle
for one ticket from development/tickets/, so an AI agent session doesn't
need the whole monorepo.

Usage:
    python3 development/agent-workflow/generate_context_pack.py \
        development/tickets/<ID>.md [--repo-root .] [--radius N] [--no-occurrence-scan]

Output:
    development/agent-workflow/context_packs/<ID>_context.md

Requires: rg (ripgrep) if available, falls back to grep -n.
Pure standard library otherwise (no pip install needed).
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Minimal frontmatter parser
#
# Supports the flat subset of YAML used by TICKET_TEMPLATE.md:
#   key: scalar
#   key: "quoted scalar"
#   key:
#     - "list item"
#     - list item
# No nested maps. Good enough for this purpose; avoids a PyYAML dependency.
# ---------------------------------------------------------------------------

def parse_frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("Ticket file must start with a YAML frontmatter block (---)")

    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        raise ValueError("Unterminated frontmatter block (missing closing ---)")

    body = "\n".join(lines[end + 1:])
    fm_lines = lines[1:end]

    data = {}
    current_list_key = None

    for raw in fm_lines:
        if not raw.strip():
            continue
        # list item
        m = re.match(r'^\s*-\s*(.*)$', raw)
        if m and current_list_key is not None:
            val = m.group(1).strip()
            val = _strip_quotes(val)
            if val != "":
                data[current_list_key].append(val)
            continue

        # key: value  OR  key:
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$', raw)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if val == "":
                data[key] = []
                current_list_key = key
            else:
                data[key] = _strip_quotes(val)
                current_list_key = None
            continue

        # anything else: ignore (comments etc.)

    return data, body


def _strip_quotes(s):
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def as_bool(val, default=False):
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    return str(val).strip().lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Search helpers (ripgrep with grep fallback)
# ---------------------------------------------------------------------------

HAVE_RG = shutil.which("rg") is not None


def search_occurrences(repo_root, pattern, glob=None):
    """Repo-wide occurrence search for a literal pattern. Returns list of
    'path:line:text' strings."""
    if HAVE_RG:
        cmd = ["rg", "-n", "-F", "--no-heading", pattern]
        if glob:
            cmd += ["-g", glob]
        cmd.append(".")
    else:
        # grep fallback: recursive, fixed-string, line numbers
        cmd = ["grep", "-rn", "-F", pattern, "."]

    try:
        result = subprocess.run(
            cmd, cwd=repo_root, capture_output=True, text=True, timeout=60
        )
    except Exception as e:
        return [f"(search failed: {e})"]

    lines = [l for l in result.stdout.splitlines() if l.strip()]
    return lines


def grep_with_context(repo_root, file_path, pattern, radius):
    """Return a (line_no, snippet_text) for the first match of `pattern`
    in file_path, with `radius` lines of context on each side. Returns
    None if not found."""
    abs_path = os.path.join(repo_root, file_path)
    if not os.path.exists(abs_path):
        return None

    if HAVE_RG:
        cmd = ["rg", "-n", "-F", "-C", str(radius), pattern, abs_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception:
            return None
        out = result.stdout
        if not out.strip():
            return None
        return out
    else:
        cmd = ["grep", "-n", "-F", f"-C{radius}", pattern, abs_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception:
            return None
        out = result.stdout
        if not out.strip():
            return None
        return out


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------

MAX_INTERFACE_FILE_CHARS = 60_000


def load_full_file(repo_root, file_path):
    abs_path = os.path.join(repo_root, file_path)
    if not os.path.exists(abs_path):
        return f"!! FILE NOT FOUND: {file_path}\n" \
               f"   (path drifted? update interface_files / reference_file in the ticket)\n"

    with open(abs_path, "r", errors="replace") as f:
        content = f.read()

    if len(content) > MAX_INTERFACE_FILE_CHARS:
        head = content[: MAX_INTERFACE_FILE_CHARS // 2]
        tail = content[-MAX_INTERFACE_FILE_CHARS // 2:]
        content = (
            head
            + f"\n\n... [TRUNCATED — file is {len(content)} chars, showing "
              f"first/last {MAX_INTERFACE_FILE_CHARS // 2} chars. "
              f"Consider narrowing interface_files or fetching the relevant "
              f"section directly in-session.] ...\n\n"
            + tail
        )
    return content


def guess_ext_lang(file_path):
    ext = os.path.splitext(file_path)[1].lstrip(".")
    return {
        "rs": "rust",
        "toml": "toml",
        "ts": "typescript",
        "sh": "bash",
        "sol": "solidity",
        "move": "move",
        "md": "markdown",
        "py": "python",
    }.get(ext, "")


# ---------------------------------------------------------------------------
# Main pack assembly
# ---------------------------------------------------------------------------

def build_pack(ticket_path, repo_root, radius_override, do_occurrence_scan):
    with open(ticket_path, "r") as f:
        raw = f.read()

    meta, body = parse_frontmatter(raw)

    ticket_id = meta.get("id", os.path.splitext(os.path.basename(ticket_path))[0])
    radius = radius_override or int(meta.get("context_radius", 25) or 25)

    sections = []

    # --- Header -------------------------------------------------------
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    git_rev = "(not a git repo)"
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                            cwd=repo_root, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            git_rev = r.stdout.strip()
    except Exception:
        pass

    sections.append(
        f"# Context Pack: {ticket_id}\n\n"
        f"Generated: {now}  \n"
        f"Repo HEAD: `{git_rev}`  \n"
        f"Crate: `{meta.get('crate', '?')}`  \n"
        f"Priority: `{meta.get('priority', '?')}`  "
        f"Security-critical: `{as_bool(meta.get('security_critical'))}`  "
        f"Model hint: `{meta.get('model_hint', 'sonnet')}`\n\n"
        f"This pack was generated by `generate_context_pack.py`. It is "
        f"meant to be the **first message** of a fresh agent session, "
        f"with the session's working directory set to `{meta.get('crate', '.')}`. "
        f"Do not load the rest of the repository unless this pack or the "
        f"agent's own scoped search turns up a concrete need to.\n"
    )

    # --- Ticket body ----------------------------------------------------
    sections.append("## Ticket\n\n" + raw.strip() + "\n")

    # --- AGENT.md ---------------------------------------------------------
    agent_md_path = meta.get("agent_md", "")
    if not agent_md_path:
        crate = meta.get("crate", "")
        if crate.startswith("csv-adapters"):
            agent_md_path = "csv-adapters/.agents/AGENT.md"
        elif crate:
            agent_md_path = f"{crate}/.agents/AGENT.md"
    if agent_md_path:
        content = load_full_file(repo_root, agent_md_path)
        sections.append(f"## AGENT.md (`{agent_md_path}`)\n\n```markdown\n{content.strip()}\n```\n")

    # --- Target file: matched snippets ----------------------------------
    target_file = meta.get("target_file", "")
    target_patterns = meta.get("target_patterns", [])
    if target_file:
        sections.append(f"## Target file: `{target_file}`\n")
        if not target_patterns:
            content = load_full_file(repo_root, target_file)
            lang = guess_ext_lang(target_file)
            sections.append(f"Full file (no target_patterns specified):\n\n```{lang}\n{content}\n```\n")
        else:
            for pat in target_patterns:
                snippet = grep_with_context(repo_root, target_file, pat, radius)
                if snippet is None:
                    sections.append(
                        f"### Pattern not found: `{pat}`\n\n"
                        f"This string was not found in `{target_file}`. It may already be "
                        f"resolved, or it may have been reworded. Search the file manually "
                        f"before assuming the work is done — confirm against the "
                        f"'Why it matters' section of the ticket.\n"
                    )
                else:
                    lang = guess_ext_lang(target_file)
                    sections.append(
                        f"### Match: `{pat}`\n\n```{lang}\n{snippet.strip()}\n```\n"
                    )

    # second target file, if present
    target_file_2 = meta.get("target_file_2", "")
    target_patterns_2 = meta.get("target_patterns_2", [])
    if target_file_2:
        sections.append(f"## Target file 2: `{target_file_2}`\n")
        if not target_patterns_2:
            content = load_full_file(repo_root, target_file_2)
            lang = guess_ext_lang(target_file_2)
            sections.append(f"Full file:\n\n```{lang}\n{content}\n```\n")
        else:
            for pat in target_patterns_2:
                snippet = grep_with_context(repo_root, target_file_2, pat, radius)
                if snippet is None:
                    sections.append(f"### Pattern not found: `{pat}`\n\n(not found — verify manually)\n")
                else:
                    lang = guess_ext_lang(target_file_2)
                    sections.append(f"### Match: `{pat}`\n\n```{lang}\n{snippet.strip()}\n```\n")

    # --- Repo-wide occurrence scan (AGENT.md §5.1, done outside the session) ---
    if do_occurrence_scan and target_patterns:
        sections.append(
            "## Repo-wide occurrence scan\n\n"
            "Per AGENT.md §5.1 ('search the repository for equivalent "
            "patterns, enumerate all occurrences, patch all production "
            "occurrences'). This was run once, outside the session, so it "
            "doesn't need to be repeated. Lines under `/tests`, `/fuzz`, "
            "`/benches`, or in `*.md` files are usually out of scope per "
            "AGENT.md §2 — but check.\n"
        )
        for pat in target_patterns:
            hits = search_occurrences(repo_root, pat)
            sections.append(f"\n**`{pat}`** — {len(hits)} occurrence(s):\n")
            if hits:
                sections.append("```\n" + "\n".join(hits[:50]) + "\n```\n")
                if len(hits) > 50:
                    sections.append(f"(showing first 50 of {len(hits)})\n")
            else:
                sections.append("(none found — may already be resolved)\n")

    # --- Interface files --------------------------------------------------
    interface_files = meta.get("interface_files", [])
    interface_files = [p for p in interface_files if p.strip()]
    if interface_files:
        sections.append("## Interface / trait definitions (full files)\n")
        for path in interface_files:
            content = load_full_file(repo_root, path)
            lang = guess_ext_lang(path)
            sections.append(f"### `{path}`\n\n```{lang}\n{content}\n```\n")

    # --- Reference implementation -------------------------------------------
    ref_crate = meta.get("reference_crate", "")
    ref_file = meta.get("reference_file", "")
    ref_patterns = meta.get("reference_patterns", [])
    if ref_file:
        sections.append(
            f"## Reference implementation: `{ref_file}` (from `{ref_crate}`)\n\n"
            f"This adapter already implements the pattern this ticket needs. "
            f"Use it to understand the *shape* of the fix — chain-specific "
            f"details (RPC calls, encodings, account/program addressing) "
            f"will differ for `{meta.get('crate', 'this crate')}`. If a "
            f"`pattern_notes/` entry exists for this reference, prefer that "
            f"over re-deriving from the raw source.\n"
        )
        if not ref_patterns:
            content = load_full_file(repo_root, ref_file)
            lang = guess_ext_lang(ref_file)
            sections.append(f"Full file:\n\n```{lang}\n{content}\n```\n")
        else:
            for pat in ref_patterns:
                snippet = grep_with_context(repo_root, ref_file, pat, radius)
                if snippet is None:
                    sections.append(f"### Pattern not found: `{pat}`\n\n(not found in reference file — search manually)\n")
                else:
                    lang = guess_ext_lang(ref_file)
                    sections.append(f"### Match: `{pat}`\n\n```{lang}\n{snippet.strip()}\n```\n")

    # --- Pattern notes (if any reference this ticket id) ------------------
    pattern_notes_dir = os.path.join(repo_root, "development", "agent-workflow", "pattern_notes")
    if os.path.isdir(pattern_notes_dir):
        for fname in sorted(os.listdir(pattern_notes_dir)):
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(pattern_notes_dir, fname)
            with open(fpath, "r", errors="replace") as f:
                pn_content = f.read()
            if ticket_id in pn_content:
                sections.append(
                    f"## Existing pattern note referencing this ticket: `{fname}`\n\n"
                    f"```markdown\n{pn_content.strip()}\n```\n"
                )

    # --- Verify commands -----------------------------------------------------
    verify_commands = meta.get("verify_commands", [])
    verify_commands = [c for c in verify_commands if c.strip()]
    if verify_commands:
        sections.append(
            "## Verify commands\n\nRun these (in this order) after making "
            "changes. These are scoped to the crate — fast feedback. Save "
            "`cargo build --workspace --all-features` / "
            "`cargo test --workspace --all-features` / the architecture "
            "constitution suite for batch verification across multiple "
            "closed tickets.\n\n```bash\n" + "\n".join(verify_commands) + "\n```\n"
        )

    pack = "\n---\n\n".join(sections)
    return ticket_id, pack


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ticket", help="Path to development/tickets/<ID>.md")
    parser.add_argument("--repo-root", default=".", help="Repo root (default: cwd)")
    parser.add_argument("--radius", type=int, default=None,
                         help="Override context_radius from the ticket")
    parser.add_argument("--no-occurrence-scan", action="store_true",
                         help="Skip the repo-wide occurrence scan section")
    args = parser.parse_args()

    repo_root = os.path.abspath(args.repo_root)
    ticket_path = os.path.abspath(args.ticket)

    if not HAVE_RG:
        sys.stderr.write(
            "note: ripgrep (rg) not found on PATH — falling back to grep. "
            "Install ripgrep for much faster occurrence scans.\n"
        )

    ticket_id, pack = build_pack(
        ticket_path, repo_root, args.radius, not args.no_occurrence_scan
    )

    out_dir = os.path.join(repo_root, "development", "agent-workflow", "context_packs")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{ticket_id}_context.md")
    with open(out_path, "w") as f:
        f.write(pack)

    approx_tokens = len(pack) // 4
    print(f"Wrote {out_path}")
    print(f"Size: {len(pack):,} chars  (~{approx_tokens:,} tokens)")
    if approx_tokens > 100_000:
        print(
            "WARNING: this pack is large (>100k tokens). Check "
            "interface_files / reference_file for unintentionally huge "
            "files, or narrow target_patterns / context_radius."
        )


if __name__ == "__main__":
    main()
