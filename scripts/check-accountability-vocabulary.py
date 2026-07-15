#!/usr/bin/env python3
"""Fail when the normative accountability vocabulary policy drifts."""

from __future__ import annotations

from pathlib import Path


POLICY = Path(__file__).resolve().parents[1] / "development/CANONICAL-NAMING.md"
REQUIRED_TERMS = ("Mandate", "Receipt", "Observation", "Claim", "Verification", "Assurance")
REQUIRED_CLAUSES = (
    "existing `csv-*` crate names remain unchanged",
    "Future crate-rename process",
    "Unknown major versions fail explicitly",
    "JSON Schema and UI projections are interoperability surfaces",
    "it cannot prove that every future sentence uses the terms correctly",
)


def main() -> int:
    text = POLICY.read_text(encoding="utf-8")
    normalized = " ".join(text.split())
    missing = []
    for term in REQUIRED_TERMS:
        if f"| **{term}** |" not in text:
            missing.append(f"canonical definition: {term}")
    for clause in REQUIRED_CLAUSES:
        if clause not in normalized:
            missing.append(f"compatibility clause: {clause}")
    if missing:
        print("accountability vocabulary policy is incomplete:")
        for item in missing:
            print(f"- {item}")
        return 1
    print("accountability vocabulary policy: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
