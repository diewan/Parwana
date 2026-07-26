#!/usr/bin/env python3
"""Generate the portable V2 hostile-conformance fixture manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "csv-testkit/corpus/v2/manifest.json"


def case(identifier, category, reason, dimensions, source, bytes_hex=""):
    return {
        "id": identifier,
        "category": category,
        "wire_version": 2,
        "contract_version": "0.1.10",
        "bytes_hex": bytes_hex,
        "expected_dimensions": dimensions,
        "expected_reason_code": reason,
        "source": source,
    }


FAILED_PROOF = {
    "proof": "failed",
    "inclusion": "failed",
    "finality": "indeterminate",
    "freshness": "indeterminate",
    "closure": "failed",
    "aggregate": "rejected",
}

CASES = [
    case("valid-v2", "positive", "ACCEPT.V2.ACCEPTED",
         {"proof": "satisfied", "inclusion": "satisfied", "finality": "satisfied",
          "freshness": "satisfied", "closure": "satisfied", "aggregate": "accepted"},
         "csv-runtime/src/recipient_acceptance.rs::success_returns_full_typed_report_and_is_idempotent"),
    case("legacy-v1", "legacy", "WIRE.V1.PORTABLE_NON_EQUIVOCATION_UNAVAILABLE",
         {"proof": "indeterminate", "inclusion": "indeterminate", "finality": "indeterminate",
          "freshness": "indeterminate", "closure": "indeterminate", "aggregate": "unsupported"},
         "csv-wire/src/consignment.rs::v1_inspection_never_claims_portable_non_equivocation"),
    *[
        case(identifier, "malicious-graph", reason,
             {"structure": "failed", "aggregate": "rejected"}, source, "ff")
        for identifier, reason, source in [
            ("graph-cycle", "PROTOCOL.DAG.CYCLE", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("graph-duplicate-node", "PROTOCOL.DAG.DUPLICATE_NODE", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("graph-self-parent", "PROTOCOL.DAG.SELF_PARENT", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("graph-missing-parent", "PROTOCOL.DAG.MISSING_PARENT", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("graph-root-substitution", "PROTOCOL.DAG.ROOT_MISMATCH", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("graph-noncanonical-order", "PROTOCOL.DAG.NON_CANONICAL_ORDER", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("state-content-mutation", "PROTOCOL.STATE.COMMITMENT_MISMATCH", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("state-output-index-mutation", "PROTOCOL.STATE.OUTPUT_NOT_FOUND", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("transition-commitment-mutation", "PROTOCOL.TRANSITION.COMMITMENT_MISMATCH", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("canonical-root-mutation", "PROTOCOL.DAG.ROOT_MISMATCH", "csv-protocol/tests/v2_transition_vectors.rs::negative_vectors_fail_for_declared_reason"),
            ("consumed-evidence-substitution", "PROTOCOL.REFERENCE.WRONG_DISCRIMINANT", "csv-protocol/src/reference.rs::consumed_and_evidence_references_are_domain_separated"),
        ]
    ],
    *[
        case(identifier, "bitcoin-closure", reason, dimensions,
             "csv-runtime/src/recipient_acceptance.rs::forged_checkpoint_corpus_fails_by_dimension",
             bytes_hex)
        for identifier, reason, dimensions, bytes_hex in [
            ("proof-nonempty-garbage", "ACCEPT.V2.SOURCE_CLOSURE", FAILED_PROOF, "fa" * 64),
            ("proof-wrong-header", "ACCEPT.V2.INCLUSION", FAILED_PROOF, "01" * 80),
            ("proof-wrong-merkle-path", "ACCEPT.V2.INCLUSION", FAILED_PROOF, "02" * 64),
            ("proof-wrong-outpoint", "ACCEPT.V2.SOURCE_CLOSURE", FAILED_PROOF, "03" * 36),
            ("proof-wrong-transition-commitment", "ACCEPT.V2.SOURCE_CLOSURE", FAILED_PROOF, "04" * 32),
            ("checkpoint-insufficient-finality", "ACCEPT.V2.FINALITY",
             {**FAILED_PROOF, "proof": "satisfied", "inclusion": "satisfied", "finality": "failed"}, ""),
            ("checkpoint-stale", "ACCEPT.V2.FRESHNESS",
             {**FAILED_PROOF, "proof": "satisfied", "inclusion": "satisfied", "finality": "satisfied", "freshness": "failed"}, ""),
            ("checkpoint-wrong-network", "ACCEPT.V2.VERIFICATION_CONTEXT", FAILED_PROOF, ""),
            ("checkpoint-orphaned", "ACCEPT.V2.SOURCE_CLOSURE",
             {**FAILED_PROOF, "proof": "satisfied", "inclusion": "failed", "finality": "failed"}, ""),
        ]
    ],
    case("losing-conflict", "conflict", "ACCEPT.V2.CONFLICT",
         {"closure": "failed", "aggregate": "rejected"},
         "csv-runtime/src/recipient_acceptance.rs::isolated_recipients_cannot_both_accept_one_source"),
    case("reorganization", "reorganization", "STORAGE.CHECKPOINT.ORPHANED",
         {"closure": "failed", "aggregate": "revoked"},
         "csv-storage/src/accepted_state.rs::orphaning_checkpoint_revokes_root_and_downgrades_descendants_idempotently"),
    case("crash-recovery", "crash", "RUNTIME.SEND.RECOVERED",
         {"aggregate": "accepted"},
         "csv-runtime/src/transfer_coordinator.rs::send_resume_after_emit_interrupt_never_recloses_source_seal"),
]


def render() -> bytes:
    payload = {
        "schema_version": 1,
        "package": "parwana-portable-conformance",
        "version": "stage4-v1",
        "platforms": {
            "native": {"verification": "supported", "persistent_store": "supported"},
            "wasm32": {"verification": "supported", "persistent_store": "unsupported"},
        },
        "cases": CASES,
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
            print(f"{OUTPUT.relative_to(ROOT)} is stale")
            return 1
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(expected)
    print(hashlib.sha256(expected).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
