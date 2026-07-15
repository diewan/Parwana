from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import date
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-contract-manifest.py"
SPEC = importlib.util.spec_from_file_location("check_contract_manifest", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ContractManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {
            "publisher": "github.com/diewan/parwana",
            "contract_version": "0.1.5",
            "protocol_version": "1.0.0",
            "stability": "pre_stable",
            "source": {"kind": "commit", "value": "a" * 40},
            "corpus": {"digest": "b" * 64},
            "compatibility": {
                "wire": "exact", "semantic": "exact", "source_api": "exact",
                "stored_data": "exact", "policy": "diewan-contract-compat-v1",
            },
        }
        self.pin = {
            "consumer": "piteka",
            "publisher": self.manifest["publisher"],
            "contract_version": self.manifest["contract_version"],
            "protocol_version": self.manifest["protocol_version"],
            "expires_on": "2027-01-16",
            "corpus_digest": self.manifest["corpus"]["digest"],
            "source": dict(self.manifest["source"]),
            "compatibility": dict(self.manifest["compatibility"]),
        }

    def validate(self, pin: dict) -> list[str]:
        return MODULE.validate_pin(Path("pin.toml"), pin, self.manifest, date(2026, 7, 16))

    def test_exact_pre_stable_pin_passes(self) -> None:
        self.assertEqual(self.validate(self.pin), [])

    def test_floating_ref_fails(self) -> None:
        self.pin["source"] = {"kind": "commit", "value": "main"}
        self.assertTrue(any("floating" in failure or "40-character" in failure for failure in self.validate(self.pin)))

    def test_digest_mismatch_fails(self) -> None:
        self.pin["corpus_digest"] = "c" * 64
        self.assertTrue(any("digest mismatch" in failure for failure in self.validate(self.pin)))

    def test_expired_pin_fails(self) -> None:
        self.pin["expires_on"] = "2026-07-15"
        self.assertTrue(any("expired" in failure for failure in self.validate(self.pin)))

    def test_incompatible_contract_fails(self) -> None:
        self.pin["contract_version"] = "0.1.4"
        self.assertTrue(any("incompatible contract" in failure for failure in self.validate(self.pin)))

    def test_stable_contract_requires_release_tag(self) -> None:
        failures = MODULE.validate_source(self.pin["source"], "stable", "pin.toml")
        self.assertTrue(any("SemVer release tag" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
