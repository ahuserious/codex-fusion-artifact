from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "artifact_verifier",
    SOURCE_ROOT / "scripts" / "verify_artifact.py",
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class SemanticMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.artifact_root = Path(self.temporary_directory.name) / "artifact"
        shutil.copytree(
            SOURCE_ROOT,
            self.artifact_root,
            ignore=shutil.ignore_patterns(".git", "__pycache__"),
        )
        self.original_root = VERIFIER.ROOT
        self.original_manifest = VERIFIER.MANIFEST
        self.original_checksums = VERIFIER.CHECKSUMS
        VERIFIER.ROOT = self.artifact_root
        VERIFIER.MANIFEST = self.artifact_root / "manifests" / "artifact-manifest.json"
        VERIFIER.CHECKSUMS = self.artifact_root / "checksums" / "SHA256SUMS"
        self.assertEqual([], VERIFIER.verify())

    def tearDown(self) -> None:
        VERIFIER.ROOT = self.original_root
        VERIFIER.MANIFEST = self.original_manifest
        VERIFIER.CHECKSUMS = self.original_checksums
        self.temporary_directory.cleanup()

    def rewrite_json(self, relative: str, mutate: object) -> None:
        path = self.artifact_root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)  # type: ignore[operator]
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def assert_semantic_failure(self, expected_fragment: str) -> None:
        # Refreshing removes file-hash mismatches from the equation. The
        # remaining failure must come from receipt or claim semantics.
        VERIFIER.refresh()
        failures = VERIFIER.verify()
        self.assertTrue(
            any(expected_fragment in failure for failure in failures),
            msg="expected semantic failure {!r}, observed: {}".format(
                expected_fragment,
                failures,
            ),
        )

    def test_response_mutation_breaks_canonical_receipt(self) -> None:
        response = sorted(
            (
                self.artifact_root
                / "evidence"
                / "runs"
                / "codex-0144-frontier-smoke-001"
                / "responses"
            ).glob("*.json")
        )[0]
        relative = response.relative_to(self.artifact_root).as_posix()

        def mutate(value: dict[str, object]) -> None:
            normalized_response = value["response"]
            assert isinstance(normalized_response, dict)
            normalized_response["text"] = str(normalized_response["text"]) + " mutation"

        self.rewrite_json(relative, mutate)
        self.assert_semantic_failure("response hash mismatch")

    def test_ledger_aggregate_mutation_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["total_tokens"] = int(value["total_tokens"]) + 1

        self.rewrite_json(
            "evidence/runs/codex-0144-frontier-smoke-001/ledger.json",
            mutate,
        )
        self.assert_semantic_failure("total_tokens does not equal input plus output")

    def test_gate_count_mutation_is_rejected(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["pass_count"] = 0

        self.rewrite_json(
            "evidence/runs/codex-0144-frontier-smoke-001/gate-1.json",
            mutate,
        )
        self.assert_semantic_failure("pass count does not match reviewer verdicts")

    def test_curated_host_cost_mutation_breaks_cross_link(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            selected = value["selected_result_fields"]
            assert isinstance(selected, dict)
            agent = selected["agent"]
            assert isinstance(agent, dict)
            agent["cost_usd"] = 1.420944

        self.rewrite_json("evidence/terminal-bench/host-result-receipt.json", mutate)
        self.assert_semantic_failure("curated host fields drifted")

    def test_high_entropy_token_is_rejected_after_rehash(self) -> None:
        token = "A9z_" * 20
        (self.artifact_root / "evidence" / "credential-leak.txt").write_text(
            "XAI_API_KEY=" + token + "\n",
            encoding="utf-8",
        )
        self.assert_semantic_failure("credential-like token")

    def test_private_user_path_is_rejected_after_rehash(self) -> None:
        private_path = "/" + "Users" + "/private-person/work/result.json"
        (self.artifact_root / "evidence" / "path-leak.txt").write_text(
            private_path + "\n",
            encoding="utf-8",
        )
        self.assert_semantic_failure("private path/identity pattern")


if __name__ == "__main__":
    unittest.main()
