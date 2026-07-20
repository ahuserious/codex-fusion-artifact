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

    def test_panel_attempt_duplicate_response_is_receipt_bound(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            attempts = value["attempts"]
            assert isinstance(attempts, list)
            first_attempt = attempts[0]
            assert isinstance(first_attempt, dict)
            response = first_attempt["response"]
            assert isinstance(response, dict)
            response["text"] = str(response["text"]) + " coordinated mutation"

        self.rewrite_json(
            "evidence/runs/codex-0144-frontier-smoke-001/panel.json",
            mutate,
        )
        self.assert_semantic_failure("embedded response differs from raw receipt artifact")

    def test_panel_result_outer_seat_is_receipt_bound(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            results = value["results"]
            assert isinstance(results, list)
            first_result = results[0]
            assert isinstance(first_result, dict)
            first_result["seat_name"] = "unbound_reviewer"

        self.rewrite_json(
            "evidence/runs/codex-0144-frontier-smoke-001/panel.json",
            mutate,
        )
        self.assert_semantic_failure("outer seat_name is not bound to the receipt seat")

    def test_panel_result_outer_role_is_invocation_bound(self) -> None:
        def mutate(value: dict[str, object]) -> None:
            results = value["results"]
            assert isinstance(results, list)
            first_result = results[0]
            assert isinstance(first_result, dict)
            first_result["role"] = "judge"

        self.rewrite_json(
            "evidence/runs/codex-0144-frontier-smoke-001/panel.json",
            mutate,
        )
        self.assert_semantic_failure("outer role is not bound to the invocation stage")

    def test_coordinated_model_receipt_rewrite_breaks_fixed_topology(self) -> None:
        run_root = (
            self.artifact_root
            / "evidence"
            / "runs"
            / "codex-0144-frontier-smoke-001"
        )
        ledger_path = run_root / "ledger.json"
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        entry = next(item for item in ledger["entries"] if item["attempt_index"] == 0)
        old_entry_id = entry["entry_id"]
        response_path = run_root / entry["response_artifact"]
        response_artifact = json.loads(response_path.read_text(encoding="utf-8"))

        entry["requested_model"] = "grok-4.3"
        entry["actual_model"] = "grok-4.3"
        response_artifact["response"]["requested_model"] = "grok-4.3"
        response_artifact["response"]["actual_model"] = "grok-4.3"
        response_sha256 = VERIFIER.canonical_json_hash(response_artifact["response"])
        new_entry_id = VERIFIER.call_receipt_entry_id(
            entry["attempt_id"],
            entry["invocation_sha256"],
            response_sha256,
        )
        entry["response_sha256"] = response_sha256
        entry["entry_id"] = new_entry_id
        entry["response_artifact"] = f"responses/{new_entry_id}.json"
        response_artifact["receipt"]["response_sha256"] = response_sha256
        response_artifact["receipt"]["entry_id"] = new_entry_id
        ledger_path.write_text(
            json.dumps(ledger, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        new_response_path = response_path.with_name(f"{new_entry_id}.json")
        new_response_path.write_text(
            json.dumps(response_artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        response_path.unlink()

        panel_path = run_root / "panel.json"
        panel = json.loads(panel_path.read_text(encoding="utf-8"))
        for collection_name in ("attempts", "results"):
            for record in panel[collection_name]:
                if record["response_evidence"]["entry_id"] != old_entry_id:
                    continue
                record["response"]["requested_model"] = "grok-4.3"
                record["response"]["actual_model"] = "grok-4.3"
                record["response_evidence"]["response_sha256"] = response_sha256
                record["response_evidence"]["entry_id"] = new_entry_id
        panel_path.write_text(
            json.dumps(panel, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assert_semantic_failure("provider/model/route drifted")

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

    def test_verifier_source_is_included_in_credential_scan(self) -> None:
        credential = "xai-" + ("Aa9_" * 8)
        verifier_path = self.artifact_root / "scripts" / "verify_artifact.py"
        with verifier_path.open("a", encoding="utf-8") as handle:
            handle.write("\n# accidental value: " + credential + "\n")
        self.assert_semantic_failure("credential pattern xai_key")

    def test_private_user_path_is_rejected_after_rehash(self) -> None:
        private_path = "/" + "Users" + "/private-person/work/result.json"
        (self.artifact_root / "evidence" / "path-leak.txt").write_text(
            private_path + "\n",
            encoding="utf-8",
        )
        self.assert_semantic_failure("private path/identity pattern")


if __name__ == "__main__":
    unittest.main()
