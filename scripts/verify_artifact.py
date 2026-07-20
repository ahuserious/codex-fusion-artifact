#!/usr/bin/env python3
"""Verify the curated artifact, its receipt graph, and its public claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "artifact-manifest.json"
CHECKSUMS = ROOT / "checksums" / "SHA256SUMS"
EXCLUDED = {
    "manifests/artifact-manifest.json",
    "checksums/SHA256SUMS",
}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SECRET_PATTERNS = {
    "xai_key": re.compile(rb"\bxai-[A-Za-z0-9_-]{12,}"),
    "openai_or_anthropic_key": re.compile(rb"\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_-]{16,}"),
    "github_token": re.compile(rb"\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "gitlab_token": re.compile(rb"\bglpat-[A-Za-z0-9_-]{16,}"),
    "huggingface_token": re.compile(rb"\bhf_[A-Za-z0-9]{20,}"),
    "npm_token": re.compile(rb"\bnpm_[A-Za-z0-9]{20,}"),
    "slack_token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{12,}"),
    "google_api_key": re.compile(rb"\bAIza[A-Za-z0-9_-]{30,}"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "bearer_value": re.compile(rb"\b(?:Authorization\s*:\s*)?Bearer\s+[A-Za-z0-9._~+/-]{12,}", re.I),
    "basic_auth_url": re.compile(rb"https?://[^\s/:@]+:[^\s/@]+@", re.I),
    "private_key": re.compile(
        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    ),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
}
PRIVATE_PATH_PATTERNS = {
    "macos_user_path": re.compile(rb"(?:file://)?/Users/[A-Za-z0-9._-]+/"),
    "linux_user_path": re.compile(rb"(?:file://)?/home/[A-Za-z0-9._-]+/"),
    "macos_ephemeral_path": re.compile(rb"/(?:private/)?var/folders/"),
    "windows_user_path": re.compile(rb"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+[\\/]", re.I),
    # Build this private identity from fragments so the scanner can inspect its
    # own source without whitelisting the verifier file.
    "known_private_identity": re.compile(b"\\b" + b"Dan" + b"Bot" + b"\\b", re.I),
}
URLSAFE_TOKEN_CANDIDATE = re.compile(
    rb"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{48,})(?![A-Za-z0-9_-])"
)
BASE64_TOKEN_CANDIDATE = re.compile(
    rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{48,}={0,2})(?![A-Za-z0-9+/])"
)
SECRET_FIELD_NAMES = {
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "refresh_token",
    "auth_token",
    "authorization",
    "client_secret",
    "password",
    "private_key",
    "secret_key",
}
COUNTER_FIELDS = (
    "input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "cached_tokens",
    "tool_calls",
)
LIVE_CALL_TOPOLOGY = {
    0: ("panel", "grok45_researcher", "structured_response"),
    1: ("panel", "grok45_adversary", "structured_response"),
    2: ("panel", "grok45_constraint_auditor", "structured_response"),
    3: ("judge", "grok45_judge", "fusion_judgment"),
    4: ("synthesis", "grok45_synthesizer", "structured_response"),
    5: ("gate", "grok45_verifier", "adversarial_verdict"),
    6: ("gate", "grok45_constraint_auditor", "adversarial_verdict"),
    7: ("amendment-1", "grok45_synthesizer", "structured_response"),
    8: ("gate-1", "grok45_verifier", "adversarial_verdict"),
    9: ("gate-1", "grok45_constraint_auditor", "adversarial_verdict"),
}
PANEL_RESULT_SEATS = {
    "Seat A": "grok45_adversary",
    "Seat B": "grok45_constraint_auditor",
    "Seat C": "grok45_researcher",
}


def _strict_json_loads(content: str | bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(content, parse_constant=reject_constant)


def load_json(relative: str, failures: list[str]) -> Any:
    path = ROOT / relative
    try:
        return _strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        failures.append(f"{relative}: cannot load strict JSON: {exc}")
        return {}


def payload_paths() -> list[Path]:
    paths: list[Path] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts or "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            continue
        if path.is_file() and relative.as_posix() not in EXCLUDED:
            paths.append(path)
    return sorted(paths, key=lambda value: value.relative_to(ROOT).as_posix())


def structure_failures() -> list[str]:
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts or "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            failures.append(f"{relative.as_posix()}: symbolic links are not allowed in the artifact")
    return failures


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text_hash(encoded)


def attempt_receipt_id(invocation_sha256: str, attempt_index: int) -> str:
    return canonical_json_hash(
        {
            "schema_version": 1,
            "invocation_sha256": invocation_sha256,
            "attempt_index": attempt_index,
        }
    )


def call_receipt_entry_id(
    attempt_id: str,
    invocation_sha256: str,
    response_sha256: str,
) -> str:
    return canonical_json_hash(
        {
            "schema_version": 1,
            "attempt_id": attempt_id,
            "invocation_sha256": invocation_sha256,
            "response_sha256": response_sha256,
        }
    )


def public_entries() -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in payload_paths()
    ]


def _looks_like_digest(candidate: bytes) -> bool:
    return len(candidate) in {40, 64, 96, 128} and all(
        character in b"0123456789abcdefABCDEF" for character in candidate
    )


def _looks_like_credential_token(candidate: bytes) -> bool:
    if _looks_like_digest(candidate):
        return False
    if re.fullmatch(rb"responses/[0-9a-f]{64}", candidate):
        return False
    character_classes = sum(
        (
            any(97 <= character <= 122 for character in candidate),
            any(65 <= character <= 90 for character in candidate),
            any(48 <= character <= 57 for character in candidate),
            any(character in b"_-+/=" for character in candidate),
        )
    )
    return character_classes >= 3


def _safe_secret_reference(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if not stripped:
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", stripped):
        return True
    if re.fullmatch(r"\$\{[A-Z][A-Z0-9_]{2,}\}", stripped):
        return True
    return (
        (stripped.startswith("<") and stripped.endswith(">"))
        or "redacted" in lowered
        or lowered in {"none", "null", "not-set", "unset"}
    )


def _scan_json_secret_fields(value: Any, relative: str, location: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            normalized_key = str(key).lower().replace("-", "_")
            if (
                normalized_key in SECRET_FIELD_NAMES
                and isinstance(child, str)
                and not _safe_secret_reference(child)
            ):
                failures.append(f"{relative}: populated secret field at {child_location}")
            failures.extend(_scan_json_secret_fields(child, relative, child_location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            failures.extend(_scan_json_secret_fields(child, relative, f"{location}[{index}]"))
    return failures


def scan_payloads(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        content = path.read_bytes()
        relative = path.relative_to(ROOT).as_posix()
        for name, pattern in PRIVATE_PATH_PATTERNS.items():
            if pattern.search(content):
                failures.append(f"{relative}: private path/identity pattern {name}")
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                failures.append(f"{relative}: credential pattern {name}")
        for candidate in URLSAFE_TOKEN_CANDIDATE.findall(content):
            if _looks_like_credential_token(candidate):
                failures.append(f"{relative}: long urlsafe credential-like token")
                break
        for candidate in BASE64_TOKEN_CANDIDATE.findall(content):
            if _looks_like_credential_token(candidate):
                failures.append(f"{relative}: long base64 credential-like token")
                break
        if path.suffix == ".json":
            try:
                parsed = _strict_json_loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                failures.append(f"{relative}: invalid strict JSON: {exc}")
            else:
                failures.extend(_scan_json_secret_fields(parsed, relative))
    return failures


def refresh() -> None:
    unsafe_structure = structure_failures()
    if unsafe_structure:
        raise RuntimeError("refusing to refresh a tree containing symbolic links")
    entries = public_entries()
    manifest = {
        "schema_version": 1,
        "artifact": "codex-fusion-artifact",
        "generated_by": "scripts/verify_artifact.py --refresh",
        "files": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    CHECKSUMS.write_text(
        "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries),
        encoding="utf-8",
    )


def _is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_nonnegative_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def _close(left: Any, right: Any) -> bool:
    try:
        return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=1e-9)
    except (TypeError, ValueError, OverflowError):
        return False


def _receipt_from_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "attempt_id": entry.get("attempt_id"),
        "entry_id": entry.get("entry_id"),
        "invocation_sha256": entry.get("invocation_sha256"),
        "response_sha256": entry.get("response_sha256"),
    }


def verify_ledger(
    ledger: Any,
    label: str,
    failures: list[str],
    *,
    response_root: Path | None = None,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "entries_by_id": {},
        "invocations_by_id": {},
        "responses_by_id": {},
        "models": {},
        "providers": {},
        "requested_models": {},
        "known_cost_usd": 0.0,
        "counters": {counter: 0 for counter in COUNTER_FIELDS},
    }
    if not isinstance(ledger, dict):
        failures.append(f"{label}: ledger root is not an object")
        return facts
    if ledger.get("schema_version") != 3:
        failures.append(f"{label}: ledger schema_version is not 3")

    calls = ledger.get("calls")
    attempts = ledger.get("attempts")
    attempt_entries = ledger.get("attempt_entries")
    entries = ledger.get("entries")
    if not _is_nonnegative_integer(calls) or not _is_nonnegative_integer(attempts):
        failures.append(f"{label}: calls/attempts must be nonnegative integers")
        return facts
    if not isinstance(attempt_entries, list) or not isinstance(entries, list):
        failures.append(f"{label}: attempt_entries/entries must be arrays")
        return facts
    if calls != attempts or calls != len(attempt_entries):
        failures.append(f"{label}: calls, attempts, and attempt_entries length differ")
    if len(entries) > calls:
        failures.append(f"{label}: recorded entries exceed reserved attempts")

    attempts_by_index: dict[int, dict[str, Any]] = {}
    for expected_index, attempt in enumerate(attempt_entries):
        if not isinstance(attempt, dict):
            failures.append(f"{label}: attempt {expected_index} is not an object")
            continue
        attempt_index = attempt.get("attempt_index")
        invocation_sha256 = attempt.get("invocation_sha256")
        attempt_id = attempt.get("attempt_id")
        if attempt_index != expected_index:
            failures.append(f"{label}: attempts are not in zero-based reservation order")
            continue
        if not isinstance(invocation_sha256, str) or not HEX_SHA256.fullmatch(invocation_sha256):
            failures.append(f"{label}: attempt {expected_index} has invalid invocation SHA-256")
            continue
        if attempt_id != attempt_receipt_id(invocation_sha256, expected_index):
            failures.append(f"{label}: attempt {expected_index} ID is not receipt-derived")
        attempts_by_index[expected_index] = attempt

    counter_sums = {counter: 0 for counter in COUNTER_FIELDS}
    provider_costs: dict[str, float] = {}
    known_costs: list[float] = []
    unknown_cost_calls = 0
    recorded_attempts: set[int] = set()
    referenced_response_files: set[str] = set()

    for entry_number, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"{label}: entry {entry_number} is not an object")
            continue
        attempt_index = entry.get("attempt_index")
        if not _is_nonnegative_integer(attempt_index) or attempt_index not in attempts_by_index:
            failures.append(f"{label}: entry {entry_number} does not identify a reserved attempt")
            continue
        if attempt_index in recorded_attempts:
            failures.append(f"{label}: reserved attempt {attempt_index} is recorded more than once")
        recorded_attempts.add(attempt_index)
        reserved = attempts_by_index[attempt_index]
        for field in ("attempt_id", "invocation_sha256", "stage", "seat"):
            if entry.get(field) != reserved.get(field):
                failures.append(f"{label}: entry {entry_number} does not match attempt field {field}")

        attempt_id = entry.get("attempt_id")
        invocation_sha256 = entry.get("invocation_sha256")
        response_sha256 = entry.get("response_sha256")
        entry_id = entry.get("entry_id")
        hashes_valid = all(
            isinstance(value, str) and HEX_SHA256.fullmatch(value)
            for value in (attempt_id, invocation_sha256, response_sha256, entry_id)
        )
        if not hashes_valid:
            failures.append(f"{label}: entry {entry_number} has a malformed receipt hash")
        elif entry_id != call_receipt_entry_id(attempt_id, invocation_sha256, response_sha256):
            failures.append(f"{label}: entry {entry_number} ID is not receipt-derived")

        expected_response_artifact = f"responses/{entry_id}.json"
        response_artifact = entry.get("response_artifact")
        if response_artifact != expected_response_artifact:
            failures.append(f"{label}: entry {entry_number} response path is not entry-ID-derived")
        elif isinstance(response_artifact, str):
            referenced_response_files.add(response_artifact)

        usage = entry.get("usage")
        if not isinstance(usage, dict):
            failures.append(f"{label}: entry {entry_number} usage is not an object")
            continue
        for counter in COUNTER_FIELDS:
            value = usage.get(counter)
            if not _is_nonnegative_integer(value):
                failures.append(f"{label}: entry {entry_number} has invalid {counter}")
            else:
                counter_sums[counter] += value
        if (
            _is_nonnegative_integer(usage.get("cached_tokens"))
            and _is_nonnegative_integer(usage.get("input_tokens"))
            and usage["cached_tokens"] > usage["input_tokens"]
        ):
            failures.append(f"{label}: entry {entry_number} cached tokens exceed input tokens")
        if (
            _is_nonnegative_integer(usage.get("reasoning_tokens"))
            and _is_nonnegative_integer(usage.get("output_tokens"))
            and usage["reasoning_tokens"] > usage["output_tokens"]
        ):
            failures.append(f"{label}: entry {entry_number} reasoning tokens exceed output tokens")
        cost = usage.get("cost_usd")
        if cost is None:
            unknown_cost_calls += 1
        elif not _is_nonnegative_number(cost):
            failures.append(f"{label}: entry {entry_number} has invalid cost")
        else:
            normalized_cost = float(cost)
            known_costs.append(normalized_cost)
            provider = entry.get("provider")
            if not isinstance(provider, str) or not provider:
                failures.append(f"{label}: entry {entry_number} has invalid provider")
            else:
                provider_costs[provider] = provider_costs.get(provider, 0.0) + normalized_cost

        model = entry.get("actual_model")
        if isinstance(model, str):
            facts["models"][model] = facts["models"].get(model, 0) + 1
        requested_model = entry.get("requested_model")
        if isinstance(requested_model, str):
            facts["requested_models"][requested_model] = (
                facts["requested_models"].get(requested_model, 0) + 1
            )
        provider_name = entry.get("provider")
        if isinstance(provider_name, str):
            facts["providers"][provider_name] = facts["providers"].get(provider_name, 0) + 1
        if isinstance(entry_id, str):
            facts["entries_by_id"][entry_id] = entry

        if response_root is None or not isinstance(response_artifact, str):
            continue
        response_path = response_root / response_artifact
        try:
            response_artifact_value = _strict_json_loads(response_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            failures.append(f"{label}: cannot load {response_artifact}: {exc}")
            continue
        if not isinstance(response_artifact_value, dict):
            failures.append(f"{label}: {response_artifact} root is not an object")
            continue
        invocation = response_artifact_value.get("invocation")
        response = response_artifact_value.get("response")
        receipt = response_artifact_value.get("receipt")
        if response_artifact_value.get("schema_version") != 1:
            failures.append(f"{label}: {response_artifact} schema_version is not 1")
        if not isinstance(invocation, dict) or canonical_json_hash(invocation) != invocation_sha256:
            failures.append(f"{label}: {response_artifact} invocation hash mismatch")
        if not isinstance(response, dict) or canonical_json_hash(response) != response_sha256:
            failures.append(f"{label}: {response_artifact} response hash mismatch")
        if receipt != _receipt_from_entry(entry):
            failures.append(f"{label}: {response_artifact} receipt does not match ledger")
        if isinstance(invocation, dict):
            for field, expected in (
                ("stage", entry.get("stage")),
                ("seat_name", entry.get("seat")),
                ("run_id", manifest.get("run_id") if manifest else None),
                ("config_sha256", manifest.get("config_hash") if manifest else None),
                ("input_sha256", manifest.get("input_hash") if manifest else None),
            ):
                if expected is not None and invocation.get(field) != expected:
                    failures.append(f"{label}: {response_artifact} invocation field {field} drifted")
            facts["invocations_by_id"][entry_id] = invocation
        if isinstance(response, dict):
            for field in (
                "actual_model",
                "latency_seconds",
                "provider",
                "raw_status",
                "request_id",
                "requested_model",
                "route",
                "usage",
            ):
                if response.get(field) != entry.get(field):
                    failures.append(f"{label}: {response_artifact} response field {field} drifted")
            facts["responses_by_id"][entry_id] = response

    for counter, recomputed in counter_sums.items():
        if ledger.get(counter) != recomputed:
            failures.append(f"{label}: aggregate {counter} does not match entries")
    if ledger.get("total_tokens") != counter_sums["input_tokens"] + counter_sums["output_tokens"]:
        failures.append(f"{label}: total_tokens does not equal input plus output")
    known_cost = math.fsum(known_costs)
    if not _close(ledger.get("known_cost_usd"), known_cost):
        failures.append(f"{label}: aggregate known cost does not match entries")
    recorded_provider_costs = ledger.get("provider_cost_usd")
    if not isinstance(recorded_provider_costs, dict) or set(recorded_provider_costs) != set(provider_costs):
        failures.append(f"{label}: provider cost keys do not match entries")
    elif any(not _close(recorded_provider_costs[key], value) for key, value in provider_costs.items()):
        failures.append(f"{label}: provider cost totals do not match entries")
    if ledger.get("unknown_cost_calls") != unknown_cost_calls:
        failures.append(f"{label}: unknown-cost count does not match entries")

    if response_root is not None:
        actual_response_files = {
            path.relative_to(response_root).as_posix()
            for path in (response_root / "responses").glob("*.json")
        }
        if actual_response_files != referenced_response_files:
            failures.append(f"{label}: response directory has missing or orphaned receipt artifacts")

    facts["known_cost_usd"] = known_cost
    facts["counters"] = counter_sums
    facts["calls"] = calls
    facts["unknown_cost_calls"] = unknown_cost_calls
    return facts


def verify_embedded_response(
    value: Any,
    label: str,
    live_facts: dict[str, Any],
    failures: list[str],
    *,
    expected_stage: str,
    expected_seat: str | None = None,
    outer_seat_field: str | None = None,
    expected_role: str | None = None,
    expected_keys: set[str] | None = None,
) -> str | None:
    if not isinstance(value, dict):
        failures.append(f"{label}: embedded response record is not an object")
        return None
    evidence = value.get("response_evidence")
    embedded_response = value.get("response")
    if not isinstance(evidence, dict):
        failures.append(f"{label}: response_evidence is missing")
        return None
    entry_id = evidence.get("entry_id")
    entry = live_facts["entries_by_id"].get(entry_id)
    invocation = live_facts["invocations_by_id"].get(entry_id)
    response = live_facts["responses_by_id"].get(entry_id)
    if not isinstance(entry, dict) or not isinstance(invocation, dict) or not isinstance(response, dict):
        failures.append(f"{label}: response_evidence does not resolve to the live ledger")
        return None
    if expected_keys is not None and set(value) != expected_keys:
        failures.append(f"{label}: outer record fields drifted")
    if evidence != _receipt_from_entry(entry):
        failures.append(f"{label}: response_evidence receipt fields drifted")
    if embedded_response != response:
        failures.append(f"{label}: embedded response differs from raw receipt artifact")
    if entry.get("stage") != expected_stage or invocation.get("stage") != expected_stage:
        failures.append(f"{label}: outer record resolves to the wrong invocation stage")
    receipt_seat = entry.get("seat")
    if invocation.get("seat_name") != receipt_seat:
        failures.append(f"{label}: invocation seat differs from the ledger seat")
    if expected_seat is not None and receipt_seat != expected_seat:
        failures.append(f"{label}: receipt resolves to an unexpected seat")
    if outer_seat_field is not None and value.get(outer_seat_field) != receipt_seat:
        failures.append(f"{label}: outer {outer_seat_field} is not bound to the receipt seat")
    for seat_field in ("seat_name", "author_seat"):
        if seat_field in value and value.get(seat_field) != receipt_seat:
            failures.append(f"{label}: outer {seat_field} differs from the receipt seat")
    if expected_role is not None and value.get("role") != expected_role:
        failures.append(f"{label}: outer role is not bound to the invocation stage")
    if "status" in value and value.get("status") != response.get("raw_status"):
        failures.append(f"{label}: outer status differs from the receipt response")
    return str(entry_id)


def verify_gate(
    gate: Any,
    label: str,
    expected_artifact_hash: str,
    expected_pass_count: int,
    expected_passed: bool,
    live_facts: dict[str, Any],
    failures: list[str],
) -> set[str]:
    referenced: set[str] = set()
    if not isinstance(gate, dict):
        failures.append(f"{label}: gate is not an object")
        return referenced
    if gate.get("artifact_sha256") != expected_artifact_hash:
        failures.append(f"{label}: artifact hash does not bind the reviewed synthesis")
    reviewers = gate.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 2:
        failures.append(f"{label}: expected exactly two reviewers")
        return referenced
    observed_passes = 0
    negative_seats: set[str] = set()
    expected_negative_verdicts: list[dict[str, Any]] = []
    expected_reviewer_seats = {"grok45_verifier", "grok45_constraint_auditor"}
    observed_reviewer_seats: set[str] = set()
    for index, reviewer in enumerate(reviewers):
        entry_id = verify_embedded_response(
            reviewer,
            f"{label}.reviewers[{index}]",
            live_facts,
            failures,
            expected_stage="gate" if label == "gate-0" else "gate-1",
            outer_seat_field="seat_name",
            expected_keys={"response", "response_evidence", "seat_name", "status", "verdict"},
        )
        if entry_id:
            referenced.add(entry_id)
        verdict = reviewer.get("verdict") if isinstance(reviewer, dict) else None
        if not isinstance(verdict, dict):
            failures.append(f"{label}: reviewer {index} verdict is missing")
            continue
        if verdict.get("artifact_sha256") != expected_artifact_hash:
            failures.append(f"{label}: reviewer {index} verdict reviewed another artifact")
        if verdict.get("verdict") == "PASS":
            observed_passes += 1
        else:
            reviewer_seat = str(reviewer.get("seat_name"))
            negative_seats.add(reviewer_seat)
            expected_negative_verdicts.append(
                {
                    "blocking_findings": verdict.get("blocking_findings"),
                    "evidence": verdict.get("evidence"),
                    "required_actions": verdict.get("required_actions"),
                    "seat_name": reviewer_seat,
                    "summary": verdict.get("summary"),
                    "verdict": verdict.get("verdict"),
                }
            )
        observed_reviewer_seats.add(str(reviewer.get("seat_name")))
        response = reviewer.get("response")
        if isinstance(response, dict):
            try:
                parsed_verdict = _strict_json_loads(response.get("text", ""))
            except (json.JSONDecodeError, ValueError, TypeError):
                failures.append(f"{label}: reviewer {index} response text is not strict JSON")
            else:
                if parsed_verdict != verdict:
                    failures.append(f"{label}: reviewer {index} parsed verdict drifted")
    if gate.get("required_passes") != 2:
        failures.append(f"{label}: required_passes is not 2")
    if observed_reviewer_seats != expected_reviewer_seats:
        failures.append(f"{label}: reviewer seat topology drifted")
    if gate.get("pass_count") != observed_passes or observed_passes != expected_pass_count:
        failures.append(f"{label}: pass count does not match reviewer verdicts")
    if gate.get("passed") is not expected_passed:
        failures.append(f"{label}: passed state drifted")
    if gate.get("negative_verdict_blocked") is not bool(negative_seats):
        failures.append(f"{label}: negative-verdict blocker state is inconsistent")
    if gate.get("negative_verdicts") != expected_negative_verdicts:
        failures.append(f"{label}: negative verdict records are not bound to reviewer results")
    if expected_passed and gate.get("deterministic_blockers") != []:
        failures.append(f"{label}: passing gate retained deterministic blockers")
    if not expected_passed and not gate.get("deterministic_blockers"):
        failures.append(f"{label}: rejected gate lost its deterministic blocker")
    return referenced


def verify_live_topology(
    ledger: Any,
    live_facts: dict[str, Any],
    failures: list[str],
) -> None:
    """Bind the immutable smoke to its intended model/provider/role topology."""

    if not isinstance(ledger, dict) or not isinstance(ledger.get("entries"), list):
        failures.append("live topology cannot resolve ledger entries")
        return
    entries_by_attempt = {
        entry.get("attempt_index"): entry
        for entry in ledger["entries"]
        if isinstance(entry, dict)
    }
    if set(entries_by_attempt) != set(LIVE_CALL_TOPOLOGY):
        failures.append("live topology does not contain exactly attempts 0 through 9")
        return
    request_ids: set[str] = set()
    for attempt_index, (expected_stage, expected_seat, expected_schema) in LIVE_CALL_TOPOLOGY.items():
        entry = entries_by_attempt[attempt_index]
        entry_id = entry.get("entry_id")
        invocation = live_facts["invocations_by_id"].get(entry_id)
        if (
            entry.get("stage") != expected_stage
            or entry.get("seat") != expected_seat
            or not isinstance(invocation, dict)
            or invocation.get("stage") != expected_stage
            or invocation.get("seat_name") != expected_seat
            or invocation.get("schema_name") != expected_schema
        ):
            failures.append(f"live topology attempt {attempt_index} stage/seat/schema drifted")
        if (
            entry.get("provider") != "xai_direct"
            or entry.get("requested_model") != "grok-4.5"
            or entry.get("actual_model") != "grok-4.5"
            or entry.get("route") != {}
            or entry.get("raw_status") != "completed"
        ):
            failures.append(f"live topology attempt {attempt_index} provider/model/route drifted")
        request_id = entry.get("request_id")
        if not isinstance(request_id, str) or not request_id or request_id in request_ids:
            failures.append(f"live topology attempt {attempt_index} request ID is missing or reused")
        else:
            request_ids.add(request_id)
        usage = entry.get("usage")
        if not isinstance(usage, dict) or (
            usage.get("unknown_cost_fail_closed") is not False
            or usage.get("input_output_usage_complete") is not True
            or usage.get("raw_usage_invalid") is not False
            or usage.get("accounting_error") is not None
            or usage.get("tool_calls") != 0
        ):
            failures.append(f"live topology attempt {attempt_index} usage-integrity state drifted")
    if live_facts.get("providers") != {"xai_direct": 10}:
        failures.append("live provider topology is not ten direct-xAI calls")
    if live_facts.get("requested_models") != {"grok-4.5": 10}:
        failures.append("live requested-model topology is not ten exact Grok 4.5 calls")
    if live_facts.get("models") != {"grok-4.5": 10}:
        failures.append("live actual-model topology is not ten exact Grok 4.5 calls")


def verify_live_run(summary: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    run_id = "codex-0144-frontier-smoke-001"
    live_root = ROOT / "evidence" / "runs" / run_id
    manifest = load_json(f"evidence/runs/{run_id}/manifest.json", failures)
    ledger = load_json(f"evidence/runs/{run_id}/ledger.json", failures)
    live_facts = verify_ledger(
        ledger,
        "live ledger",
        failures,
        response_root=live_root,
        manifest=manifest if isinstance(manifest, dict) else {},
    )
    verify_live_topology(ledger, live_facts, failures)
    if not isinstance(manifest, dict):
        return live_facts
    if manifest.get("run_id") != run_id or manifest.get("status") != "completed":
        failures.append("live manifest run/status mismatch")
    expected_stages = {
        "panel": ("panel.json", "completed"),
        "judge": ("judge.json", "completed"),
        "synthesis": ("synthesis.json", "completed"),
        "gate-0": ("gate-0.json", "rejected"),
        "amendment-1": ("synthesis-amendment-1.json", "completed"),
        "gate-1": ("gate-1.json", "passed"),
    }
    stages = manifest.get("stages")
    if not isinstance(stages, dict) or set(stages) != set(expected_stages):
        failures.append("live manifest stage set drifted")
    else:
        for stage, (artifact, status) in expected_stages.items():
            if stages[stage].get("artifact") != artifact or stages[stage].get("status") != status:
                failures.append(f"live manifest stage {stage} drifted")

    panel = load_json(f"evidence/runs/{run_id}/panel.json", failures)
    judge = load_json(f"evidence/runs/{run_id}/judge.json", failures)
    synthesis = load_json(f"evidence/runs/{run_id}/synthesis.json", failures)
    gate_0 = load_json(f"evidence/runs/{run_id}/gate-0.json", failures)
    amendment = load_json(f"evidence/runs/{run_id}/synthesis-amendment-1.json", failures)
    gate_1 = load_json(f"evidence/runs/{run_id}/gate-1.json", failures)
    handoff = load_json(f"evidence/runs/{run_id}/execution-handoff.json", failures)

    referenced: set[str] = set()
    if not isinstance(panel, dict):
        failures.append("live panel is not an object")
    else:
        results = panel.get("results")
        attempts = panel.get("attempts")
        if (
            not isinstance(results, list)
            or len(results) != 3
            or panel.get("live_count") != 3
            or panel.get("failed_count") != 0
            or panel.get("degraded") is not False
        ):
            failures.append("live panel completion counters drifted")
        attempt_entry_ids: list[str] = []
        if not isinstance(attempts, list) or len(attempts) != 3:
            failures.append("live panel attempts are incomplete")
        else:
            for index, attempt in enumerate(attempts):
                expected_seat = LIVE_CALL_TOPOLOGY[index][1]
                entry_id = verify_embedded_response(
                    attempt,
                    f"panel.attempts[{index}]",
                    live_facts,
                    failures,
                    expected_stage="panel",
                    expected_seat=expected_seat,
                    outer_seat_field="seat_name",
                    expected_role="panel",
                    expected_keys={
                        "anonymous_label",
                        "error",
                        "response",
                        "response_evidence",
                        "role",
                        "seat_name",
                        "status",
                    },
                )
                if entry_id:
                    attempt_entry_ids.append(entry_id)
                    entry = live_facts["entries_by_id"].get(entry_id, {})
                    if entry.get("attempt_index") != index:
                        failures.append(f"panel.attempts[{index}]: receipt order drifted")
                if not isinstance(attempt, dict) or (
                    attempt.get("anonymous_label") != ""
                    or attempt.get("error") is not None
                ):
                    failures.append(f"panel.attempts[{index}]: completion wrapper drifted")

        result_entry_ids: list[str] = []
        observed_labels: set[str] = set()
        if isinstance(results, list) and len(results) == 3:
            for index, result in enumerate(results):
                label = result.get("anonymous_label") if isinstance(result, dict) else None
                expected_seat = PANEL_RESULT_SEATS.get(str(label))
                entry_id = verify_embedded_response(
                    result,
                    f"panel.results[{index}]",
                    live_facts,
                    failures,
                    expected_stage="panel",
                    expected_seat=expected_seat,
                    outer_seat_field="seat_name",
                    expected_role="panel",
                    expected_keys={
                        "anonymous_label",
                        "error",
                        "response",
                        "response_evidence",
                        "role",
                        "seat_name",
                        "status",
                    },
                )
                if entry_id:
                    result_entry_ids.append(entry_id)
                    referenced.add(entry_id)
                if isinstance(label, str):
                    observed_labels.add(label)
                if not isinstance(result, dict) or result.get("error") is not None:
                    failures.append(f"panel.results[{index}]: completion wrapper drifted")
        if observed_labels != set(PANEL_RESULT_SEATS):
            failures.append("live panel anonymous-label topology drifted")
        if len(set(attempt_entry_ids)) != 3 or set(attempt_entry_ids) != set(result_entry_ids):
            failures.append("live panel attempts/results do not bind the same three receipts")

    judge_entry = verify_embedded_response(
        judge,
        "judge",
        live_facts,
        failures,
        expected_stage="judge",
        expected_seat="grok45_judge",
        expected_keys={"judgment", "response", "response_evidence"},
    )
    if judge_entry:
        referenced.add(judge_entry)
    if isinstance(judge, dict) and isinstance(judge.get("response"), dict):
        try:
            parsed_judgment = _strict_json_loads(judge["response"].get("text", ""))
        except (json.JSONDecodeError, ValueError, TypeError):
            failures.append("judge response text is not strict JSON")
        else:
            if parsed_judgment != judge.get("judgment"):
                failures.append("judge parsed judgment drifted")

    def verify_synthesis(
        value: Any,
        label: str,
        expected_stage: str,
    ) -> tuple[str, str | None]:
        if not isinstance(value, dict) or not isinstance(value.get("text"), str):
            failures.append(f"{label}: synthesis text is missing")
            return "", None
        synthesis_hash = text_hash(value["text"])
        if value.get("sha256") != synthesis_hash:
            failures.append(f"{label}: text SHA-256 mismatch")
        if not isinstance(value.get("response"), dict) or value["response"].get("text") != value["text"]:
            failures.append(f"{label}: normalized response text differs from synthesis")
        entry_id = verify_embedded_response(
            value,
            label,
            live_facts,
            failures,
            expected_stage=expected_stage,
            expected_seat="grok45_synthesizer",
            outer_seat_field="author_seat",
            expected_keys={
                "author_seat",
                "mode",
                "response",
                "response_evidence",
                "sha256",
                "text",
            },
        )
        if value.get("mode") != "client_orchestrated":
            failures.append(f"{label}: synthesis mode drifted")
        return synthesis_hash, entry_id

    synthesis_hash, synthesis_entry = verify_synthesis(synthesis, "synthesis", "synthesis")
    if synthesis_entry:
        referenced.add(synthesis_entry)
    gate_0_entries = verify_gate(
        gate_0,
        "gate-0",
        synthesis_hash,
        1,
        False,
        live_facts,
        failures,
    )
    referenced.update(gate_0_entries)
    amendment_hash, amendment_entry = verify_synthesis(
        amendment,
        "synthesis amendment",
        "amendment-1",
    )
    if amendment_entry:
        referenced.add(amendment_entry)
    gate_1_entries = verify_gate(
        gate_1,
        "gate-1",
        amendment_hash,
        2,
        True,
        live_facts,
        failures,
    )
    referenced.update(gate_1_entries)
    if referenced != set(live_facts["entries_by_id"]):
        failures.append("live semantic artifacts do not reference every ledger receipt exactly by ID")

    if isinstance(handoff, dict):
        contract = handoff.get("execution_contract")
        if not isinstance(contract, dict):
            failures.append("execution handoff contract is missing")
        else:
            if handoff.get("execution_contract_sha256") != canonical_json_hash(contract):
                failures.append("execution handoff contract hash mismatch")
            handoff_contract = {
                "selected_profile": handoff.get("selected_profile"),
                "execution_contract": contract,
            }
            if handoff.get("handoff_contract_sha256") != canonical_json_hash(handoff_contract):
                failures.append("execution handoff profile/contract hash mismatch")
        payload = dict(handoff)
        payload.pop("handoff_payload_sha256", None)
        if handoff.get("handoff_payload_sha256") != canonical_json_hash(payload):
            failures.append("execution handoff payload hash mismatch")
        synthesis_gate = handoff.get("synthesis_gate")
        if not isinstance(synthesis_gate, dict) or (
            synthesis_gate.get("artifact_sha256") != amendment_hash
            or synthesis_gate.get("passed") is not True
        ):
            failures.append("execution handoff is not bound to the final passing synthesis gate")
        artifacts = handoff.get("artifacts")
        if not isinstance(artifacts, dict) or artifacts.get("fused_plan") != amendment.get("text"):
            failures.append("execution handoff fused plan differs from the amended synthesis")
        if (
            handoff.get("status") != "awaiting_host_gates"
            or handoff.get("ready_for_host_workflow") is not True
            or handoff.get("ready") is not False
            or handoff.get("mutation_authorized") is not False
        ):
            failures.append("execution handoff authorization boundary drifted")

    run_by_id = {run.get("id"): run for run in summary.get("runs", []) if isinstance(run, dict)}
    live_summary = run_by_id.get(run_id)
    result_summary = load_json("results/live-fusion-summary.json", failures)
    expected_tokens = {
        "input": live_facts["counters"]["input_tokens"],
        "output": live_facts["counters"]["output_tokens"],
        "reasoning": live_facts["counters"]["reasoning_tokens"],
        "cached": live_facts["counters"]["cached_tokens"],
        "total": live_facts["counters"]["input_tokens"] + live_facts["counters"]["output_tokens"],
    }
    if not isinstance(live_summary, dict):
        failures.append("campaign summary lost the current live run")
    else:
        if (
            live_summary.get("calls") != live_facts.get("calls")
            or live_summary.get("actual_models") != ["grok-4.5"]
            or live_summary.get("requested_models") != ["grok-4.5"]
            or not _close(live_summary.get("known_cost_usd"), live_facts["known_cost_usd"])
            or live_summary.get("tokens") != expected_tokens
            or live_summary.get("unknown_cost_calls") != live_facts["unknown_cost_calls"]
        ):
            failures.append("campaign live-run aggregate differs from verified ledger")
        expected_gate_history = [
            {"stage": "gate-0", "status": "rejected", "pass": 1, "total": 2},
            {"stage": "gate-1", "status": "passed", "pass": 2, "total": 2},
        ]
        if live_summary.get("gate_history") != expected_gate_history:
            failures.append("campaign gate history differs from verified gates")
    if not isinstance(result_summary, dict) or (
        result_summary.get("calls") != live_facts.get("calls")
        or not _close(result_summary.get("known_cost_usd"), live_facts["known_cost_usd"])
        or result_summary.get("model_provenance")
        != {"actual": ["grok-4.5"], "requested": ["grok-4.5"]}
        or result_summary.get("tokens") != expected_tokens
        or result_summary.get("initial_gate") != {"status": "rejected", "pass": 1, "total": 2}
        or result_summary.get("final_gate") != {"status": "passed", "pass": 2, "total": 2}
    ):
        failures.append("published live result summary differs from verified evidence")
    return live_facts


def verify_terminal_bench(summary: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    terminal_root = ROOT / "evidence" / "terminal-bench"
    terminal_call_count = 0
    terminal_costs: list[float] = []
    terminal_models: dict[str, int] = {}
    ledgers = sorted((terminal_root / "ri").glob("*/ledger.json"))
    if len(ledgers) != 6:
        failures.append("Terminal-Bench lifecycle ledger count is not six")
    for ledger_path in ledgers:
        relative = ledger_path.relative_to(ROOT).as_posix()
        ledger = load_json(relative, failures)
        facts = verify_ledger(ledger, f"historical {ledger_path.parent.name} ledger", failures)
        terminal_call_count += int(facts.get("calls", 0))
        terminal_costs.append(float(facts.get("known_cost_usd", 0.0)))
        for model, count in facts.get("models", {}).items():
            terminal_models[model] = terminal_models.get(model, 0) + count
        manifest_relative = ledger_path.with_name("manifest.json").relative_to(ROOT).as_posix()
        manifest = load_json(manifest_relative, failures)
        if not isinstance(manifest, dict) or (
            manifest.get("run_id") != ledger_path.parent.name or manifest.get("status") != "completed"
        ):
            failures.append(f"historical {ledger_path.parent.name} manifest drifted")
    terminal_cost = math.fsum(terminal_costs)
    if terminal_call_count != 17 or terminal_models != {"grok-4.3": 8, "grok-4.5": 9}:
        failures.append("historical Terminal-Bench ledger count/model mismatch")
    if not _close(terminal_cost, 0.32157745):
        failures.append("historical Terminal-Bench external cost mismatch")

    receipt = load_json("evidence/terminal-bench/host-result-receipt.json", failures)
    validator = load_json("evidence/terminal-bench/current-validator-observation.json", failures)
    public_index_hash = sha256(terminal_root / "evidence.json")
    if not isinstance(receipt, dict) or (
        receipt.get("public_index_sha256") != public_index_hash
        or receipt.get("raw_source", {}).get("sha256")
        != "7279b1701561ae49ba6235740b5018d83f51ef6f0356c25374e17cb211ba7afa"
        or receipt.get("raw_source", {}).get("published") is not False
        or receipt.get("raw_run_contract", {}).get("sha256")
        != "e14b56e03f078887e6f9501a9b9eac50abb2e0d2e777a554f3939de4744674fe"
    ):
        failures.append("Terminal-Bench private-source commitment drifted")
        selected = {}
    else:
        selected = receipt.get("selected_result_fields", {})
    if (
        not isinstance(selected, dict)
        or selected.get("task_name") != "terminal-bench/fix-git"
        or selected.get("reward") != 1.0
        or not _close(selected.get("agent", {}).get("cost_usd"), 1.410944)
    ):
        failures.append("Terminal-Bench curated host fields drifted")
    if (terminal_root / "reward.txt").read_text(encoding="utf-8").strip() != "1":
        failures.append("Terminal-Bench public reward text drifted")
    ctrf = load_json("evidence/terminal-bench/ctrf.json", failures)
    if not isinstance(ctrf, dict) or ctrf.get("results", {}).get("summary", {}).get("passed") != 2:
        failures.append("Terminal-Bench CTRF pass count drifted")
    if not isinstance(validator, dict) or (
        validator.get("classification") != "rejected_contract_drift"
        or validator.get("observation")
        != {
            "combined_output": "INVALID: Agent timeout drift\n",
            "exit_code": 1,
            "observed_on": "2026-07-20",
        }
        or validator.get("validator", {}).get("script_sha256")
        != "fa0f29e70790a122f78ee584ad13f599a0d8992a776dd9f56d5377c3fe76cc88"
        or validator.get("public_index_sha256") != public_index_hash
        or validator.get("raw_run_contract_sha256")
        != receipt.get("raw_run_contract", {}).get("sha256")
    ):
        failures.append("Terminal-Bench current-validator observation drifted")

    run_by_id = {run.get("id"): run for run in summary.get("runs", []) if isinstance(run, dict)}
    campaign = run_by_id.get("codex-final-003/fix-git")
    result = load_json("results/terminal-bench-summary.json", failures)
    expected_models = {"grok-4.3": 8, "grok-4.5": 9, "host": "openai/gpt-5.6-sol"}
    if not isinstance(campaign, dict) or (
        campaign.get("reward") != 1.0
        or campaign.get("external_calls") != terminal_call_count
        or not _close(campaign.get("external_known_cost_usd"), terminal_cost)
        or not _close(campaign.get("host_cost_usd"), selected.get("agent", {}).get("cost_usd"))
        or campaign.get("current_release_binding") != "historical_only_validator_rejects_drift"
    ):
        failures.append("campaign Terminal-Bench summary differs from verified evidence")
    if not isinstance(result, dict) or (
        result.get("reward") != 1.0
        or result.get("external_calls") != terminal_call_count
        or not _close(result.get("external_known_cost_usd"), terminal_cost)
        or not _close(result.get("host_cost_usd"), selected.get("agent", {}).get("cost_usd"))
        or result.get("models") != expected_models
        or result.get("current_validator_status") != "rejected_contract_drift"
    ):
        failures.append("published Terminal-Bench result summary differs from verified evidence")
    return {
        "external_cost_usd": terminal_cost,
        "host_cost_usd": selected.get("agent", {}).get("cost_usd", 0.0),
    }


def verify_deep_swe(summary: dict[str, Any], failures: list[str]) -> dict[str, Any]:
    deep_root = ROOT / "evidence" / "deep-swe"
    reward = load_json("evidence/deep-swe/reward.json", failures)
    index = load_json("evidence/deep-swe/evidence.json", failures)
    ctrf = load_json("evidence/deep-swe/ctrf.json", failures)
    receipt = load_json("evidence/deep-swe/host-result-receipt.json", failures)
    preflight = load_json("evidence/deep-swe/preflight-observation.json", failures)
    public_index_hash = sha256(deep_root / "evidence.json")
    if not isinstance(reward, dict) or reward != {
        "reward": 0,
        "f2p_total": 2,
        "f2p_passed": 0,
        "p2p_total": 119,
        "p2p_passed": 119,
        "f2p": 0.0,
        "p2p": 1.0,
        "partial": 0.9834710743801653,
    }:
        failures.append("DeepSWE public reward fields drifted")
    if not isinstance(index, dict) or index.get("ri_runs") != []:
        failures.append("DeepSWE index no longer proves zero recorded fusion runs")
    ctrf_summary = ctrf.get("results", {}).get("summary", {}) if isinstance(ctrf, dict) else {}
    if ctrf_summary != {
        "tests": 121,
        "passed": 119,
        "failed": 2,
        "skipped": 0,
        "pending": 0,
        "other": 0,
    }:
        failures.append("DeepSWE CTRF aggregate drifted")
    if not isinstance(receipt, dict) or (
        receipt.get("public_index_sha256") != public_index_hash
        or receipt.get("raw_source", {}).get("sha256")
        != "02a5742863b824ede76f939c5ed59c8d220f9b549ac2558f93db5cf1432ae8d6"
        or receipt.get("raw_source", {}).get("published") is not False
        or receipt.get("raw_run_contract", {}).get("sha256")
        != "70c45f86d95c2cb60a555de71f73a73ac76288c62f694e76d8f4e8445f2f5004"
    ):
        failures.append("DeepSWE private-source commitment drifted")
        selected = {}
    else:
        selected = receipt.get("selected_result_fields", {})
    if (
        not isinstance(selected, dict)
        or selected.get("task_name") != "datacurve/anko-default-function-arguments"
        or selected.get("reward")
        != {
            "f2p_passed": 0,
            "f2p_total": 2,
            "p2p_passed": 119,
            "p2p_total": 119,
            "partial": 0.9834710743801653,
            "reward": 0,
        }
        or not _close(selected.get("agent", {}).get("cost_usd"), 0.380207)
    ):
        failures.append("DeepSWE curated host fields drifted")
    expected_preflight = {
        "command_records": 12,
        "exit_records": 12,
        "hard_character_limit": 12000,
        "message": "Preflight failed its hard bound: 25,050 characters exceeded the 12,000-character limit. Per your instruction, I stopped before fusion and made no branch, file changes, test runs, or commits.",
        "observed_characters": 25050,
        "stage": "preflight_before_fusion",
    }
    if not isinstance(preflight, dict) or (
        preflight.get("observed_failure") != expected_preflight
        or preflight.get("private_source_commitments")
        != {
            "codex_transcript_sha256": "9e9617e4cd0c1c5f24eff4fe808c57e04e4ed7549e14a6c196d9953a28efe0e4",
            "trajectory_sha256": "29e63970254518c5e2bc1fe586f9f8a7902f06aa5355ee952f8e41a4c97d678b",
        }
        or preflight.get("public_consequences", {}).get("relentless_inception_external_calls") != 0
    ):
        failures.append("DeepSWE preflight observation drifted")

    run_by_id = {run.get("id"): run for run in summary.get("runs", []) if isinstance(run, dict)}
    campaign = run_by_id.get("codex-final-006/anko-default-function-arguments")
    result = load_json("results/deep-swe-summary.json", failures)
    for label, candidate in (("campaign", campaign), ("published result", result)):
        if not isinstance(candidate, dict) or (
            candidate.get("reward") != 0
            or candidate.get("external_calls") != 0
            or candidate.get("f2p_passed") != 0
            or candidate.get("f2p_total") != 2
            or candidate.get("p2p_passed") != 119
            or candidate.get("p2p_total") != 119
            or not _close(candidate.get("partial"), 0.9834710743801653)
            or not _close(candidate.get("host_cost_usd"), selected.get("agent", {}).get("cost_usd"))
        ):
            failures.append(f"{label} DeepSWE summary differs from verified evidence")
    return {"host_cost_usd": selected.get("agent", {}).get("cost_usd", 0.0)}


def verify_jigs(summary: dict[str, Any], failures: list[str]) -> None:
    pins = load_json("jigs/current-source-pins.json", failures)
    source = summary.get("source", {})
    if not isinstance(pins, dict) or pins.get("source", {}).get("commit") != source.get("commit"):
        failures.append("jig source commit is not bound to campaign source")
    required_fragments = {
        "jigs/live-fusion/run.sh": (
            "verify-checkout.sh",
            "RELENTLESS_INCEPTION_CONFIG",
            "RELENTLESS_INCEPTION_DATA_DIR",
            "RI_EVIDENCE_ROOT already exists",
        ),
        "jigs/terminal-bench/run.sh": ("verify-checkout.sh", "RI_ACCEPT_NETWORK_FETCHES"),
        "jigs/deepswe/run.sh": ("verify-checkout.sh", "RI_ACCEPT_NETWORK_FETCHES"),
    }
    for relative, fragments in required_fragments.items():
        content = (ROOT / relative).read_text(encoding="utf-8")
        if "--execute" not in content or any(fragment not in content for fragment in fragments):
            failures.append(f"{relative}: replay safety boundary drifted")


def verify() -> list[str]:
    failures: list[str] = []
    failures.extend(structure_failures())

    manifest = load_json("manifests/artifact-manifest.json", failures)
    expected_header = {
        "schema_version": 1,
        "artifact": "codex-fusion-artifact",
        "generated_by": "scripts/verify_artifact.py --refresh",
    }
    if not isinstance(manifest, dict):
        failures.append("artifact manifest root is not an object")
    else:
        for key, value in expected_header.items():
            if manifest.get(key) != value:
                failures.append(f"manifest {key} mismatch")
        expected_entries = public_entries()
        if manifest.get("files") != expected_entries:
            failures.append("manifest file list, size, or SHA-256 differs; run --refresh after review")
        expected_checksums = "".join(
            f"{entry['sha256']}  {entry['path']}\n" for entry in expected_entries
        )
        try:
            observed_checksums = CHECKSUMS.read_text(encoding="utf-8")
        except OSError as exc:
            failures.append(f"checksums/SHA256SUMS cannot be read: {exc}")
        else:
            if observed_checksums != expected_checksums:
                failures.append("checksums/SHA256SUMS differs from payload")

    summary = load_json("evidence/campaign-summary.json", failures)
    if not isinstance(summary, dict):
        failures.append("campaign summary root is not an object")
        summary = {}
    if summary.get("artifact") != "codex-fusion-artifact":
        failures.append("campaign artifact name drifted")
    if summary.get("claim_scope") != "limited_engineering_validation":
        failures.append("campaign claim scope drifted")
    if summary.get("limited_due_to_api_cost") is not True:
        failures.append("campaign must retain limited_due_to_api_cost=true")
    if summary.get("openrouter_live_tested") is not False:
        failures.append("campaign must not claim a live OpenRouter test")
    runs = summary.get("runs")
    if not isinstance(runs, list) or len(runs) != 3:
        failures.append("campaign must retain exactly the three selected observations")
        summary["runs"] = []
    elif len({run.get("id") for run in runs if isinstance(run, dict)}) != len(runs):
        failures.append("campaign run IDs are not unique")

    live = verify_live_run(summary, failures)
    terminal = verify_terminal_bench(summary, failures)
    deep = verify_deep_swe(summary, failures)
    selected_cost = math.fsum(
        [
            float(live.get("known_cost_usd", 0.0)),
            float(terminal.get("external_cost_usd", 0.0)),
            float(terminal.get("host_cost_usd", 0.0)),
            float(deep.get("host_cost_usd", 0.0)),
        ]
    )
    if not _close(summary.get("selected_receipts_known_cost_usd"), selected_cost):
        failures.append("selected receipt cost total does not match its four published components")
    if summary.get("selected_receipts_are_complete_campaign_spend") is not False:
        failures.append("campaign must not claim selected costs are complete development spend")
    cost_evidence = summary.get("cost_evidence")
    if cost_evidence != {
        "direct_xai": "public_provider_ledger",
        "terminal_external": "public_provider_ledgers",
        "terminal_host": "curated_private_source_commitment",
        "deep_swe_host": "curated_private_source_commitment",
    }:
        failures.append("campaign cost evidence classes are missing or drifted")
    verify_jigs(summary, failures)
    failures.extend(scan_payloads(payload_paths()))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    if args.refresh:
        refresh()
    failures = verify()
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(f"PASS: {len(public_entries())} payload files and semantic receipt graph verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
