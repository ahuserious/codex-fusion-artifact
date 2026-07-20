#!/usr/bin/env python3
"""Render a deterministic compact report from the public campaign summary."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "evidence" / "campaign-summary.json"


def main() -> int:
    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    print(f"artifact: {data['artifact']}")
    print(f"scope: {data['claim_scope']}")
    print("runs:")
    for run in data["runs"]:
        outcome = run.get("status", "unknown")
        cost_components = []
        if "known_cost_usd" in run:
            cost_components.append(f"provider=${run['known_cost_usd']:.8f}")
        if "external_known_cost_usd" in run:
            cost_components.append(f"external=${run['external_known_cost_usd']:.8f}")
        if "host_cost_usd" in run:
            cost_components.append(f"host=${run['host_cost_usd']:.8f}")
        rendered_cost = ", ".join(cost_components) if cost_components else "no retained cost"
        print(f"- {run['id']}: {outcome}; {rendered_cost}")
    print(
        "selected receipt total: "
        f"${data['selected_receipts_known_cost_usd']:.8f}; "
        "not complete campaign spend"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
