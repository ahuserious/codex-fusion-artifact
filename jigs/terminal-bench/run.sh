#!/bin/sh
set -eu

if [ "${1:-}" != "--execute" ]; then
  echo "Refusing billable harness run. Review this script, then pass --execute." >&2
  exit 2
fi

: "${RI_CODEX_SOURCE:?Set RI_CODEX_SOURCE to the pinned plugin checkout}"
: "${RI_EVIDENCE_ROOT:?Set RI_EVIDENCE_ROOT to a new private output directory}"

exec python3 "$RI_CODEX_SOURCE/bench/run_bench.py" \
  --task fix-git \
  --attempt 1 \
  --evidence-root "$RI_EVIDENCE_ROOT"
