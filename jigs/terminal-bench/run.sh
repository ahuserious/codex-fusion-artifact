#!/bin/sh
set -eu

if [ "${1:-}" != "--execute" ]; then
  echo "Refusing billable harness run. Review this script, then pass --execute." >&2
  exit 2
fi

: "${RI_CODEX_SOURCE:?Set RI_CODEX_SOURCE to the pinned plugin checkout}"
: "${RI_EVIDENCE_ROOT:?Set RI_EVIDENCE_ROOT to a new private output directory}"
: "${RI_ACCEPT_NETWORK_FETCHES:?Set RI_ACCEPT_NETWORK_FETCHES=yes after reviewing uvx and container fetches}"

if [ "$RI_ACCEPT_NETWORK_FETCHES" != "yes" ]; then
  echo "RI_ACCEPT_NETWORK_FETCHES must equal yes" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/../verify-checkout.sh" \
  "$RI_CODEX_SOURCE" \
  "eaba350bc49cecd5e4ef56e76b0a3f5c188be326" \
  "Relentless Inception source"

exec python3 "$RI_CODEX_SOURCE/bench/run_bench.py" \
  --task fix-git \
  --attempt 1 \
  --evidence-root "$RI_EVIDENCE_ROOT"
