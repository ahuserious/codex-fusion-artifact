#!/bin/sh
set -eu

if [ "${1:-}" != "--execute" ]; then
  echo "Refusing billable run. Review this script, then pass --execute." >&2
  exit 2
fi

: "${RI_CODEX_SOURCE:?Set RI_CODEX_SOURCE to the pinned plugin checkout}"
: "${RI_EVIDENCE_ROOT:?Set RI_EVIDENCE_ROOT to a new private output directory}"
: "${XAI_API_KEY:?Set XAI_API_KEY without writing it to this repository}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/../verify-checkout.sh" \
  "$RI_CODEX_SOURCE" \
  "eaba350bc49cecd5e4ef56e76b0a3f5c188be326" \
  "Relentless Inception source"

if [ -e "$RI_EVIDENCE_ROOT" ]; then
  echo "RI_EVIDENCE_ROOT already exists; choose a new private output directory" >&2
  exit 2
fi
mkdir -m 700 -p "$RI_EVIDENCE_ROOT"

export RELENTLESS_INCEPTION_CONFIG="$script_dir/empty-user-config.json"
export RELENTLESS_INCEPTION_DATA_DIR="$RI_EVIDENCE_ROOT"

exec "$RI_CODEX_SOURCE/scripts/ri" fuse \
  --task-file "$script_dir/task.txt" \
  --profile maximum_intelligence
