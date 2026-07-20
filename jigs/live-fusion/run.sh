#!/bin/sh
set -eu

if [ "${1:-}" != "--execute" ]; then
  echo "Refusing billable run. Review this script, then pass --execute." >&2
  exit 2
fi

: "${RI_CODEX_SOURCE:?Set RI_CODEX_SOURCE to the pinned plugin checkout}"
: "${XAI_API_KEY:?Set XAI_API_KEY without writing it to this repository}"

exec "$RI_CODEX_SOURCE/scripts/ri" fuse \
  --task-file "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/task.txt" \
  --profile maximum_intelligence
