#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: verify-checkout.sh CHECKOUT EXPECTED_COMMIT LABEL" >&2
  exit 2
fi

checkout=$1
expected_commit=$2
label=$3

if ! git -C "$checkout" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "$label is not a Git checkout: $checkout" >&2
  exit 2
fi

actual_commit=$(git -C "$checkout" rev-parse --verify HEAD)
if [ "$actual_commit" != "$expected_commit" ]; then
  echo "$label commit mismatch: expected $expected_commit, observed $actual_commit" >&2
  exit 2
fi

if [ -n "$(git -C "$checkout" status --porcelain --untracked-files=all)" ]; then
  echo "$label checkout is not clean; refusing an evidence replay from modified source" >&2
  exit 2
fi
