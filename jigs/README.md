# Reproduction Jigs

Every wrapper is opt-in and refuses to start without `--execute`. They call the pinned source plugin; they do not embed credentials, install dependencies, or hide retries.

- `live-fusion/run.sh` exercises an equivalent direct-xAI fusion topology.
- `terminal-bench/run.sh` invokes the source's fail-closed Harbor jig for one `fix-git` attempt.
- `deepswe/run.sh` invokes the source's Pier jig for one `anko-default-function-arguments` attempt.
- `current-source-pins.json` is the final release's harness pin snapshot. The historical Terminal-Bench trace used older source hashes, documented in the public result.

Review source commit `eaba350bc49cecd5e4ef56e76b0a3f5c188be326` and set the required path variables before executing.
