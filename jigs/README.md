# Reproduction Jigs

Every wrapper is opt-in and refuses to start without `--execute`. Each wrapper verifies an exact clean Git checkout before dispatch. They do not embed credentials or hide retries.

- `live-fusion/run.sh` exercises an equivalent direct-xAI fusion topology, disables user-config merging with the checked-in empty override, and requires a new private output directory.
- `terminal-bench/run.sh` invokes the source's fail-closed Harbor jig for one `fix-git` attempt.
- `deepswe/run.sh` verifies both source checkouts and invokes the source's Pier jig for one `anko-default-function-arguments` attempt.
- `current-source-pins.json` is the final release's harness pin snapshot. The historical Terminal-Bench trace used older source hashes, documented in the public result.

Review source commit `eaba350bc49cecd5e4ef56e76b0a3f5c188be326` and set the required path variables before executing. The harness wrappers may let pinned `uvx` commands download Harbor/Pier packages and may pull pinned container images; they require the separate `RI_ACCEPT_NETWORK_FETCHES=yes` acknowledgment.
