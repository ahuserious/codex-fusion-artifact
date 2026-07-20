# Reproduce

## Offline artifact verification

```bash
python3 scripts/verify_artifact.py
python3 -m unittest discover -s tests -v
python3 analysis/report.py
```

These commands use only the Python standard library and make no network or model calls.

## Source verification

```bash
git clone https://github.com/ahuserious/relentless-inception-codex.git
cd relentless-inception-codex
git checkout eaba350bc49cecd5e4ef56e76b0a3f5c188be326
python3 -m unittest discover -s tests -v
python3 -m compileall -q plugins/relentless-inception
```

## Billable replays

The wrappers under [`jigs/`](jigs/) refuse to run unless `--execute` is supplied. They also require the exact clean source commit. The live jig isolates the plugin from user configuration and writes to a new private output directory. Harness jigs require `RI_ACCEPT_NETWORK_FETCHES=yes` because the pinned `uvx` tools and container images may be downloaded. Review them first: they can consume Codex subscription quota, provider API credits, network bandwidth, Docker resources, and substantial wall time.

Equivalent results are not guaranteed. Provider implementations, model snapshots, harness images, Codex behavior, and stochastic outputs can drift. A new run should publish requested and actual models, exact pins, cost, raw outcome, and all failures instead of being silently merged with this artifact.
