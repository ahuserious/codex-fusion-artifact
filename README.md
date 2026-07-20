# Codex Fusion Artifact

This repository is the public, curated evidence package for the limited-cost release campaign of [Relentless Inception for Codex](https://github.com/ahuserious/relentless-inception-codex). It follows the replay/result/jig pattern of the [TrustedRouter Fusion DRACO artifact](https://github.com/ahuserious/trustedrouter-fusion-artifact), while adding file-level checksums, a machine-readable manifest, secret/path scans, and CI verification.

> **Limited-cost engineering validation — not a benchmark leaderboard.** The campaign deliberately stopped after a small number of paid calls. It is not statistically powered, contains no confidence interval, and does not establish a population-level quality improvement from fusion.

## Headline result

The current frontier-only direct-xAI smoke completed ten receipt-bound calls, all requested and returned as exact `grok-4.5`. The first two-reviewer gate returned one `PASS` and one `NEEDS_WORK`; the synthesizer amended the artifact; the second exact-artifact gate returned `PASS` from both reviewers. The ledger records **$0.268100**, 81,060 total tokens, no unknown-cost calls, and no automatic model downgrade.

That proves the client-orchestrated map → independent panel → comparative judge → fresh synthesis → adversarial amendment → exact-hash re-gate path executed successfully. It does not prove that a Grok-only panel is cross-model diversity, nor that every optional provider works live.

## Published outcomes

| Surface | Published observation | Interpretation |
|---|---|---|
| Direct xAI fusion | `codex-0144-frontier-smoke-001`: 10/10 exact `grok-4.5` calls; amendment; final gate 2/2 `PASS`; $0.268100 | Current all-Grok-4.5 fusion and receipt path worked live |
| Terminal-Bench | `fix-git`: reward 1.0; historical 17-call mixed Grok 4.5/4.3 lifecycle; external-seat cost $0.32157745; Codex host cost $1.410944 | Task solved, but trace predates final all-4.5 defaults and current validator rejects its drifted contract |
| DeepSWE/Pier | `anko-default-function-arguments`: reward 0; 119/119 pass-to-pass, 0/2 fail-to-pass; no RI calls | Negative integration trace; preflight stopped before fusion, and the post-fix path was not rerun |
| OpenRouter | Not called live | Mock/request-shape coverage is not provider acceptance evidence |

Task reward and Relentless Inception gate acceptance are separate results. A reward of 1.0 does not repair a stale evidence contract, and a fusion gate cannot substitute for a benchmark verifier.

## Evidence map

- [`evidence/campaign-summary.json`](evidence/campaign-summary.json) is the machine-readable campaign index.
- [`evidence/runs/codex-0144-frontier-smoke-001/`](evidence/runs/codex-0144-frontier-smoke-001/) contains the exact publishable run artifacts and response-receipt chain. The local `result.json` and lock were excluded.
- [`evidence/terminal-bench/`](evidence/terminal-bench/) contains safe verifier outputs, provider ledgers, a curated host-result commitment, and the observed current-validator rejection.
- [`evidence/deep-swe/`](evidence/deep-swe/) contains the negative verifier result, a curated host-result commitment, and the bounded-preflight observation.
- [`jigs/`](jigs/) contains opt-in, billable reproduction wrappers and the pinned source snapshot.
- [`docs/FINDINGS.md`](docs/FINDINGS.md), [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md), and [`LIMITATIONS.md`](LIMITATIONS.md) separate observation, method, and claim boundaries.
- [`manifests/artifact-manifest.json`](manifests/artifact-manifest.json) and [`checksums/SHA256SUMS`](checksums/SHA256SUMS) bind every published payload file.

## Verify without API spend

```bash
python3 scripts/verify_artifact.py
python3 analysis/report.py
```

The verifier recomputes every live invocation/attempt/response/entry receipt, synthesis and gate hash, token and cost aggregate, handoff hash, harness cross-link, manifest hash, and selected-cost total. It also scans for private paths, populated secret fields, and common/high-entropy credential shapes. Mutation tests refresh the checksums after deliberate tampering and confirm the semantic verifier still fails closed. CI runs all three checks. Live jigs require an explicit `--execute` flag and can incur provider and Codex usage.

The two host costs are not independently recomputable from public raw result files: those files were withheld because they embed private paths and session links. Their selected non-sensitive fields are operator-attested in SHA-256-bound curated receipts. Provider-ledger costs and public reward files remain directly recomputable from this repository.

## License status

No distribution license has been selected for this artifact or its source plugin. Public visibility is not a grant of reuse rights. See [`NOTICE.md`](NOTICE.md).
