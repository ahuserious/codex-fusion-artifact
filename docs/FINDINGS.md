# Findings

## 1. The enforced fusion path worked live

The current standalone run completed a three-seat independent panel, structured comparative judge, fresh synthesis, two-reviewer gate, bounded amendment, and second two-reviewer gate. Every outbound request was exact `grok-4.5` through direct xAI. The first gate did not get rounded up to success: one `NEEDS_WORK` verdict forced an amendment. The amended artifact then passed 2/2.

This is stronger evidence than a provider ping or mocked adapter test because it exercises orchestration, semantic parsing, usage/cost accounting, persistence, response receipts, amendment state, and exact-artifact gating together.

## 2. Role diversity is not model diversity

All external seats were Grok 4.5. Different personas and independent context lenses can expose different concerns, but this run cannot measure the benefit of cross-family model diversity. An optional funded GPT/Claude/router seat remains future evidence.

## 3. Benchmark reward and evidence acceptance diverge

The selected Terminal-Bench trace earned reward 1.0. Its six Relentless Inception lifecycle runs also contain visible gate results. However, the trace predates final all-4.5 defaults and its recorded contract no longer satisfies the current validator. The correct statement is “the historical implementation solved the task,” not “the current release passed its exact benchmark gate.”

## 4. Negative traces are useful

The DeepSWE trace preserved a realistic integration failure: preflight material exceeded the permitted evidence size, so no fusion call occurred and the task earned reward 0. The source was tightened afterward, but without a paid rerun that fix remains offline-validated only for this harness path.

## 5. Cost is part of correctness

The standalone live ledger reports $0.268100 with zero unknown-cost calls. The system preserved a rejected gate and paid amendment instead of silently treating the initial synthesis as complete. That behavior is desirable for maximum-intelligence mode, but it also shows why release campaigns need explicit budgets and why this artifact stops short of repeated benchmarking.
