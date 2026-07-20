# Limitations

## Cost-limited sample

This is a release-engineering artifact, not a controlled benchmark. Only one current direct-xAI fusion run, one selected Terminal-Bench trace, and one selected DeepSWE trace are reported. There are no repeated seeds, matched solo baseline, confidence intervals, blinded graders, or significance tests.

The selected receipts do not represent the full development spend. Failed experiments and earlier iterations were not aggregated into a complete billing statement. Costs here are exact only where the retained host or provider ledger reports them.

## Model and provider coverage

The current live fusion replay used role-diverse calls to one external model family: exact `grok-4.5`. That is multi-agent deliberation, not cross-model fusion. The Codex host used `gpt-5.6-sol`, but this small campaign does not isolate the marginal value of combining the host and external model family.

OpenRouter, OpenRouter native Fusion, direct OpenAI, direct Anthropic, and TrustedRouter-compatible transports were not exercised with funded live credentials in this release campaign. Their unit and mock coverage must not be described as live acceptance.

## Harness comparability

The Terminal-Bench trace is historical evidence from a pre-final mixed Grok 4.5/4.3 profile. Its reward is real, but its recorded plugin, runner, validator, timeout, and runtime pins do not match the final release contract. The current validator therefore rejects it before semantic acceptance. It is published as an honest historical trace, not a current-version pass.

The DeepSWE/Pier trace stopped before any fusion dispatch because the preflight evidence packet exceeded its bound. It earned reward 0 and contains zero Relentless Inception runs. Source was later tightened to cap preflight material, but the paid physical task was not rerun.

## Evidence redaction

Raw Codex sessions, trajectories, job logs, auth state, local configuration, absolute private paths, ephemeral secret-file paths, and the local `result.json` were withheld. Exact publishable provider response artifacts were retained for the standalone live run because content review and automated scans found no credential or local-identity values. The manifest identifies the public derivative; it is not a claim that every private source byte is present.

## Integrity boundary

SHA-256 receipts detect accidental drift and inconsistent partial artifacts. They are not signatures against an attacker who can rewrite the entire repository and recompute hashes. The immutable Git commit/tag is the external anchor for this publication.
