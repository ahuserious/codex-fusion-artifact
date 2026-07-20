# Methodology

## Selection rules

Evidence was selected by an explicit file allowlist after inspecting run schemas, model provenance, costs, gate status, harness outcomes, local paths, and credential-like patterns. “Green-looking” intermediate outputs were not promoted to final acceptance when a downstream gate or current validator disagreed.

## Live fusion record

The public replay retains semantic artifacts, schema-v3 ledger entries, invocation hashes, response hashes, and the corresponding raw normalized response artifacts. It excludes the mutable lock and aggregate `result.json` containing a local path. The ledger is the source of truth for call count, models, tokens, and provider cost; the manifest is the source of truth for stage status.

## Harness records

Terminal-Bench reward comes from the public harness verifier output. Relentless Inception lifecycle observations come from separate retained manifests and ledgers. Current compatibility is assessed independently by comparing recorded pin fields with the final source and running the current validator. The withheld host result and run contract are SHA-256 committed; selected non-sensitive fields are explicitly labeled as operator-attested.

DeepSWE reward fields are copied from Pier's retained verifier JSON. Because `ri_runs` was empty, no fusion outcome is inferred. The preflight cause is a curated observation bound to the withheld transcript and trajectory hashes, not a claim that those private files are publicly reproducible.

## Checksums

`scripts/verify_artifact.py --refresh` deterministically lists every payload file, records its size and SHA-256, and writes `checksums/SHA256SUMS`. The manifest and checksum file are intentionally excluded from their own circular payload list; the Git commit and immutable tag bind them.

Normal verification additionally derives every live receipt ID from canonical JSON, checks raw response artifacts against the ledger, recomputes usage/cost totals, binds synthesis text to both gates, validates gate votes and the execution handoff, cross-checks harness summaries and curated commitments, and scans the complete payload tree for credential/private-path patterns. The mutation suite changes semantic evidence and then refreshes file hashes, demonstrating that checksum regeneration cannot hide those mutations.

## Claim discipline

The report uses “observed” for retained physical outcomes, “covered” for offline/mock tests, “not run” for unexercised live surfaces, and “historical” when the evidence does not bind the final release tree.
