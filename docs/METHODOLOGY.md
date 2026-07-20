# Methodology

## Selection rules

Evidence was selected by an explicit file allowlist after inspecting run schemas, model provenance, costs, gate status, harness outcomes, local paths, and credential-like patterns. “Green-looking” intermediate outputs were not promoted to final acceptance when a downstream gate or current validator disagreed.

## Live fusion record

The public replay retains semantic artifacts, schema-v3 ledger entries, invocation hashes, response hashes, and the corresponding raw normalized response artifacts. It excludes the mutable lock and aggregate `result.json` containing a local path. The ledger is the source of truth for call count, models, tokens, and provider cost; the manifest is the source of truth for stage status.

## Harness records

Terminal-Bench reward comes from the harness verifier. Relentless Inception lifecycle observations come from separate retained manifests and ledgers. Current compatibility is assessed independently by comparing recorded pin fields with the final source and running the current validator.

DeepSWE reward fields are copied from Pier's retained verifier JSON. Because `ri_runs` was empty, no fusion outcome is inferred.

## Checksums

`scripts/verify_artifact.py --refresh` deterministically lists every payload file, records its size and SHA-256, and writes `checksums/SHA256SUMS`. The manifest and checksum file are intentionally excluded from their own circular payload list; the Git commit and immutable tag bind them.

## Claim discipline

The report uses “observed” for retained physical outcomes, “covered” for offline/mock tests, “not run” for unexercised live surfaces, and “historical” when the evidence does not bind the final release tree.
