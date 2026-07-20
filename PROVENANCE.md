# Provenance

## Release source

- Plugin repository: `https://github.com/ahuserious/relentless-inception-codex`
- Tested release commit: `eaba350bc49cecd5e4ef56e76b0a3f5c188be326`
- Plugin version: `0.1.4`
- Commit tree: `e5b0f52aa5aa98a0693fbe413de640cf587432ef`
- Plugin source tree SHA-256: `1f9722b7659edd643fa62a1e36ae6ad6e008a0e46535668eab2af2665818ccaa`
- Installed Codex cache tree SHA-256: `1f9722b7659edd643fa62a1e36ae6ad6e008a0e46535668eab2af2665818ccaa`
- Codex CLI observed: `0.145.0-alpha.18`
- Host default: `openai/gpt-5.6-sol`, reasoning effort `xhigh`

The equal source/cache tree hashes were computed over relative path, executable mode, and per-file SHA-256 while excluding bytecode and `.DS_Store`.

## Current live run

- Run ID: `codex-0144-frontier-smoke-001`
- Created: `2026-07-20T05:26:55.783893+00:00`
- Completed: `2026-07-20T05:32:39.343744+00:00`
- Ledger schema: `3`
- Config hash: `9a1e638f11883d36f289c8d97a17281769e79487808daed98ce87fbb38b29a7e`
- Input hash: `67be687b9020a48ef06a884e92f684184d370adaf32ed7bafdb6385f00763a43`
- Task hash: `367e8e49b5e498b2c5a1d93711dded07b7b3481c87771ae3e018f3d009d05c03`

The published run omits `.run.lock` and `result.json`; the latter contained only an absolute local artifact-directory path beyond the already published semantic artifacts. All response receipts referenced by the ledger are retained.

## Terminal-Bench trace

- Campaign directory label: `codex-final-003`
- Task: `terminal-bench/fix-git`
- Harbor: `0.20.0`, commit `459ff6ec99417589b7f679d14ddf3b3f0ae4f1dc`
- Terminal-Bench source commit: `69671fbaac6d67a7ef0dfec016cc38a64ef7a77c`
- Image digest: `sha256:61e431c00c58df652287aadce5457634d9f9330cfdd153ebdf2802df0d540119`
- Host model: `openai/gpt-5.6-sol`, `xhigh`
- Reward: `1.0`

Recorded historical hashes differ from the final source: plugin `d32f79e0...` versus current `1f9722b7...`, and the current validator rejects the old timeout contract. The public summary preserves that drift explicitly.

## DeepSWE trace

- Campaign directory label: `codex-final-006`
- Task: `datacurve/anko-default-function-arguments`
- Pier: `0.3.0`
- DeepSWE source commit: `6db64a40f3318d8659238ff34a8cc4b491c49205`
- Task base commit: `9d2d84bb1564e9513287998c56ccf16c01c19008`
- Image digest: `sha256:31c8dce39317314800d1200610475ba27b98c71350d524d25e7df71d80c5752a`
- Reward: `0`

The run used final plugin/runner/validator hashes but a pre-fix benchmark-runtime tree. It dispatched no Relentless Inception model calls.
