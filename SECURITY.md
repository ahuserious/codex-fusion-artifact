# Security and Redaction Policy

This repository was built from an explicit allowlist. It does not contain auth files, credential values, provider headers, shell environments, private Codex sessions, local user configuration, raw job trajectories, or ephemeral secret mounts.

Only environment-variable names such as `XAI_API_KEY` appear in reproduction jigs. Never commit their values. The verifier rejects common provider, cloud, package-registry, OAuth/JWT, private-key, bearer/basic-auth, populated secret-field, and high-entropy token shapes. It also rejects macOS/Linux/Windows user paths, macOS ephemeral paths, the known private identity, and symbolic links that could escape the reviewed tree.

Published standalone response files retain non-secret provider request IDs because they participate in the exact receipt and audit trail. If a downstream mirror has a stricter telemetry policy, publish a separately named redacted derivative and do not claim its response hashes are byte-identical.

To report a sensitive-data issue, use GitHub's private vulnerability reporting for the source repository when available. Do not open a public issue containing the secret. A credential pasted into any chat or log should be rotated even if it does not appear here.
