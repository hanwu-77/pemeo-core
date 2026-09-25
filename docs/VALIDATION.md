# Validation boundaries

This repository includes automated tests, a guarded synthetic PostgreSQL/browser runner and a GitHub workflow. Their presence does not mean any particular distributed archive passed them. For actual counts, platform versions, run identifiers and failures, use the separately published evidence record bound to that archive's SHA-256 and commit. Earlier archives' results remain historical evidence and must not be transferred by name.

An audit package may include JUnit, raw PostgreSQL logs, dependency snapshots and a full source diff. Such packages can contain local paths and are not public release artifacts. File hashes establish correspondence; they do not authenticate the remote service that generated a log or certify the process that ran the tests. Toolchain components such as Node, Chrome and the runner OS remain outside the source archive's artifact-hash closure.

Human login/cancel/approve observations consist of user reports and developer read-only checks; they cannot be independently replayed from a sanitized summary. Credential addition and revocation remain manually unverified. A failure of credential management must not be described as necessarily limited to lockout.

All security and capability claims are limited to the exact tested version and environment. See [dependency integrity](DEPENDENCY_INTEGRITY.md), [known limitations](KNOWN_LIMITATIONS.md) and [release evidence](../RELEASE_READINESS.md).
