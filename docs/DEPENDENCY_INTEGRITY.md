# Dependency artifact integrity

Supported installation target: CPython 3.12, macOS 14+ arm64 and Ubuntu 24.04
x86_64 (glibc). Python metadata allowing other versions is not a claim that
these locks support them. CI labels macos-14 and ubuntu-24.04 currently mean
arm64 and x86_64 respectively. Each distributed archive needs its own
hash-bound installation and hosted-validation evidence.

Bootstrap, build and runtime/test locks pin wheel hashes. Install with
--require-hashes and --only-binary=:all:; no source-build fallback. Metadata,
wheel names, SHA-256 values and target-specific Requires-Dist are recorded in
release/python-artifacts.json. Only selected compatible wheels are permitted.
SQLAlchemy additionally requires greenlet on Linux x86_64; this dependency was
missing from the earlier Mac-derived list. Existing versions stay unchanged.
Hashes bind reviewed bytes; they do not certify upstream authors or safety.

pnpm is installed by npm ci using release/pnpm/package-lock.json with the
official tarball integrity. No lifecycle scripts run. Its downstream packages
use pnpm-lock.yaml integrity and a frozen installation. Do not replace these
steps with npx fetching only a version label. npm/Node itself remains a trusted
installation prerequisite provided by the runner or operator.

This is not a hermetic OS/browser build. Python/Node/setup actions, runner
images, system libraries, Chrome and its system dependencies remain separately
managed. Playwright library integrity is not Chrome binary integrity. A private hosted run for one archive does not verify a later archive or an
independent external installation. Cross-platform metadata checks alone cannot
close either gap.

Updating an allowed artifact requires reviewing its metadata, license notices,
hashes, all applicable platform dependencies, installation and regressions.
No wheel or Node executable/package code is redistributed in this source ZIP.
