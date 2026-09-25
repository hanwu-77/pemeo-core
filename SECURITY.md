# Security policy

This is an experimental developer preview for synthetic data, not a production
identity service. Only the specific source candidate and recorded test scope
are evaluated; no long-term support or response SLA is promised.

## Reporting

Do not post credentials, assertions, tokens, database contents, personal files,
private paths or exploitable details in public issues. Use [GitHub private vulnerability reporting](https://github.com/hanwu-77/pemeo-core/security/advisories/new)
for PeMeO Core. GitHub reports this feature enabled for the public repository.
Report the affected version, impact and synthetic reproduction steps there.
The maintainer has not yet performed an independent end-to-end report submission
test; no response time or coordinated disclosure SLA is promised.

## Scope

Authentication/authorization bypass, replay, transaction partial writes,
credential lifecycle, unintended record mutation and sensitive logging are
in scope for review. Describe versions, synthetic reproduction steps and impact.
Do not attack deployments or other people's authenticators without permission.
See docs/KNOWN_LIMITATIONS.md for the trust boundary and unverified paths.

The project uses established cryptographic libraries. Automated tests and
AI-assisted review are not professional security certification. Do not claim
that an unverified credential-management issue could only cause lockout.
