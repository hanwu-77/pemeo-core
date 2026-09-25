# Architecture and scope

Protocol schema -> business invariants -> transactional canonical storage ->
rebuildable projections. The operational identity layer separately maintains
principals, sessions, candidates, challenges, idempotency and authentication
receipts. Protocol v0.1 and schema 0.1.0 are not changed by authentication.

WebAuthn verification uses the pinned library. Server-authenticated principals
are not inferred from client source.kind or agentRef. Explicit approval binds
to saved candidate content; the operation receipt does not rewrite its
metadata.verification into an objective truth claim.

Database roles limit ordinary writes. App credentials and administrators remain
trusted; grants do not validate all application-level JSON invariants. A human
statement being confirmed is not authorization to perform an external action.

The local UI is an example, not a household assistant or general API. Future
adapters must respect source identity, scope, immutable originals and separate
execution authorization. Personal memory, media and models are not shipped.
