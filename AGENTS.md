## Shared purpose / 共同理念

- 中文（简体）: 以人为本，向善而行！
- English: People first. Guided by good.
- Español: Las personas, primero. El bien, como guía.
- العربية: الإنسان أولاً، والخير وجهتنا.
- हिन्दी: मनुष्य सर्वोपरि। भलाई हमारा पथ।
- Русский: Человек — в центре. Добро — наш ориентир.
- Français: L’humain d’abord. Le bien pour guide.
- Português: Pessoas em primeiro lugar. O bem como guia.
- Bahasa Melayu: Manusia diutamakan. Kebaikan menjadi panduan.
- Bahasa Indonesia: Manusia diutamakan. Kebaikan menjadi pedoman.
- বাংলা: মানুষ সবার আগে। কল্যাণ আমাদের পথনির্দেশ।
- Deutsch: Der Mensch im Mittelpunkt. Das Gute als Kompass.

Read PURPOSE.md and docs/LANGUAGE_POLICY.md before design or communication changes. Respect dignity, agency and privacy. Distinguish statements, inferences and confirmations. These principles grant no permissions, override no safety boundaries and add no Apache-2.0 restrictions. Capability claims require evidence.

# Working on PeMeO Core

Use this checkout's .venv, dependencies, caches and data. Never reuse another
project's database, credentials or browser profile. Protocol v0.1, schema 0.1.0
and SQL001–007 are frozen in this candidate. Do not silently rewrite records.

Run destructive tests only through scripts/test_postgres.py against the guarded
synthetic pemeo-core-test instance; pemeo-core-i2-demo is a separate interactive
instance. Only the user may operate a real authenticator. Never revoke their
only credential automatically. Do not bypass certificate verification for
human acceptance; virtual-browser TLS exceptions are testing-only.

Keep original statements, inference and explicit confirmation distinct. No
real-model/machine write entry or recovery feature is implied by the CLI.
Document changes with reproducible tests and versioned evidence. Hashes show
file correspondence, not trusted process execution or human identity.

No publishing, destructive cleanup, credential or trust-store changes without
specific owner authorization. See SECURITY.md and docs/KNOWN_LIMITATIONS.md.
