# Source checkout installation and validation

Prerequisites: Python 3.12 for the tested baseline, Docker Engine/Desktop with
Compose v2 for database tests. Node.js >=22.13, pnpm 11.19.0 and Chrome are needed
only for the virtual browser test. The validated Node major is 22; higher
majors are allowed by the upstream engine range but are not validated here. Do not substitute an existing personal
browser profile. The demonstration currently has Chinese UI labels.

Run from the extracted source root, in a new directory. The version metadata
permits Python 3.11+; other versions are not established by this baseline.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple --only-binary=:all: --no-deps --require-hashes -r requirements-bootstrap.lock
.venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple --only-binary=:all: --require-hashes -r requirements-build.lock
.venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple --only-binary=:all: --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/python -m pip check
.venv/bin/ecom-validate protocol/ecom_protocol_v0.1.example.json --schema protocol/ecom_protocol_v0.1.schema.json
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q release/test_export_source.py release/test_dependency_install.py
```

Plain pytest intentionally skips integration cases. A green unit subset is not
full database/browser validation. The schema path is explicit because this is a
source checkout distribution, not a self-contained installed wheel with assets.

## Full synthetic database and browser tests

The fixed pemeo-core-test container/network/volume names support one checkout per
Docker daemon. Before first setup, inspect existing resources. If another
checkout owns those names, use a separate Docker environment; do not stop,
remove or repoint someone else's instance. The runner validates the exact DDL
mount and rejects the wrong checkout. It never accepts a supplied database URL.

Generate .env once, without printing the password or overwriting an existing file:

```sh
.venv/bin/python -c "import os,secrets; f=os.fdopen(os.open('.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w'); f.write('PEMEO_CORE_TEST_PASSWORD='+secrets.token_hex(24)+'\n'); f.close()"
docker compose up -d --wait --wait-timeout 60
npm ci --prefix release/pnpm --engine-strict --ignore-scripts --no-audit --no-fund --cache .cache/npm
node release/pnpm/node_modules/pnpm/bin/pnpm.cjs install --frozen-lockfile --engine-strict --ignore-scripts --store-dir .cache/pnpm-store
node release/pnpm/node_modules/pnpm/bin/pnpm.cjs exec playwright install chrome
export PEMEO_NODE="$(command -v node)"
export PEMEO_PLAYWRIGHT_MODULE="$PWD/node_modules/playwright"
.venv/bin/python scripts/test_postgres.py --browser
docker compose stop
```

On a machine that already has Chrome, omit its installation step. The runner
uses the disposable virtual authenticator and a fresh profile; no real passkey
is touched. Outputs are private under artifacts/validation. Do not publish raw
logs: they may contain checkout paths and synthetic environment identifiers.
Stopping preserves the synthetic volume. No removal/prune is part of this guide.

For non-browser database verification use `--webauthn` instead of `--browser`;
the browser case will remain skipped. Never run tests on the interactive demo.

## Optional real-authenticator demo

Read KNOWN_LIMITATIONS first. This uses pemeo-core-i2-demo, independent from the
synthetic test database. Ensure the fixed demo names are not already owned by
another checkout. Initialization fails on partial/existing database state rather
than resetting it. Only run on disposable synthetic data.

```sh
.venv/bin/python scripts/i2_demo.py init
.venv/bin/python scripts/i2_demo.py start
```

Open https://localhost:8443/ in your own browser. The generated certificate is
not automatically trusted. Inspect .local/i2-demo/PeMeO-Local-CA.crt and explicitly
approve a narrowly scoped localhost trust setup appropriate to your OS/browser.
Do not bypass warnings or install trust globally by an unattended script.
If trust cannot be established, stop the manual acceptance attempt.

When ready, run `scripts/i2_demo.py registration-window` with .venv/bin/python;
read the one-time token locally from .local/i2-demo/registration-token.txt and
enter it on the page. Never upload that file. Register your authenticator, log
in, review the default synthetic expression, cancel one prompt, then explicitly
approve after a fresh prompt. Confirm the receipt and unchanged original text.
These are user actions; automation is not a substitute for human acceptance.

Do not revoke your only credential. There is no recovery procedure. The `stop`
action stops only this demo listener; it does not delete records or stop Docker.

The bootstrap lock pins the installer itself, including its wheel hash. The
venv seed pip is used only to install that verified wheel from the official
index; subsequent package installation uses the upgraded pip. Existing RC4
environments are historical evidence and were not silently upgraded.

RC6 preparation: see DEPENDENCY_INTEGRITY.md for hashed installation and remaining platform/browser boundaries.
