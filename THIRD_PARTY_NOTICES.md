# Third-party licenses and distribution scope

Apache-2.0 applies to project-authored material. It does not relicense third-party
libraries or the unmodified license/attribution texts under third_party/licenses.
The inventory records pinned installed macOS distributions and selected official
Linux wheels. It includes platform-specific dependencies, not only packages
installed on the preparation machine. Artifact hashes and scope are recorded
in release/python-artifacts.json and the inventory JSON files.

This candidate distributes PeMeO source and dependency declarations only. It
contains no Python dependency wheels/code, virtual environment, Node modules,
OpenSSL/libpq binaries, PostgreSQL image or real credentials. Dependencies are
obtained separately during installation. License texts are copied unmodified
for review and attribution; they are not PeMeO-authored Apache material.

| Package | Version | Declared license |
| --- | --- | --- |
| annotated-types | 0.8.0 | MIT |
| attrs | 26.1.0 | MIT |
| iniconfig | 2.3.0 | MIT |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.6.0 | MIT |
| psycopg | 3.3.5 | LGPL-3.0-only |
| psycopg-binary | 3.3.5 | LGPL-3.0-only |
| pydantic | 2.13.5 | MIT |
| pydantic_core | 2.46.5 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| pytest | 9.0.3 | MIT |
| referencing | 0.37.0 | MIT |
| rpds-py | 2026.6.3 | MIT |
| SQLAlchemy | 2.0.54 | MIT |
| greenlet (Linux x86_64) | 3.5.6 | MIT AND PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| rfc8785 | 0.1.4 | Apache-2.0 |
| cbor2 | 6.1.4 | MIT |
| cffi | 2.1.1 | MIT-0 |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| pyasn1 | 0.6.4 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD-2-Clause |
| pycparser | 3.0 | BSD-3-Clause |
| pyOpenSSL | 26.4.0 | Apache-2.0 |
| webauthn | 3.0.0 | BSD-3-Clause |

## Items requiring distribution-specific review

psycopg and psycopg-binary are LGPL-3.0-only, not permissive. Do not relabel or
vendor them as Apache-2.0. Modified-library or combined/binary distribution has
additional obligations; review actual LGPL/GPL texts and replacement/relinking
requirements before shipping wheels, executables or containers. No conclusion
of blanket license compatibility is implied by this inventory.

The installed macOS psycopg-binary includes libpq, OpenSSL, Kerberos and LDAP
libraries. cryptography also has platform-dependent native components. Python
metadata is not a complete native-library SBOM. No such binary is in this source
candidate; publishing a bundled binary is a separate release gate.

Build tools (requirements-build.lock), pnpm, Playwright/its browser and Docker
images are independently obtained tools, not relicensed or bundled here.
Record their exact license/version in the preparation evidence as well.
Source and binary dependency obligations must not be conflated.

## Follow-up: installer and notice completeness

The installer is pinned by requirements-bootstrap.lock (pip 26.2, MIT); the
bootstrap wheel is obtained separately, not bundled. Build-tool license texts
retain upstream directory structure so vendored notices with the same basename
do not overwrite each other. The exporter validates each declared notice hash.

The LGPL text incorporates GPLv3: an unmodified GPL-3.0 text is included for
reference alongside LGPL notices. See docs/DISTRIBUTION_LICENSE_REVIEW.md for
source-only scope and the separate obligations before any binary distribution.

pnpm 11.19.0 is bootstrapped with its npm tarball integrity pinned. Its root
MIT license and bundled license/notice-named files are preserved under
third_party/licenses/pnpm; TOOLS.json records each original member path.
Percent-encoded member names avoid path collisions and do not relax the ban
on bundling node_modules. These notices are not a complete native-tool SBOM.

## Language-selection research data

`docs/brand/language-selection-data.json` is a selected, sorted and rounded derivative of OBDILCI ResultsV6 (July 2025), under CC-BY-SA-4.0: https://creativecommons.org/licenses/by-sa/4.0/ . Source: https://www.obdilci.org/wp-content/uploads/2025/07/ResultsV6.xlsx . Attribution: Observatory of Linguistic and Cultural Diversity in the Internet. The data file is not relicensed as Apache-2.0. This notice concerns that data file, not the original PeMeO implementation or original editorial translations.
