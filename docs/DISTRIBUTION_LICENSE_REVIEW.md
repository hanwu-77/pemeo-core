# Distribution-specific license review — source candidate

Date: 2026-09-21. Engineering assessment, not a legal clearance opinion.
Apache-2.0 is selected for PeMeO-authored material; it does not cover third-party
code, establish ownership of historical contributions, or grant brand rights.

## Current source-only artifact

The reviewed whitelist ships PeMeO source, configuration, dependency references,
and unmodified notices. It does not ship dependency wheels, installed modules,
PostgreSQL images, native libraries or executables. Installation downloads
third-party distributions separately. Retain attribution and exact license texts;
do not represent psycopg or psycopg-binary as Apache. Both declare LGPL-3.0-only.
The added GPLv3 text accompanies the LGPL's incorporation of GPLv3.

This scope reduces redistribution work for unbundled libraries; it is not a
blanket compatibility opinion or permission to omit obligations on a later
combined distribution. Public source ownership/attribution still needs owner
confirmation. No additional restrictions are added to the Apache license.

## If the distribution changes

| Artifact | Required assessment before shipping |
| --- | --- |
| PeMeO-only wheel without vendored dependencies | Inspect actual archive contents and metadata; retain notices; verify separation and asset completeness. |
| Dependency wheel mirror or installer bundling psycopg | Verify the exact library version and corresponding source, preserve copyright and LGPL/GPL notices, satisfy the applicable source-distribution or source-offer method; a generic project URL alone is not an automatic substitute. |
| Executable, appliance or container bundling linked libraries | Inventory actual native binaries and licenses per platform; assess LGPL section 4 modification/replacement or relinking path, reverse-engineering permissions for debugging modifications, and installation information where applicable. Verify the chosen mechanism in the delivered artifact. |
| Modified LGPL library | Track modifications and provide the required library source under the applicable terms; do not silently relicense as Apache. |

Native libpq/OpenSSL/Kerberos/LDAP and cryptography components need their own
versioned inventory and notices. Copying the Python package license alone is
insufficient. This release does not establish those future obligations as met.

Sources consulted:
- https://www.gnu.org/licenses/lgpl-3.0.html (LGPL sections 0 and 4; exact local text under third_party/licenses/psycopg/)
- https://www.gnu.org/licenses/gpl-3.0.txt (official text downloaded and hashed)
- https://www.psycopg.org/psycopg3/docs/basic/install.html (binary versus local/pure Python distribution; live documentation is not a version-specific 3.3.5 guarantee)
- Exact 3.3.5 wheel metadata/notices in third_party/DEPENDENCIES.json.
