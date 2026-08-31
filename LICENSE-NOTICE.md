# License notice

The rule bundles under `rules/` come from two upstream projects, each
redistributed unmodified:

- [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts)
  (Elastic License 2.0), and
- [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)
  (Apache-2.0), covering vulnerable and malicious Windows kernel drivers.

## Elastic rules (ELv2)

Those rules carry the **Elastic License 2.0 (ELv2)** license.
Read the terms at https://www.elastic.co/licensing/elastic-license

## What ELv2 permits

Use, copy, distribute, make available, and prepare derivative works, subject to
three limitations. The two that matter here:

1. You may not provide the software to third parties as a hosted or managed
   service where they get substantial access to its features.
2. You may not remove or obscure licensing, copyright, or other notices.

## What that means for us

Internal detection use across our own fleet is squarely permitted.

**Open question for legal before any customer-facing use.**
Fleet is a device management vendor. Shipping these rules to customers as part
of a managed offering is the exact shape ELv2 limitation 1 restricts. Internal
use is not in question; redistribution to customers is. Raise it before any
customer-facing use.

## LOLDrivers rules (Apache-2.0)

The `windows/loldrivers_*.yar` files come from
[magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers) and
carry the **Apache-2.0** license (full text at
https://www.apache.org/licenses/LICENSE-2.0). Apache-2.0 is permissive: the
only obligations are to keep the license and copyright notices, state changes
if any, and not use the project's names to endorse a derived product. No
customer-facing restriction of the ELv2 kind applies to these files.

Every generated bundle carries the license notice in its header. Do not strip it.
