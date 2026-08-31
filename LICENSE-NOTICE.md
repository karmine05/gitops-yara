# License notice

The rule bundles under `rules/` come from
[elastic/protections-artifacts](https://github.com/elastic/protections-artifacts),
redistributed unmodified.

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

Every generated bundle carries the license notice in its header. Do not strip it.
