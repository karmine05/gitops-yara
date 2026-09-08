# skills/

Reusable agent skills for the dexterlabs threat-hunting stack, maintained alongside
the YARA rules and OCSF reports in this repo.

## windows-endpoint-threat-hunting

Hunt/investigate a Windows endpoint for compromise using Fleet MCP only.
Source of truth: `~/.hermes/skills/security/windows-endpoint-threat-hunting/`
on the Hermes operator host; this copy is the version-controlled mirror.

Layout (standard agent-skill format):

- `SKILL.md` — hard rules (schema-first gate, 24h time bound, one query at a
  time, 90s first-fire retry), phase order, anti-forensics interpretation,
  report format
- `references/hunt-queries.md` — validated osquery SQL per OCSF module, all
  time-bounded to 24h by default
- `references/ocsf-mapping.md` — OCSF event-class to Windows-source mapping
  and OCSF JSON record templates

To load into a Hermes agent profile: copy the
`windows-endpoint-threat-hunting/` directory into the profile's
`~/.hermes/skills/security/` (or any category dir). To install as a raw
markdown runbook, read `SKILL.md` top to bottom.

Sync rule: after any hunt that produces a new lesson, patch the skill in
`~/.hermes/skills/` first, then re-copy into this folder and push.
