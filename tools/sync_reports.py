#!/usr/bin/env python3
"""Keep fleet/ocsf/*.yml in step with fleet/*.sql and check the report shape.

    python3 tools/sync_reports.py          # rewrite every query: from its .sql
    python3 tools/sync_reports.py --check  # exit 1 if out of step or malformed

The .sql files are the source of truth. Statement N of fleet/X.sql becomes the
query: of report N in fleet/ocsf/X.yml, collapsed to one line (whitespace outside
string literals only). --check also compiles every statement against stub tables
built from Fleet's osquery schema plus the ATC tables in agent-options-v5.yml, so
a wrong table or column name fails here instead of on a live host, and verifies
that every detect.yml event carries the OCSF base attributes.
"""
import argparse
import json
import re
import sqlite3
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FILES = ["detect", "health-check", "test-pack", "verify"]
SCHEMA_URL = "https://raw.githubusercontent.com/fleetdm/fleet/main/schema/osquery_fleet_schema.json"
OCSF_BASE = {
    "class_uid", "class_name", "category_uid", "category_name", "activity_id",
    "activity_name", "type_uid", "severity_id", "severity", "time", "time_dt",
    "metadata.version", "metadata.product.name", "metadata.product.vendor_name",
    "metadata.log_name", "device.hostname", "device.uid",
}
NOT_OCSF = {"detect-0-1-publisher-row-counts"}  # publisher health, not an event


def statements(sql):
    body = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("--"))
    return [s.strip() + ";" for s in body.split(";") if s.strip()]


def one_line(stmt):
    parts = stmt.split("'")
    for i in range(0, len(parts), 2):  # even chunks are outside string literals
        parts[i] = re.sub(r"\s+", " ", parts[i])
    return "'".join(parts).strip()


def aliases(stmt):
    return {m.group(1) or m.group(2) for m in re.finditer(r'\bAS\s+(?:"([^"]+)"|(\w+))', stmt, re.I)}


def stub_db(schema):
    if schema and Path(schema).exists():
        raw = Path(schema).read_bytes()
    else:
        raw = urllib.request.urlopen(schema or SCHEMA_URL, timeout=30).read()
    db = sqlite3.connect(":memory:")
    cols = lambda names: ", ".join(f'"{c}"' for c in names)
    for t in json.loads(raw):
        db.execute(f'CREATE TABLE "{t["name"]}" ({cols(c["name"] for c in t["columns"])})')

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "auto_table_construction":
                    for name, spec in v.items():
                        db.execute(f'CREATE TABLE IF NOT EXISTS "{name}" ({cols(spec["columns"])})')
                else:
                    walk(v)

    walk(yaml.safe_load((ROOT / "fleet/agent-options-v5.yml").read_text()))
    return db


def compile_error(db, stmt):
    for _ in range(10):  # osquery-only functions become no-ops as they surface
        try:
            db.execute(stmt.rstrip(";"))
            return None
        except sqlite3.OperationalError as e:
            m = re.match(r"no such function: (\w+)", str(e))
            if not m:
                return str(e)
            db.create_function(m.group(1), -1, lambda *a: None)
    return "too many unknown functions"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--schema", help="osquery_fleet_schema.json path or URL (default: fleetdm/fleet main)")
    args = ap.parse_args()
    db = stub_db(args.schema) if args.check else None
    errors = []
    for name in FILES:
        sql_path, yml_path = ROOT / f"fleet/{name}.sql", ROOT / f"fleet/ocsf/{name}.yml"
        stmts = statements(sql_path.read_text())
        docs = yml_path.read_text().split("\n---\n")
        if len(stmts) != len(docs):
            errors.append(f"{name}: {len(stmts)} SQL statements vs {len(docs)} reports")
            continue
        out = []
        for i, (doc, stmt) in enumerate(zip(docs, stmts)):
            spec = yaml.safe_load(doc)["spec"]
            q = one_line(stmt)
            lines = doc.split("\n")
            qi = [j for j, l in enumerate(lines) if l.startswith("  query: ")]
            assert len(qi) == 1, f"{name}[{i}] expected exactly one query: line"
            lines[qi[0]] = "  query: " + json.dumps(q)
            out.append("\n".join(lines))
            if not args.check:
                continue
            tag = f"{name}[{i}] {spec['name']}"
            if spec["query"] != q:
                errors.append(f"{tag}: query differs from {sql_path.name}; run tools/sync_reports.py")
            if err := compile_error(db, stmt):
                errors.append(f"{tag}: {err}")
            if name == "detect" and spec["name"] not in NOT_OCSF:
                if missing := OCSF_BASE - aliases(stmt):
                    errors.append(f"{tag}: missing OCSF columns {sorted(missing)}")
                lit = {k: int(v) for v, k in re.findall(r"\b(\d+) AS (class_uid|activity_id|type_uid)\b", stmt)}
                if lit.keys() >= {"class_uid", "activity_id", "type_uid"} and lit["type_uid"] != lit["class_uid"] * 100 + lit["activity_id"]:
                    errors.append(f"{tag}: type_uid must be class_uid*100+activity_id")
        if not args.check:
            yml_path.write_text("\n---\n".join(out))
    if errors:
        print("\n".join(errors))
        sys.exit(1)
    print("ok" if args.check else "synced")


if __name__ == "__main__":
    main()
