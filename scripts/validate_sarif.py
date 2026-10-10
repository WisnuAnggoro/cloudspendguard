#!/usr/bin/env python3
"""Validate a SARIF file against the official OASIS 2.1.0 schema (FR8).

Usage: scripts/validate_sarif.py csg.sarif
Needs: pip install jsonschema
"""
import json
import sys
import urllib.request

import jsonschema

SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def main(path: str) -> int:
    with urllib.request.urlopen(SCHEMA_URL, timeout=30) as resp:
        schema = json.load(resp)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    for e in errors[:10]:
        print(f"{'/'.join(map(str, e.path))}: {e.message[:200]}", file=sys.stderr)
    results = sum(len(r.get("results", [])) for r in doc.get("runs", []))
    print(f"{path}: {'INVALID' if errors else 'valid'} against SARIF 2.1.0 ({results} results, {len(errors)} errors)")
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
