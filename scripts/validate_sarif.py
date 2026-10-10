#!/usr/bin/env python3
"""Validate a SARIF file against the official OASIS 2.1.0 schema (FR8).

Usage: scripts/validate_sarif.py csg.sarif
Needs: python3 -m pip install -r scripts/requirements-sarif.txt
"""
import json
import ssl
import sys
import urllib.error
import urllib.request

import certifi
import jsonschema

SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def schema_ssl_context() -> ssl.SSLContext:
    """Trust configured/default roots plus certifi, with TLS checks enabled."""
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=certifi.where())
    return context


def main(path: str) -> int:
    try:
        with urllib.request.urlopen(
            SCHEMA_URL, timeout=30, context=schema_ssl_context()
        ) as resp:
            schema = json.load(resp)
    except (urllib.error.URLError, OSError) as exc:
        print(f"Could not download the SARIF schema: {exc}", file=sys.stderr)
        print(
            "TLS verification remains enabled. Update certifi with "
            "'python3 -m pip install --upgrade certifi'. If your network uses "
            "a custom CA, set SSL_CERT_FILE to its trusted PEM bundle.",
            file=sys.stderr,
        )
        return 2
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
