"""Findings output: a human-readable summary and optional JSON."""

import json
from collections import Counter
from dataclasses import asdict

from .analyzer import Finding

_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


def print_report(findings: list[Finding], submissions: int) -> None:
    """Print a console summary, findings sorted strongest-first."""
    print("\n" + "=" * 60)
    print(f"  Scan complete: {submissions} submissions, {len(findings)} finding(s)")
    print("=" * 60)

    if not findings:
        print("  No vulnerabilities detected.")
        return

    by_type = Counter(f.vuln_type for f in findings)
    print("  By type: " + ", ".join(f"{t}={n}" for t, n in by_type.items()))
    print("-" * 60)

    for f in sorted(findings, key=lambda x: _CONF_ORDER.get(x.confidence, 9)):
        print(f"  [{f.confidence.upper():6}] {f.vuln_type:16} field={f.field_name!r}")
        print(f"           {f.evidence}")
        print(f"           payload: {f.payload[:60]!r}")


def write_json(findings: list[Finding], path: str) -> None:
    """Write findings to a JSON file for tooling / later review."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)
