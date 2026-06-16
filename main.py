"""Automated web-form fuzzer -- entry point / orchestrator.

Pipeline:  discover -> classify -> generate payloads -> submit -> analyze -> report

Usage:
    python main.py <url> [--allow HOST]... [--json OUT] [--headed] [--limit N]

    python main.py http://127.0.0.1:8000/
    python main.py https://my-staging.site/ --allow my-staging.site --json out.json

Only run against sites you own or have explicit written permission to test.
Non-localhost hosts must be authorized with --allow.
"""

import sys

from playwright.sync_api import sync_playwright

from fuzzer.analyzer import Finding, analyze
from fuzzer.classifier import classify_all
from fuzzer.discovery import discover_forms
from fuzzer.payloads import generate_for
from fuzzer.report import print_report, write_json
from fuzzer.scope import ScopeError, check_in_scope
from fuzzer.submitter import submit_payload

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def run(url: str, *, allow: set[str], json_out: str | None,
        headless: bool, limit: int | None) -> int:
    """Fuzz every form on the page. Returns the number of findings."""
    check_in_scope(url, allow)  # raises ScopeError if not authorized

    findings: list[Finding] = []
    submissions = 0

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        page.goto(url, wait_until="domcontentloaded")

        forms = discover_forms(page)
        print(f"Discovered {len(forms)} form(s) at {url}")

        for fi, form in enumerate(forms):
            classify_all(form.fields)
            fields = [f for f in form.fields if f.name]
            print(f"\n[Form {fi}] {form.method.upper()} {form.action or '(no action)'}"
                  f"  -- {len(fields)} fuzzable field(s)")

            for field in fields:
                payloads = generate_for(field)
                if limit:
                    payloads = payloads[:limit]
                print(f"  fuzzing {field.name!r} ({field.field_type.value}, "
                      f"{len(payloads)} payloads)")

                for payload in payloads:
                    result = submit_payload(page, url, form, field, payload)
                    submissions += 1
                    findings.extend(analyze(result))

        browser.close()

    print_report(findings, submissions)
    if json_out:
        write_json(findings, json_out)
        print(f"\n  findings written to {json_out}")
    return len(findings)


def _parse_args(argv: list[str]) -> dict:
    if not argv:
        print(__doc__)
        sys.exit(1)

    opts = {"url": argv[0], "allow": set(), "json_out": None,
            "headless": True, "limit": None}
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--allow":
            opts["allow"].add(argv[i + 1]); i += 2
        elif arg == "--json":
            opts["json_out"] = argv[i + 1]; i += 2
        elif arg == "--limit":
            opts["limit"] = int(argv[i + 1]); i += 2
        elif arg == "--headed":
            opts["headless"] = False; i += 1
        else:
            print(f"unknown argument: {arg}"); sys.exit(1)
    return opts


if __name__ == "__main__":
    o = _parse_args(sys.argv[1:])
    try:
        run(o["url"], allow=o["allow"], json_out=o["json_out"],
            headless=o["headless"], limit=o["limit"])
    except ScopeError as e:
        print(f"\n[SCOPE BLOCKED] {e}")
        sys.exit(2)
