"""Entry point: launch a browser, discover forms on a page, print them.

This is Phase 1 -- discovery only. Run it against a target URL to see the
forms and fields the tool detects before we add classification, payload
generation, and submission.

    python main.py https://testphp.vulnweb.com/login.php

Only run this against sites you own or have explicit permission to test.
"""

import sys

from playwright.sync_api import sync_playwright

from fuzzer.classifier import classify_all
from fuzzer.discovery import discover_forms
from fuzzer.payloads import generate_for


def run(url: str, headless: bool = True) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")

        forms = discover_forms(page)
        for form in forms:
            classify_all(form.fields)
        _print_report(url, forms)

        browser.close()


def _print_report(url: str, forms) -> None:
    print(f"\n{url}\n  found {len(forms)} form(s)\n")
    for i, form in enumerate(forms):
        print(f"  [Form {i}] {form.method.upper()} {form.action or '(no action)'}")
        for field in form.fields:
            payloads = generate_for(field)
            print(
                f"      - {field.tag}"
                f" name={field.name!r}"
                f" => {field.field_type.value.upper()}"
                f" ({len(payloads)} payloads)"
            )
            for p in payloads[:3]:
                print(f"          [{p.vuln}] {p.value[:40]!r}")
        if form.submitter:
            print(f"      > submit via name={form.submitter.name!r}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python main.py <url> [--headed]")
        sys.exit(1)

    target = sys.argv[1]
    run(target, headless="--headed" not in sys.argv)
