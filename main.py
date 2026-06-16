"""Entry point: launch a browser, discover forms on a page, print them.

This is Phase 1 -- discovery only. Run it against a target URL to see the
forms and fields the tool detects before we add classification, payload
generation, and submission.

    python main.py https://testphp.vulnweb.com/login.php

Only run this against sites you own or have explicit permission to test.
"""

import sys

from playwright.sync_api import sync_playwright

from fuzzer.discovery import discover_forms


def run(url: str, headless: bool = True) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")

        forms = discover_forms(page)
        _print_report(url, forms)

        browser.close()


def _print_report(url: str, forms) -> None:
    print(f"\n{url}\n  found {len(forms)} form(s)\n")
    for i, form in enumerate(forms):
        print(f"  [Form {i}] {form.method.upper()} {form.action or '(no action)'}")
        for field in form.fields:
            print(
                f"      - {field.tag}"
                f" name={field.name!r}"
                f" type={field.html_type!r}"
                f" label={field.label!r}"
                + (f" pattern={field.pattern!r}" if field.pattern else "")
            )
        if form.submitter:
            print(f"      > submit via name={form.submitter.name!r}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python main.py <url> [--headed]")
        sys.exit(1)

    target = sys.argv[1]
    run(target, headless="--headed" not in sys.argv)
