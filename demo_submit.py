"""Demo: run the full pipeline and submit a few payloads to the test server.

Start the server first:  python tests/server.py
Then:                     python demo_submit.py
"""

import sys

from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from fuzzer.analyzer import analyze
from fuzzer.classifier import classify_all
from fuzzer.discovery import discover_forms
from fuzzer.payloads import generate_for
from fuzzer.submitter import submit_payload

URL = "http://127.0.0.1:8000/"


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(URL, wait_until="domcontentloaded")

        forms = discover_forms(page)
        form = forms[0]
        classify_all(form.fields)

        # Pick the password field and fire its payloads at the server.
        target = next(f for f in form.fields if f.name == "password")
        payloads = generate_for(target)

        print(f"Fuzzing field '{target.name}' with {len(payloads)} payloads:\n")
        all_findings = []
        for payload in payloads:
            result = submit_payload(page, URL, form, target, payload)
            findings = analyze(result)
            all_findings.extend(findings)
            tag = "  ".join(f"[{f.vuln_type}:{f.confidence}]" for f in findings)
            print(
                f"  [{payload.vuln:10}] status={result.status} "
                f"{result.elapsed_ms:6.0f}ms  {payload.value[:28]!r}   {tag}"
            )

        print(f"\n=== {len(all_findings)} finding(s) ===")
        for f in all_findings:
            print(f"  {f.confidence.upper():6} {f.vuln_type:16} field={f.field_name!r}")
            print(f"         evidence: {f.evidence}")
            print(f"         payload:  {f.payload[:50]!r}")

        browser.close()


if __name__ == "__main__":
    main()
