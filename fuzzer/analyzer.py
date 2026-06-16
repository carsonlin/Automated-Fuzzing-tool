"""Response analysis -- turn raw submissions into vulnerability findings.

This is the stage that makes the difference between "submitted a payload" and
"found a bug". It inspects each SubmitResult for signals:

  - 5xx status            -> the input crashed the server
  - DB error strings      -> SQL injection
  - reflected payload      -> cross-site scripting (XSS)
  - response-time spike    -> time-based blind injection
  - stack traces           -> information disclosure

Each signal becomes a Finding with a confidence level. We use what payload
was sent (payload.vuln) to raise confidence: a 500 right after a SQLi payload
is far more telling than a 500 on random input.
"""

import re
from dataclasses import dataclass

from .payloads import PayloadCategory
from .submitter import SubmitResult

# Time-based blind injection: if a SLEEP/delay payload comes back this slow,
# it likely actually executed. Tunable.
TIME_THRESHOLD_MS = 4000

# Known database error signatures -> strong SQL-injection evidence.
SQL_ERROR_PATTERNS = [
    re.compile(r"SQL syntax", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
]

# Generic crash/stack-trace signatures -> information disclosure.
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"java\.lang\.[A-Za-z]+Exception"),
    re.compile(r"<b>(Warning|Fatal error)</b>", re.I),
]


@dataclass
class Finding:
    """A potential vulnerability detected from one submission."""

    field_name: str | None
    vuln_type: str          # "sqli", "xss", "server_error", "info_disclosure", ...
    confidence: str         # "high" | "medium" | "low"
    evidence: str           # short human-readable why
    payload: str            # the input that triggered it


def analyze(result: SubmitResult) -> list[Finding]:
    """Inspect one submission result and return any findings."""
    findings: list[Finding] = []
    body = result.body or ""
    sent = result.payload

    # 1. SQL error strings in the body -> SQL injection (highest signal).
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.search(body):
            findings.append(Finding(
                result.field_name, "sqli", "high",
                f"DB error matched /{pattern.pattern}/ in response",
                sent.value,
            ))
            break

    # 2. Reflected XSS: an XSS payload comes back verbatim & unescaped.
    if sent.vuln == "xss" and sent.value and sent.value in body:
        findings.append(Finding(
            result.field_name, "xss", "high",
            "XSS payload reflected unescaped in response body",
            sent.value,
        ))

    # 3. Server error (5xx). Confidence depends on what we sent: an attack
    #    payload making the server 500 is more interesting than a fluke.
    if result.status and result.status >= 500:
        # Don't double-report if we already pinned it as SQLi above.
        if not any(f.vuln_type == "sqli" for f in findings):
            confidence = "medium" if sent.category is PayloadCategory.ATTACK else "low"
            findings.append(Finding(
                result.field_name, "server_error", confidence,
                f"HTTP {result.status} triggered by {sent.vuln} payload",
                sent.value,
            ))

    # 4. Time-based blind: a time-delay payload that actually delayed.
    if "sleep" in sent.description.lower() or "time" in sent.vuln.lower():
        if result.elapsed_ms >= TIME_THRESHOLD_MS:
            findings.append(Finding(
                result.field_name, "blind_injection", "medium",
                f"Response took {result.elapsed_ms:.0f}ms on a time-delay payload",
                sent.value,
            ))

    # 5. Stack trace / framework error -> information disclosure.
    for pattern in STACK_TRACE_PATTERNS:
        if pattern.search(body):
            findings.append(Finding(
                result.field_name, "info_disclosure", "medium",
                f"Stack trace / framework error exposed (/{pattern.pattern}/)",
                sent.value,
            ))
            break

    return findings
