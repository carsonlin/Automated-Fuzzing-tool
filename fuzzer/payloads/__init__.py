"""Payload generation.

Each classified field gets a set of payloads appropriate to its type. We
split payloads into two intents:

  - BOUNDARY: valid-but-edge inputs that probe how the app handles limits
    (empty, very long, unicode, min/max). Catches crashes & bad validation.
  - ATTACK: malicious inputs probing for vulnerabilities (SQLi, XSS, command
    injection, path traversal, etc.).

`generate_for(field)` is the entry point: it looks up the right generator
for the field's FieldType and returns a list of Payloads.
"""

from .base import Payload, PayloadCategory
from .registry import generate_for

__all__ = ["Payload", "PayloadCategory", "generate_for"]
