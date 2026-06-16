"""Scope guard -- refuse to fuzz hosts we aren't authorized to test.

This tool sends real attack payloads. Running it against a site you don't
own or have permission to test is illegal in most jurisdictions. The guard
makes the safe path the default: only localhost is allowed unless the user
explicitly passes additional hosts.
"""

from urllib.parse import urlparse

# Always-allowed hosts (local testing).
DEFAULT_ALLOWED = {"localhost", "127.0.0.1", "::1"}


class ScopeError(Exception):
    """Raised when a target host is not in the authorized allowlist."""


def check_in_scope(url: str, extra_allowed: set[str] | None = None) -> None:
    """Raise ScopeError unless the URL's host is explicitly allowed."""
    host = (urlparse(url).hostname or "").lower()
    allowed = DEFAULT_ALLOWED | {h.lower() for h in (extra_allowed or set())}

    if host not in allowed:
        raise ScopeError(
            f"Refusing to fuzz '{host}': not in the authorized scope.\n"
            f"  Allowed: {sorted(allowed)}\n"
            f"  To authorize this host, pass --allow {host} "
            f"(only do this for sites you own or have written permission to test)."
        )
