"""Data structures that flow through the fuzzing pipeline.

A page is parsed into Forms; each Form holds the Fields we can fuzz plus
the submit trigger we click. Keeping these as plain dataclasses keeps the
stages (discovery -> classify -> payload -> submit -> analyze) decoupled.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .payloads.base import Payload


class FieldType(Enum):
    """Our internal notion of what a field really is.

    The HTML `type` attribute is only a hint (often just "text"), so the
    classifier maps each raw field onto one of these, which then decides
    what payloads we generate.
    """

    EMAIL = "email"
    PASSWORD = "password"
    INTEGER = "integer"
    PHONE = "phone"
    URL = "url"
    DATE = "date"
    SEARCH = "search"
    FILE_UPLOAD = "file"
    FREETEXT = "freetext"   # default catch-all
    UNKNOWN = "unknown"


@dataclass
class Field:
    """One fuzzable input within a form (input / textarea / select)."""

    name: str | None            # the `name` attribute the server expects
    tag: str                    # "input", "textarea", or "select"
    html_type: str | None       # raw `type` attribute, e.g. "text", "email"
    selector: str               # CSS/locator string to find it on the page
    label: str | None = None    # nearby <label> text, if any
    placeholder: str | None = None
    pattern: str | None = None  # HTML5 validation regex, if present
    maxlength: int | None = None
    required: bool = False
    options: list[str] = dc_field(default_factory=list)  # for <select>
    field_type: FieldType = FieldType.UNKNOWN            # filled in by classifier


@dataclass
class Submitter:
    """The element that triggers submission (button / input[type=submit])."""

    selector: str
    name: str | None = None
    value: str | None = None


@dataclass
class Form:
    """A discovered form: its fields plus how to submit it."""

    action: str | None
    method: str                 # "get" or "post"
    selector: str
    fields: list[Field] = dc_field(default_factory=list)
    submitter: Submitter | None = None


@dataclass
class SubmitResult:
    """What came back from submitting one payload (produced by the engine)."""

    field_name: str | None
    payload: Payload
    status: int | None       # HTTP status, or None if no navigation happened
    body: str                # response HTML (for the analyzer to inspect)
    elapsed_ms: float        # round-trip time (for time-based detection)
    error: str | None = None
