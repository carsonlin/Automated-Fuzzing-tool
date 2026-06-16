"""Field-type classification.

Discovery gives us raw fields, but the HTML `type` attribute is often just
"text" and tells us nothing useful. This stage layers several clues -- in
priority order -- to decide what a field *really* is, so the payload stage
can target it appropriately.

Priority:
  1. Explicit, trustworthy html_type (email/number/url/password/...).
  2. Keyword match on name / id / label / placeholder.
  3. The HTML5 `pattern` validation regex as a weak hint.
  4. Default to FREETEXT.
"""

import re

from .models import Field, FieldType

# html_type values we trust outright -> our FieldType.
EXPLICIT_TYPE_MAP: dict[str, FieldType] = {
    "email": FieldType.EMAIL,
    "password": FieldType.PASSWORD,
    "number": FieldType.INTEGER,
    "tel": FieldType.PHONE,
    "url": FieldType.URL,
    "date": FieldType.DATE,
    "datetime-local": FieldType.DATE,
    "month": FieldType.DATE,
    "week": FieldType.DATE,
    "search": FieldType.SEARCH,
    "file": FieldType.FILE_UPLOAD,
}

# Keyword patterns matched against name/id/label/placeholder text.
# First match wins, so order from most- to least-specific.
KEYWORD_RULES: list[tuple[FieldType, re.Pattern]] = [
    (FieldType.EMAIL, re.compile(r"e[-_]?mail", re.I)),
    (FieldType.PASSWORD, re.compile(r"pass(word|wd)?|pwd", re.I)),
    (FieldType.PHONE, re.compile(r"phone|mobile|tel(ephone)?|cell", re.I)),
    (FieldType.URL, re.compile(r"url|website|homepage|link", re.I)),
    (FieldType.DATE, re.compile(r"date|dob|birth|expir", re.I)),
    (FieldType.SEARCH, re.compile(r"search|query|\bq\b|find", re.I)),
    (FieldType.INTEGER, re.compile(r"\bage\b|\bcount\b|\bqty\b|quantity|amount|\bzip\b|number|\bnum\b", re.I)),
]

# A `pattern` of only digit-ish tokens implies a numeric field.
NUMERIC_PATTERN = re.compile(r"^\^?\\d|\[0-9\]|\\d[+*{]")


def classify(field: Field) -> FieldType:
    """Determine the real FieldType for a single field."""
    # 1. Trust an explicit html_type if we recognize it.
    if field.html_type and field.html_type in EXPLICIT_TYPE_MAP:
        return EXPLICIT_TYPE_MAP[field.html_type]

    # 2. Keyword-match the field's descriptive text.
    haystack = _descriptive_text(field)
    if haystack:
        for field_type, pattern in KEYWORD_RULES:
            if pattern.search(haystack):
                return field_type

    # 3. A numeric-looking validation pattern hints at an integer.
    if field.pattern and NUMERIC_PATTERN.search(field.pattern):
        return FieldType.INTEGER

    # 4. Nothing matched -> treat it as free text.
    return FieldType.FREETEXT


def classify_all(fields: list[Field]) -> None:
    """Classify a list of fields in place, setting each field.field_type."""
    for field in fields:
        field.field_type = classify(field)


def _descriptive_text(field: Field) -> str:
    """Join the field's human-readable clues into one searchable string."""
    parts = [field.name, field.label, field.placeholder]
    return " ".join(p for p in parts if p)
