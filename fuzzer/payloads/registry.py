"""Registry mapping each FieldType to its payload generator.

Keeping this as a single lookup table makes the system easy to extend: add
a generator in generators.py, wire it here, done. generate_for() is what the
rest of the pipeline calls.
"""

from ..models import Field, FieldType
from . import generators as g
from .base import Payload

# FieldType -> a zero-arg function returning that type's payloads.
_REGISTRY = {
    FieldType.FREETEXT: g.freetext_payloads,
    FieldType.SEARCH: g.search_payloads,
    FieldType.EMAIL: g.email_payloads,
    FieldType.INTEGER: g.integer_payloads,
    FieldType.PHONE: g.phone_payloads,
    FieldType.URL: g.url_payloads,
    FieldType.DATE: g.date_payloads,
    FieldType.PASSWORD: g.password_payloads,
}


def generate_for(field: Field) -> list[Payload]:
    """Return the payloads appropriate for a classified field.

    Falls back to free-text payloads for any type without a dedicated
    generator (FILE_UPLOAD, UNKNOWN), since those are the safe superset.
    """
    generator = _REGISTRY.get(field.field_type, g.freetext_payloads)
    payloads = generator()
    return _apply_field_constraints(field, payloads)


def _apply_field_constraints(field: Field, payloads: list[Payload]) -> list[Payload]:
    """Add a maxlength-boundary payload when the field declares one.

    A field with maxlength=N is interesting at exactly N and N+1 chars --
    does the server enforce the limit the browser advertises, or trust it?
    """
    if not field.maxlength:
        return payloads

    from .base import PayloadCategory

    extra = [
        Payload("A" * field.maxlength, PayloadCategory.BOUNDARY, "maxlen",
                f"Exactly maxlength ({field.maxlength})"),
        Payload("A" * (field.maxlength + 1), PayloadCategory.BOUNDARY, "maxlen",
                f"One over maxlength ({field.maxlength + 1})"),
    ]
    return [*payloads, *extra]
