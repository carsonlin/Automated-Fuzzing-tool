"""Form submission via Playwright.

For one (field, payload) pair we: reload a fresh form, fill the target field
with the payload and every other field with a valid filler value, trigger
submission, and capture the response for the analyzer.

We reload before each submission so payloads never bleed across attempts,
and we fill the non-target fields so the form passes basic validation and
the payload actually reaches the server (avoids false negatives).
"""

import time
from dataclasses import dataclass

from playwright.sync_api import Locator, Page, TimeoutError as PWTimeout

from .models import Field, FieldType, Form
from .payloads import Payload

# Valid dummy values used to fill the fields we're NOT currently fuzzing.
FILLERS: dict[FieldType, str] = {
    FieldType.EMAIL: "test@example.com",
    FieldType.PASSWORD: "Passw0rd!",
    FieldType.INTEGER: "42",
    FieldType.PHONE: "5551234567",
    FieldType.URL: "https://example.com",
    FieldType.DATE: "2020-01-01",
    FieldType.SEARCH: "test",
    FieldType.FREETEXT: "test",
}
DEFAULT_FILLER = "test"


@dataclass
class SubmitResult:
    """What came back from submitting one payload."""

    field_name: str | None
    payload: Payload
    status: int | None       # HTTP status, or None if no navigation happened
    body: str                # response HTML (for the analyzer to inspect)
    elapsed_ms: float        # round-trip time (for time-based detection)
    error: str | None = None


def submit_payload(
    page: Page, url: str, form: Form, target: Field, payload: Payload
) -> SubmitResult:
    """Fill the form with one payload in `target`, submit, capture response."""
    page.goto(url, wait_until="domcontentloaded")
    form_loc = page.locator(form.selector)

    # Fill every named field: the payload in the target, fillers elsewhere.
    for field in form.fields:
        if not field.name:
            continue
        value = payload.value if field is target else _filler_for(field)
        _fill_field(form_loc, field, value)

    return _submit_and_capture(page, form, target, payload)


def _fill_field(form_loc: Locator, field: Field, value: str) -> None:
    """Set a field's value, handling the input/textarea/select differences."""
    el = form_loc.locator(f"[name='{field.name}']")
    if el.count() == 0:
        return

    if field.tag == "select":
        # Can't type into a dropdown -- pick an option (tampering uses index/label).
        try:
            el.first.select_option(value)
        except PWTimeout:
            pass  # value isn't a valid option; skip rather than hang
        except Exception:
            pass
        return

    # input / textarea: clear then type. force/no-validate so HTML5 type
    # constraints (e.g. number fields) don't reject our payloads.
    try:
        el.first.fill(value, timeout=2000)
    except Exception:
        # Some inputs reject programmatic fill (e.g. number with letters);
        # fall back to a JS value-set so the payload still lands.
        el.first.evaluate("(e, v) => { e.value = v; }", value)


def _submit_and_capture(
    page: Page, form: Form, target: Field, payload: Payload
) -> SubmitResult:
    status: int | None = None
    error: str | None = None
    start = time.perf_counter()

    try:
        with page.expect_navigation(wait_until="domcontentloaded", timeout=5000) as nav:
            _trigger_submit(page, form)
        response = nav.value
        status = response.status if response else None
    except PWTimeout:
        # No navigation -- JS-handled form, or nothing happened. Not fatal.
        error = "no navigation after submit"
    except Exception as exc:  # noqa: BLE001 - record and move on
        error = str(exc)

    elapsed_ms = (time.perf_counter() - start) * 1000
    body = page.content()
    return SubmitResult(
        field_name=target.name,
        payload=payload,
        status=status,
        body=body,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def _trigger_submit(page: Page, form: Form) -> None:
    """Click the submit button if there is one; else press Enter in a field."""
    if form.submitter and form.submitter.name:
        btn = page.locator(f"{form.selector} >> [name='{form.submitter.name}']")
        if btn.count() > 0:
            btn.first.click()
            return

    form_loc = page.locator(form.selector)
    buttons = form_loc.locator("button:not([type=button]):not([type=reset]), input[type=submit]")
    if buttons.count() > 0:
        buttons.first.click()
        return

    # Fallback: focus the first text-ish field and press Enter.
    inputs = form_loc.locator("input")
    if inputs.count() > 0:
        inputs.first.press("Enter")


def _filler_for(field: Field) -> str:
    return FILLERS.get(field.field_type, DEFAULT_FILLER)
