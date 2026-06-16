"""Form & field discovery using Playwright's live DOM.

We drive a real browser so JavaScript has already run by the time we look
for forms -- this is what lets us handle modern/SPA pages that a static
HTML parse would miss. Each <form> becomes a Form object holding its
fuzzable Fields and its submit trigger.
"""

from playwright.sync_api import Locator, Page

from .models import Field, Form, Submitter

# Inputs whose `type` we never fuzz: they don't take user data, or they're
# the trigger rather than a field. (Hidden tokens we still send, but the
# classifier/submitter handles those separately.)
NON_FUZZABLE_INPUT_TYPES = {"submit", "reset", "button", "image"}


def discover_forms(page: Page) -> list[Form]:
    """Return every form on the currently-loaded page."""
    forms: list[Form] = []
    form_locators = page.locator("form")

    for i in range(form_locators.count()):
        form_loc = form_locators.nth(i)
        selector = f"form >> nth={i}"
        forms.append(_build_form(form_loc, selector))

    return forms


def _build_form(form_loc: Locator, selector: str) -> Form:
    action = form_loc.get_attribute("action")
    method = (form_loc.get_attribute("method") or "get").lower()

    form = Form(action=action, method=method, selector=selector)
    form.fields = _discover_fields(form_loc, selector)
    form.submitter = _find_submitter(form_loc, selector)
    return form


def _discover_fields(form_loc: Locator, form_selector: str) -> list[Field]:
    """Collect input/textarea/select descendants as fuzzable fields."""
    fields: list[Field] = []
    field_locators = form_loc.locator("input, textarea, select")

    for j in range(field_locators.count()):
        el = field_locators.nth(j)
        tag = el.evaluate("e => e.tagName.toLowerCase()")
        html_type = (el.get_attribute("type") or "").lower() or None

        # Skip buttons / submit inputs -- those are triggers, not fields.
        if tag == "input" and html_type in NON_FUZZABLE_INPUT_TYPES:
            continue

        fields.append(
            Field(
                name=el.get_attribute("name"),
                tag=tag,
                html_type=html_type,
                selector=f"{form_selector} >> input, textarea, select >> nth={j}",
                label=_label_for(el),
                placeholder=el.get_attribute("placeholder"),
                pattern=el.get_attribute("pattern"),
                maxlength=_int_or_none(el.get_attribute("maxlength")),
                required=el.get_attribute("required") is not None,
                options=_select_options(el) if tag == "select" else [],
            )
        )

    return fields


def _find_submitter(form_loc: Locator, form_selector: str) -> Submitter | None:
    """Find the element that submits this form.

    A <button> with no type defaults to submit, so we accept buttons that
    aren't explicitly type=button/reset, plus input[type=submit].
    """
    candidates = form_loc.locator(
        "button:not([type=button]):not([type=reset]), input[type=submit]"
    )
    if candidates.count() == 0:
        return None

    el = candidates.first
    return Submitter(
        selector=f"{form_selector} >> button, input[type=submit] >> nth=0",
        name=el.get_attribute("name"),
        value=el.get_attribute("value"),
    )


def _label_for(el: Locator) -> str | None:
    """Best-effort label text: <label for=id>, wrapping label, or aria-label."""
    aria = el.get_attribute("aria-label")
    if aria:
        return aria.strip()

    el_id = el.get_attribute("id")
    if el_id:
        page = el.page
        lbl = page.locator(f"label[for='{el_id}']")
        if lbl.count() > 0:
            return (lbl.first.text_content() or "").strip() or None
    return None


def _select_options(el: Locator) -> list[str]:
    return el.locator("option").evaluate_all(
        "opts => opts.map(o => o.value)"
    )


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
