"""Concurrent submission engine (async Playwright).

Discovery runs once (sync, elsewhere) and produces plain Form/Field data.
This engine takes that data and fuzzes it concurrently: a pool of worker
pages each pull (form, field, payload) tasks off a shared queue, so many
submissions are in flight at once instead of one-at-a-time.

The pure-logic stages (payloads, analyzer) are reused unchanged -- only the
Playwright calls needed an async variant.
"""

import asyncio
import time

from playwright.async_api import (
    Locator,
    Page,
    TimeoutError as PWTimeout,
    async_playwright,
)

from .analyzer import Finding, analyze
from .models import Field, FieldType, Form, SubmitResult
from .payloads import generate_for

# Cosmetic assets we don't need while fuzzing -- aborting them speeds reloads.
_BLOCKED = ("image", "stylesheet", "font", "media")

# Valid dummy values used to fill the fields we're NOT currently fuzzing,
# so the form passes basic validation and the payload reaches the server.
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


async def fuzz_concurrent(
    url: str, forms: list[Form], *, concurrency: int, headless: bool,
    limit: int | None,
) -> tuple[list[Finding], int]:
    """Fuzz all forms concurrently. Returns (findings, submission_count)."""
    queue: asyncio.Queue = asyncio.Queue()
    for form in forms:
        for field in form.fields:
            if not field.name:
                continue
            payloads = generate_for(field)
            for payload in (payloads[:limit] if limit else payloads):
                queue.put_nowait((form, field, payload))

    total = queue.qsize()
    findings: list[Finding] = []
    counter = [0]
    print(f"  queued {total} submissions across {concurrency} workers\n")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        workers = [
            asyncio.create_task(
                _worker(browser, url, queue, findings, counter, total)
            )
            for _ in range(concurrency)
        ]
        await asyncio.gather(*workers)
        await browser.close()

    return findings, counter[0]


async def _worker(browser, url, queue, findings, counter, total) -> None:
    """One worker: its own page, drains the queue until empty."""
    page = await browser.new_page()
    await page.route(
        "**/*",
        lambda route: (
            route.abort()
            if route.request.resource_type in _BLOCKED
            else route.continue_()
        ),
    )
    try:
        while True:
            try:
                form, target, payload = queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            result = await _submit_one(page, url, form, target, payload)
            findings.extend(analyze(result))  # safe: asyncio is single-threaded
            counter[0] += 1
            if counter[0] % 20 == 0 or counter[0] == total:
                print(f"  ... {counter[0]}/{total} submitted")
            queue.task_done()
    finally:
        await page.close()


async def _submit_one(
    page: Page, url: str, form: Form, target: Field, payload
) -> SubmitResult:
    await page.goto(url, wait_until="domcontentloaded")
    form_loc = page.locator(form.selector)

    for field in form.fields:
        if not field.name:
            continue
        value = payload.value if field is target else _filler_for(field)
        await _fill_field(form_loc, field, value)

    status = None
    error = None
    start = time.perf_counter()
    try:
        async with page.expect_navigation(wait_until="domcontentloaded", timeout=5000) as nav:
            await _trigger_submit(page, form)
        response = await nav.value
        status = response.status if response else None
    except PWTimeout:
        error = "no navigation after submit"
    except Exception as exc:  # noqa: BLE001
        error = str(exc)

    elapsed_ms = (time.perf_counter() - start) * 1000
    body = await page.content()
    return SubmitResult(target.name, payload, status, body, elapsed_ms, error)


async def _fill_field(form_loc: Locator, field: Field, value: str) -> None:
    el = form_loc.locator(f"[name='{field.name}']")
    if await el.count() == 0:
        return
    if field.tag == "select":
        try:
            await el.first.select_option(value)
        except Exception:
            pass
        return
    try:
        await el.first.fill(value, timeout=2000)
    except Exception:
        await el.first.evaluate("(e, v) => { e.value = v; }", value)


async def _trigger_submit(page: Page, form: Form) -> None:
    if form.submitter and form.submitter.name:
        btn = page.locator(f"{form.selector} >> [name='{form.submitter.name}']")
        if await btn.count() > 0:
            await btn.first.click()
            return
    form_loc = page.locator(form.selector)
    buttons = form_loc.locator(
        "button:not([type=button]):not([type=reset]), input[type=submit]"
    )
    if await buttons.count() > 0:
        await buttons.first.click()
        return
    inputs = form_loc.locator("input")
    if await inputs.count() > 0:
        await inputs.first.press("Enter")


def _filler_for(field: Field) -> str:
    return FILLERS.get(field.field_type, DEFAULT_FILLER)
