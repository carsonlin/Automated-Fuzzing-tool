# Automated Fuzzing Tool

A web-form fuzzer. Point it at a page and it discovers every form, figures
out what each field is, fuzzes each one with type-appropriate payloads, and
reports likely vulnerabilities (SQL injection, XSS, server errors, info
disclosure).

It drives a real browser (Playwright), so it works on JavaScript-rendered
forms, not just static HTML.

> ⚠️ **Authorized testing only.** This tool sends real attack payloads.
> Only run it against sites you own or have explicit written permission to
> test. Targets are restricted to `localhost` unless you explicitly
> authorize a host with `--allow`.

## How it works

The scan is a pipeline of decoupled stages:

```
discover  ->  classify  ->  generate payloads  ->  submit  ->  analyze  ->  report
```

| Stage | Module | Job |
|-------|--------|-----|
| discover | `fuzzer/discovery.py` | Find forms + input/textarea/select fields in the live DOM |
| classify | `fuzzer/classifier.py` | Decide each field's real type (email, integer, password, ...) |
| payloads | `fuzzer/payloads/` | Generate type-appropriate test inputs (boundary + attack) |
| submit | `fuzzer/engine.py` | Fill the form and submit it, concurrently, capturing responses |
| analyze | `fuzzer/analyzer.py` | Inspect each response for vulnerability signals |
| report | `fuzzer/report.py` | Print findings and optionally write JSON |

A scope guard (`fuzzer/scope.py`) blocks unauthorized hosts before anything
is sent.

## Install

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Requires Python 3.11+.

## Usage

```bash
python main.py <url> [options]
```

| Option | Description |
|--------|-------------|
| `--allow HOST` | Authorize a non-localhost host (repeatable) |
| `--json OUT` | Write findings to a JSON file |
| `--concurrency N` | Number of parallel workers (default 8; use 1 for serial) |
| `--limit N` | Cap payloads per field (faster, less thorough) |
| `--headed` | Show the browser window instead of running headless |

### Examples

```bash
# Scan the bundled test server
python main.py http://127.0.0.1:8000/

# Scan an authorized staging host, save results, gentler concurrency
python main.py https://staging.example.com/ \
    --allow staging.example.com --json out.json --concurrency 4
```

## Try it against the test server

The repo ships a deliberately-vulnerable local server so you can see the
tool find real bugs (for local testing only — never expose it):

```bash
# terminal 1: start the target
python tests/server.py

# terminal 2: scan it
python main.py http://127.0.0.1:8000/
```

Expected: ~21 findings (SQL injection, reflected XSS, overflow-triggered
server errors) across the login form's fields.

## Project layout

```
main.py                       # entry point / orchestrator + CLI
fuzzer/
  models.py                   # core data types (Field, Form, SubmitResult, FieldType)
  discovery.py                # form & field discovery (sync Playwright)
  classifier.py               # field -> FieldType
  payloads/                   # per-type payload generators + registry
  engine.py                   # concurrent submission (async Playwright)
  analyzer.py                 # response -> findings
  report.py                   # console + JSON output
  scope.py                    # authorization guard
tests/
  server.py                   # local vulnerable target
  fixtures/sample_form.html   # static form for testing discovery offline
```

## Known limitations

- **Client-side constraints can blunt payloads.** The browser enforces
  `maxlength`, `type=number`, etc. before submitting, so some payloads get
  truncated/rejected before reaching the server. A raw-HTTP submission path
  would bypass this.
- **Dropdowns (`<select>`) aren't deeply fuzzed.** They currently receive
  free-text payloads they can't actually accept; proper option-tampering is
  future work.
- **Single page only.** No crawling/link-following yet — it fuzzes the forms
  on the URL you give it.
- **Findings are signals, not proof.** Each finding is a strong indicator
  worth manual confirmation, not a guaranteed exploit.
