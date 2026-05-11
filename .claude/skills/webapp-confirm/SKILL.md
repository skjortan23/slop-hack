---
name: webapp-confirm
description: Verify webapp-fuzz / nuclei-DAST candidate findings with per-vuln-class confirmation tools, then log a new finding at elevated severity with smoking-gun evidence. sqli → sqlmap, xss → canary reflection in executable context (script tag / event handler / javascript: href), ssrf → interactsh OAST callback, ssti → escalation from {{7*7}} to {{config}} / class introspection, path traversal → escalation from /etc/passwd to /etc/shadow or /proc/self/environ, open-redirect → Location header to attacker URL. Closes the candidate→confirmed gap.
---

# webapp-confirm

The webapp-fuzz skill produces *candidate* findings at `medium` severity
based on indicator matching. This skill takes those candidates and
**confirms** them with stronger tests, then logs at appropriate severity.

## Why this matters

Severity rubric says no `critical` without 200-with-real-data evidence.
Until we confirm, we have indicators, not vulns. webapp-confirm closes the
gap:

```
webapp-fuzz finds:   "SQL syntax" error in response   → candidate (medium)
webapp-confirm runs: sqlmap successfully extracts DB   → confirmed (high)
```

## Usage

```bash
# Process all fuzz-results.jsonl from the engagement
webapp-confirm

# One class at a time
webapp-confirm --class sqli
webapp-confirm --class xss
webapp-confirm --class ssti

# Cap candidates (for smoke / time budget)
webapp-confirm --limit 5

# One-shot mode (no fuzz-results.jsonl needed)
webapp-confirm --url "https://target/api/users?id=1" --param id --class sqli

# Just probe, don't log
webapp-confirm --no-log --json
```

## Per-class confirmation strategies

| Class | Tool | "Confirmed" criterion |
|---|---|---|
| `sqli` | `sqlmap --batch --level 3 --risk 2 --time-sec 5` against the param | sqlmap stdout contains `"is vulnerable"`, `"the back-end DBMS is"`, or `Parameter:` |
| `xss` | inject unique canary `slopxss_<hex>`, fetch response, check if canary appears in `<script>...canary</script>` or `on<event>=` handler or `javascript:` href | reflection in **executable context** (not just HTML body or attribute value) |
| `ssrf` | `interactsh-client -n 1 -json` provisions OAST URL, inject as param, request the target | callback received within 30s on the OAST URL (v1: callback polling logged but manual confirm — see Limitations) |
| `ssti` | escalate from `{{7*7}}` (expects 49) to `{{config}}` / `{{request.application.__globals__}}` | response contains `SECRET_KEY` / `flask.config.Config` / `jinja` references |
| `path` / `path-traversal` / `lfi` | escalate `/etc/passwd` → `/etc/shadow` / `/proc/self/environ` / `..\windows\win.ini` | response contains `root:$` (shadow) / `PATH=` (environ) / `[fonts]` (win.ini) |
| `redirect` / `open-redirect` | inject attacker URL as param, check `Location:` header | `Location: https://example.org/...` |

Severity escalation when confirmed:
- sqli, xss, ssrf, path (passwd only) → **high**
- ssti, rce → **critical**
- path with /etc/shadow or /proc/self/environ → **critical** (auto via `severity_hint`)
- open-redirect → **low** (typical impact is phishing assist)

## Inputs / outputs

- **Input**: `$ENGAGEMENT_DIR/webapp/fuzz-results.jsonl` (from webapp-fuzz)
  OR explicit `--url --param --class` args
- **Output**: per-candidate JSON written to `$ENGAGEMENT_DIR/webapp/confirmed.jsonl`
  + findings logged via `findings add` at elevated severity
  + summary JSON to stdout

## Limitations (v1)

- **SSRF callback polling not wired automatically.** The skill provisions an
  interactsh URL and injects it, but doesn't yet poll for the callback. You
  need to start `interactsh-client -t /tmp/oast.log -json` in a background
  shell and inspect the log manually. v2 will wire this end-to-end.
- **sqlmap is slow** (30s–5min per param). The skill sets `--time-sec 5`,
  `--threads 4`, `--smart` to keep it bounded.
- **XSS confirmation is reflection-based**, not actual JS execution. For
  DOM-based XSS, the canary may execute but not appear in raw response.
  Headless render via Playwright would catch those; not yet integrated.
- **Body-fuzzing not handled** — only query parameters. POST-body or
  JSON-body fuzzing inherits from the fuzz-results.jsonl shape; if
  webapp-fuzz didn't capture them, webapp-confirm can't replay them.

## Pairs with webapp-fuzz

Standard flow:
```bash
webapp-extract              # flows.jsonl → endpoints.jsonl
webapp-fuzz                 # endpoints → nuclei DAST → fuzz-results.jsonl (candidates, medium)
webapp-confirm              # candidates → smoking gun → confirmed.jsonl (high/critical)
findings export-md          # report with confirmed findings featured
```
