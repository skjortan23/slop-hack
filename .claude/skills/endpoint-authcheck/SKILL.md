---
name: endpoint-authcheck
description: For each endpoint in $ENGAGEMENT_DIR/webapp/endpoints.jsonl, send the request WITHOUT auth headers and classify the response. Identifies endpoints that should require authentication but don't enforce it — auth bypass / access control gaps. Complements webapp-fuzz (which only fuzzes injection on query params); this skill covers the "who can call this without credentials?" question across ALL endpoints regardless of param shape. Logs unauth-200-with-data hits as high findings, validation-only (422/400) as medium, server-errors as low.
---

# endpoint-authcheck

Systematically tests every endpoint in `endpoints.jsonl` without
authentication headers, classifies the response, and logs findings for
unauth-accessible resources.

## Why this matters

`webapp-fuzz` (nuclei DAST) fuzzes injection vectors, mostly on query
parameters. It does NOT systematically test "what happens if I call this
without auth?". For path-parameter routes (`/api/users/{id}`,
`/api/scans/{scan_id}/log`) and body-parameter POST endpoints, that's the
primary attack surface — and webapp-fuzz misses it entirely.

endpoint-authcheck fills the gap:

```
extract → endpoints.jsonl
       ↓
       ├─ webapp-fuzz       (injection / query-param fuzzing)
       └─ endpoint-authcheck (auth bypass / access control across ALL eps)
```

## Usage

```bash
# Process all endpoints in $ENGAGEMENT_DIR/webapp/endpoints.jsonl
endpoint-authcheck

# Cap the probe count for smoke / time budget
endpoint-authcheck --limit 25

# Tighter rate-limit for stealth or weak targets
endpoint-authcheck --rate-limit 1.0

# One-shot mode (no endpoints.jsonl needed)
endpoint-authcheck --url https://api.target.com/admin/users --method GET

# JSON summary
endpoint-authcheck --json

# Probe without logging findings
endpoint-authcheck --no-log
```

## Classification table

| Response | Bucket | Severity | Logged? |
|---|---|---|---|
| 401 / 403 | `auth_enforced` | info | no |
| 200 with body matching auth-error pattern | `auth_enforced_200` | info | no |
| **200 with real data** (>200 bytes, JSON array/object indicators) | **`UNAUTH_EXECUTES`** | **high** | **YES** |
| 200 with empty/trivial body | `empty_200` | info | no |
| 400 / 422 (validation error) | `validation_only` | **medium** | YES |
| 405 method not allowed | `method_not_allowed` | (HTTP standards behavior) | no |
| 500 server error | `server_error` | **low** | YES |
| 3xx redirect | `redirect` | info | no |
| 404 | `not_found` | (assume route doesn't exist) | no |
| Network error / timeout | `network_error` | — | no |

## Request shaping

For each endpoint, sends:
- `Method`: from endpoints.jsonl (GET/POST/PUT/PATCH/DELETE)
- `Body`: for POST/PUT/PATCH, builds JSON `{"<param>": "test", ...}` from declared body params (capped at 10). Empty `{}` if no params declared.
- `Headers`: `Accept: application/json` + `Content-Type: application/json` for body-bearing methods. **No Authorization, no Cookie** — that's the whole point.
- `Path templates`: `{id}` → `1`, `{uuid}` → `00000000-...`, plus common FastAPI param names (`{scan_id}`, `{token_id}`, `{repo_full_name}`, `{job_id}`, `{filename}`).

## Outputs

- `$ENGAGEMENT_DIR/webapp/authcheck-results.jsonl` — per-endpoint result (probe + classification)
- Findings logged via `findings add` with `--source endpoint-authcheck`
- Summary JSON to stdout:
  ```json
  {
    "total": 51,
    "by_bucket": {
      "auth_enforced": 38,
      "UNAUTH_EXECUTES": 2,
      "validation_only": 5,
      "method_not_allowed": 4,
      "server_error": 2
    },
    "logged_findings": 9,
    "unauth_executes": [
      {"url": "https://app.codelight.ai/api/config", "method": "GET",
       "status": 200, "size": 234, "snippet": "..."},
      ...
    ]
  }
  ```

## Heuristics — "real data" vs "auth error in 200"

Some APIs return HTTP 200 with a JSON error body like
`{"detail": "Missing token"}` instead of properly returning 401. This skill
explicitly checks for those patterns so we don't false-positive them as
"unauth executes". The "real data" classification requires:

- Body size > 200 bytes (rules out small error envelopes), OR
- Body contains a data-indicator pattern: `"id":N`, `"name":"..."`, JSON
  array of objects, `"data": [...]`, `"items": [...]`, `"results": [...]`,
  `"users": [...]`, `"total": N`

If body matches an auth-error pattern (`"detail": "missing token"`,
`"error": "unauthorized"`), it's classified `auth_enforced_200` — not a
finding.

## Pairs with the rest

Standard webapp pipeline now:
```
webapp-capture   → flows.jsonl
webapp-extract   → endpoints.jsonl   (from proxy capture)
openapi-import   → endpoints.jsonl   (from /openapi.json — often richer)
endpoint-authcheck → access-control findings
webapp-fuzz      → injection findings (candidates)
webapp-confirm   → escalate confirmed candidates
findings export-md → report
```
