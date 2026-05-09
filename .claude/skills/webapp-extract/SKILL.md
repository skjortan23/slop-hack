---
name: webapp-extract
description: Process captured proxy flows from $ENGAGEMENT_DIR/webapp/flows.jsonl into a deduped, structured endpoint inventory. Path-templates numeric/uuid/hash segments, extracts query/body parameters, tags auth method per endpoint, counts request volume. Output endpoints.jsonl. Use after webapp-capture, before webapp-fuzz.
---

# webapp-extract

Turn raw mitmproxy flow capture into a deduped, parameter-aware endpoint
inventory.

## Prerequisites

- `$ENGAGEMENT_DIR/webapp/flows.jsonl` exists (run `webapp-capture` first)

## Run

```bash
python3 /root/.claude/skills/webapp-extract/extract.py
```

Output: `$ENGAGEMENT_DIR/webapp/endpoints.jsonl`

Stdout prints a summary:
```json
{
  "total_endpoints": 47,
  "by_method": {"GET": 34, "POST": 11, "PUT": 1, "DELETE": 1},
  "by_auth": {"bearer": 28, "cookie": 7, "none": 12},
  "with_params": 31,
  "output": "/work/.../webapp/endpoints.jsonl"
}
```

## What it does

- **Path templating** — replaces:
  - numeric segments (`/users/123` → `/users/{id}`)
  - UUIDs (`/orders/8f1f...-...-...` → `/orders/{uuid}`)
  - long hex hashes (`/cache/a1b2c3...` → `/cache/{hash}`)
- **Dedup key** — `(method, host, path-template, content-type)`
- **Param merging** — across all observed instances of the same endpoint, union the query and body parameter names
- **Auth tag** — taken from request headers: `bearer` / `cookie` / `basic` / `none`

## Output schema (per line)

```json
{
  "method": "POST",
  "host": "api.acme.com",
  "port": 443,
  "scheme": "https",
  "path": "/v1/users/{id}/orders",
  "example_path": "/v1/users/12345/orders",
  "url_template": "https://api.acme.com/v1/users/{id}/orders",
  "params": {
    "query": ["page", "limit"],
    "body": ["product_id", "quantity"]
  },
  "auth": "bearer",
  "request_content_type": "application/json",
  "response_status": 200,
  "count": 7
}
```

## Useful follow-up queries

```bash
ENDPOINTS=$ENGAGEMENT_DIR/webapp/endpoints.jsonl

# Auth'd endpoints with parameters (highest fuzz value)
jq -c 'select(.auth=="bearer" and (.params.query|length>0 or .params.body|length>0))' $ENDPOINTS

# Mutating endpoints (POST/PUT/PATCH/DELETE)
jq -c 'select(.method | test("^(POST|PUT|PATCH|DELETE)$"))' $ENDPOINTS

# JSON APIs
jq -c 'select(.request_content_type | startswith("application/json"))' $ENDPOINTS

# Parameter inventory across the whole app
jq -r '.params.query[], .params.body[]' $ENDPOINTS | sort -u
```

## Next

- `webapp-fuzz` — replay endpoints with injection payloads
- Optional `arjun -u <url>` per endpoint to find HIDDEN params not seen in capture
