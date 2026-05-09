---
name: webapp-fuzz
description: Replay extracted endpoints with injection payloads via nuclei DAST mode to detect webapp vulnerabilities — SQLi, XSS, SSTI, path traversal, command injection, SSRF, open redirect. Uses nuclei's battle-tested fuzz templates from /root/nuclei-templates/dast/. Sends real payloads — only run after scope-check + with explicit user authorization. Logs candidate findings via the findings skill at the severity nuclei reports.
---

# webapp-fuzz

Inject payloads against captured endpoints using **nuclei DAST mode**.
Battle-tested template matchers, no hand-rolled regex, fully Go.

## Prerequisites

- `$ENGAGEMENT_DIR/webapp/endpoints.jsonl` (run `webapp-extract` first), OR
  `$ENGAGEMENT_DIR/recon/active/httpx.json` (URL list from active-recon)
- User has explicitly authorized active fuzzing
- scope-check still passing for target hosts

## Build URL list

Either source works. Endpoints from the proxy capture are richer (real
parameters seen during use); httpx is the fallback for unauth surface.

```bash
URLS=$ENGAGEMENT_DIR/webapp/fuzz-urls.txt
mkdir -p $ENGAGEMENT_DIR/webapp

# From proxy capture (preferred — has real query params)
if [ -s "$ENGAGEMENT_DIR/webapp/endpoints.jsonl" ]; then
  jq -r '
    .url_template
    | gsub("\\{id\\}"; "1")
    | gsub("\\{uuid\\}"; "00000000-0000-0000-0000-000000000000")
    | gsub("\\{hash\\}"; "0000000000000000000000000000000000000000")
  ' $ENGAGEMENT_DIR/webapp/endpoints.jsonl | sort -u > $URLS
else
  jq -r '.url' $ENGAGEMENT_DIR/recon/active/httpx.json | sort -u > $URLS
fi

wc -l $URLS
```

## Run nuclei DAST

```bash
nuclei -l $URLS \
  -dast \
  -severity low,medium,high,critical \
  -rate-limit 50 -bulk-size 25 -concurrency 25 -timeout 10 \
  -json-export $ENGAGEMENT_DIR/webapp/dast.json \
  -silent
```

Flags:
- `-dast`: enables DAST mode (loads `dast/` templates)
- `-rate-limit 50`: requests/sec ceiling
- `-severity low,medium,high,critical`: skip `info` noise
- `-json-export`: structured output for finding ingestion

If you want to scope by vuln class instead of severity:

```bash
nuclei -l $URLS -dast \
  -include-tags 'sqli,xss,ssti,lfi,rce,ssrf,redirect' \
  -json-export $ENGAGEMENT_DIR/webapp/dast.json -silent
```

DAST template tag classes available (peek with `ls /root/nuclei-templates/dast/`):
- `sqli` — SQL injection (error-based, time-based, union)
- `xss` — reflected, DOM, stored
- `ssti` — server-side template injection
- `lfi` / `path-traversal`
- `rce` / `cmdi`
- `ssrf` / `redirect`
- `headers` — host header injection, etc.
- `crlf-injection`

## Persist findings

Each nuclei DAST hit becomes a finding tied to the host+port:

```bash
jq -c '.' $ENGAGEMENT_DIR/webapp/dast.json | while read line; do
  host=$(echo "$line"   | jq -r '.host // .input // empty' | sed 's|https\?://||;s|/.*||;s|:.*||')
  url=$(echo "$line"    | jq -r '.matched-at // .url // empty')
  port=$(echo "$line"   | jq -r 'if (.url|test("https://")) then "443/tcp" else "80/tcp" end')
  sev=$(echo "$line"    | jq -r '.info.severity // "medium"')
  title=$(echo "$line"  | jq -r '.info.name // .template-id // "DAST finding"')
  templ=$(echo "$line"  | jq -r '.template-id // empty')
  param=$(echo "$line"  | jq -r '."matched-at" // empty')
  cwe=$(echo "$line"    | jq -r '.info.classification."cwe-id"[]? // empty' | head -1)

  findings add "$host" --port "$port" \
    --severity "$sev" \
    --title "$title" \
    --evidence "$url (template: $templ)" \
    ${cwe:+--cve "$cwe"} \
    --source nuclei-dast
done
```

## OOB callbacks for blind classes

For blind SSRF / blind RCE / blind XXE, nuclei integrates with interactsh
automatically when `interactsh-client` is on PATH (we install it). Add:

```bash
nuclei -l $URLS -dast \
  -interactsh-url 'https://oast.pro' \
  -severity low,medium,high,critical \
  -json-export $ENGAGEMENT_DIR/webapp/dast.json -silent
```

`oast.pro` is PD's hosted OAST collaborator (free). For self-hosted OOB, set
up an interactsh server on a public DNS+IP and pass `-interactsh-url`.

## Confirm before escalating

Nuclei DAST templates have well-tuned matchers, so `high`/`critical` from
nuclei is usually accurate. Still:

- **SQLi `high`** → re-run with `sqlmap -u "<url>?param=*" --batch --level 3` to confirm and dump.
- **RCE/SSRF `critical` via OAST** → if the interactsh callback fired, finding is solid.
- **XSS `high`** → render with headless browser to confirm execution (future `webapp-confirm` skill).

## Output summary

After completion, report:
- Total nuclei DAST hits (`jq -s 'length' $DAST_JSON`)
- Severity breakdown (`jq -s 'group_by(.info.severity)|map({(.[0].info.severity):length})|add'`)
- Top template by hit count
- Most actionable finding (highest severity, with CVE/CWE if present)
- Suggested next step (sqlmap for SQLi, OAST callback check for blind, etc.)

## Caveats

- **Auth context** — DAST templates run unauthenticated by default. For
  auth'd surface, pass `-H "Authorization: Bearer ..."` or
  `-H "Cookie: ..."`. Capture cookies from the proxy session first.
- **WAF interference** — try `-rate-limit 10` and `-timeout 30` if seeing
  blanket 403/429.
- **POST body fuzzing** — DAST templates fuzz query params primarily. For
  POST body / JSON body fuzzing, the templates that support it are tagged
  `body-fuzz` — see `nuclei -tl -tags body-fuzz`.
