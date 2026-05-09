---
name: webapp-capture
description: Start an intercepting proxy (mitmproxy) on container port 8080 to capture HTTP traffic from an authorized webapp target. Two modes — manual (user proxies host browser through it and logs in / explores the app), auto (uses katana headless crawler routed through the proxy for "lazy enum" of unauth surface). All flows persisted to $ENGAGEMENT_DIR/webapp/flows.jsonl with auth tagging. Out-of-scope requests blocked at the proxy by a scope-check addon.
---

# webapp-capture

Capture HTTP traffic to/from an authorized webapp for later extraction and
fuzzing. Both modes write the same `flows.jsonl`.

## Prerequisites

- scope-check passes for the target
- `$ENGAGEMENT_DIR` set; output dir auto-created
- Container started with port 8080 published (compose default)

## Mode A — manual (recommended for auth'd apps)

Use this when the user wants to log in themselves and click around. Realistic
auth flows, captures real session traffic.

1. Start mitmproxy with the slop-hack scope-aware addon:
   ```bash
   mkdir -p $ENGAGEMENT_DIR/webapp
   mitmdump \
     -s /root/.claude/skills/webapp-capture/mitm-addon.py \
     --listen-host 0.0.0.0 --listen-port 8080 \
     --set confdir=/root/.mitmproxy \
     > $ENGAGEMENT_DIR/webapp/mitmdump.log 2>&1 &
   echo $! > $ENGAGEMENT_DIR/webapp/mitm.pid
   sleep 2
   ```

2. Tell the user (briefly):
   - Set host browser HTTP/HTTPS proxy to **`localhost:8080`**
   - Visit `http://mitm.it` once (through the proxy) to install the CA cert (one-time per browser)
   - Browse the target — log in, click around, hit APIs, submit forms

3. While they browse, mitmproxy logs every in-scope request/response:
   `$ENGAGEMENT_DIR/webapp/flows.jsonl` (one JSON line per flow)

4. Out-of-scope requests are auto-blocked with a 403 from the addon (visible in `mitmdump.log`).

5. When the user signals they're done:
   ```bash
   kill "$(cat $ENGAGEMENT_DIR/webapp/mitm.pid)" 2>/dev/null
   wc -l $ENGAGEMENT_DIR/webapp/flows.jsonl
   ```

## Mode B — auto / lazy enum (no user driving needed)

For unauth surface or simple GET-driven crawls. Uses katana's headless
Chromium routed through mitmproxy.

**Important — TLS interception:** mitmproxy presents a fake cert signed by
its own CA. The container's system trust already has that CA installed at
build time, so curl/wget/python work transparently. **Chromium uses its own
NSS store and IGNORES the system trust**, so katana's headless mode needs
`--chrome-arg "--ignore-certificate-errors"` explicitly.

```bash
mkdir -p $ENGAGEMENT_DIR/webapp

# Sanity check — kill any stale instance, then start fresh
pkill -f "mitmdump.*8080" 2>/dev/null
sleep 1

# Start mitm in background (loopback only — the crawler is in-container)
nohup mitmdump \
  -s /root/.claude/skills/webapp-capture/mitm-addon.py \
  --listen-host 127.0.0.1 --listen-port 8080 \
  --set confdir=/root/.mitmproxy \
  -q > $ENGAGEMENT_DIR/webapp/mitmdump.log 2>&1 &
echo $! > $ENGAGEMENT_DIR/webapp/mitm.pid
sleep 3

# Verify proxy is alive (system trust knows about mitm CA, no -k needed)
curl -s --proxy http://127.0.0.1:8080 -o /dev/null -w "proxy_check:%{http_code}\n" \
  https://example.com -m 8

# Drive katana through it. Chromium needs --ignore-certificate-errors
# because its NSS store doesn't see our system-installed mitm CA.
katana -u https://<target> \
  -headless -jc -kf all \
  -depth 3 -fs rdn \
  -proxy http://127.0.0.1:8080 \
  -system-chrome \
  --chrome-arg "--ignore-certificate-errors" \
  --chrome-arg "--no-sandbox" \
  -silent \
  -o $ENGAGEMENT_DIR/webapp/katana.txt

# Tear down
kill "$(cat $ENGAGEMENT_DIR/webapp/mitm.pid)" 2>/dev/null
rm -f $ENGAGEMENT_DIR/webapp/mitm.pid
wc -l $ENGAGEMENT_DIR/webapp/flows.jsonl 2>/dev/null
```

Katana with `-headless -jc` runs JS, follows links, submits non-destructive
forms. Routing it through mitmproxy means every request it makes lands in
flows.jsonl just like a manual browser would.

### Troubleshooting auto mode

- **Empty flows.jsonl** → check `$ENGAGEMENT_DIR/webapp/mitmdump.log`. If
  nothing logged, the proxy didn't start; ports may be blocked or the addon
  errored. If you see scope-block lines, the target wasn't matched in
  `scope.yaml`.
- **`HTTP 000` from curl through proxy** → mitmproxy is dead (check pid),
  or the curl is missing `--proxy http://127.0.0.1:8080`.
- **katana finishes with 0 URLs** → almost always Chromium TLS errors. Add
  `--chrome-arg "--ignore-certificate-errors"`. If still empty, run
  `katana ... -v` to see the actual error.
- **`Exit code 144`** from `pkill` is normal — it means "no matching
  processes" (it's exit-after-signal arithmetic in some shells); the
  command did its job.

## Combined mode

You can also start mitm in mode A (`0.0.0.0`) AND launch katana through it.
The user's browser AND the headless crawler both contribute to the same
flows.jsonl. Useful for: user logs in manually, then katana crawls auth'd
surface using the same cookies (if browser is the proxy client too — note,
katana doesn't share the user's cookies; for that, pass them with `-H`).

## Output

`$ENGAGEMENT_DIR/webapp/flows.jsonl` — one record per request/response:
```json
{
  "ts":"2026-05-09T12:34:56+00:00",
  "method":"POST", "scheme":"https",
  "host":"api.acme.com", "port":443,
  "path":"/v1/login", "url":"https://api.acme.com/v1/login",
  "request_headers":{...},
  "request_content_type":"application/json",
  "request_body":"{\"user\":\"...\"}",
  "status":200,
  "response_content_type":"application/json",
  "auth":"none"
}
```

`$ENGAGEMENT_DIR/webapp/mitmdump.log` — proxy events (out-of-scope blocks, errors)

## Next

- `webapp-extract` — dedupe flows into structured endpoints.jsonl
- `webapp-fuzz` — replay endpoints with injection payloads

## Caveats

- HTTPS interception requires the mitmproxy CA cert installed in the user's browser. Tell them. (Cert is at `/root/.mitmproxy/mitmproxy-ca-cert.pem` after first run; or `http://mitm.it` is easier.)
- WebSockets/HTTP/2 — the addon currently logs HTTP/1.1 + HTTPS. WS frames aren't logged in the same shape.
- Katana doesn't share session state with the user's browser. For auth'd auto-crawl, capture cookies manually and pass via `-H 'Cookie: ...'`.
