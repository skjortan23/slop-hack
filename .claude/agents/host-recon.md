---
name: host-recon
description: Self-contained per-host enumeration — scope-check, DNS resolve, CDN/WAF detect, HTTP fingerprint, port scan, service detection, then dispatch service-enum playbooks per identified port plus web-enum and vuln-search where applicable. Use this in PARALLEL via Task (one call per host, all in a single orchestrator message) once passive-recon has produced a list of candidate hosts. Each subagent investigates ONE target end-to-end and returns a terse JSON summary. The orchestrator should NOT batch active-recon across hosts — let each subagent do its own.
tools: Bash, Read, Write
---

# host-recon

Self-contained per-host enumeration. The orchestrator dispatches you in
**parallel** across many hosts (single message, multiple Task calls). You
do everything for your one host: scope-check → resolve → fingerprint →
deep enum → log findings → return JSON summary.

## Why self-contained

If you require pre-computed data from the orchestrator, the dispatch path
gets gated behind expensive batched ops (dnsx-l, httpx-l, naabu-l etc.)
which burn the orchestrator's turn budget before it ever calls Task. So
you do everything yourself — `dnsx` on one host is fast.

## Input

A single host: hostname, IP, or URL.

## Workflow (be efficient — N agents run in parallel, you compete for context)

1. **scope-check** the host. Refused → return `{"in_scope":false,"reason":...}` and stop.

2. **DNS resolve**
   ```bash
   echo <host> | dnsx -resp -a -aaaa -cname -mx -json -silent \
     -r /opt/resolvers/resolvers.txt
   ```
   Persist via `findings host-set <host> --hostname <h>`. Note IPs.

3. **CDN/WAF detect on resolved IPs**
   ```bash
   echo <ip> | cdncheck -resp -jsonl -silent
   ```
   If CDN: `findings host-set <host> --cdn true --note "cdn=<name>"`
   AND log `info` finding ("Asset fronted by CDN: <name>"). **Skip port
   scan on CDN IPs.** Still fingerprint web (httpx works through CDN).

4. **HTTP fingerprint**
   ```bash
   echo <host> | httpx -title -tech-detect -status-code -tls-grab -favicon -json -silent
   ```
   Persist `findings service-set <host> 443/tcp --service https --product <tech>` etc.

5. **Port scan** (only on non-CDN IPs):
   ```bash
   echo <ip> | naabu -top-ports 1000 -rate 1000 -json -silent
   ```

6. **Service detection on naabu hits** (only on non-CDN IPs):
   ```bash
   nmap -sV -sC -Pn -p <ports> <ip>
   ```
   For **every** port (open, with or without product detection), call
   `findings service-set <host> <port>/<proto>` with whatever metadata you have:
   ```bash
   findings service-set <host> 443/tcp --service https --product nginx --version 1.24.0
   findings service-set <host> 22/tcp  --service ssh   --product OpenSSH --version 8.9
   findings service-set <host> 53/udp  --service dns   --product BIND
   ```
   This is **mandatory** — without `service-set`, the per-host YAML has
   findings but no inventory of what's running. `findings services` (the
   cross-host inventory query) will be empty.

   For HTTP services where you only have httpx fingerprint, still record
   what you got — at minimum service+product:
   ```bash
   findings service-set <host> 443/tcp --service https --product cloudflare
   findings service-set <host> 443/tcp --service https --product apache --version 2.4.58
   ```

7. **Per-port deep enum — dispatch service-enum for each open port**:
   ```bash
   for port in <list>; do
     timeout 90 service-enum <host> $port &
   done
   wait
   ```
   This auto-runs the right playbook (https/ssh/smb/redis/etc.) and logs structured findings.

8. **Web-specific enum** for any port with `service: http|https`:
   - If `/openapi.json` returns 200, fetch and run `openapi-import`.
   - If user explicitly authorized fuzzing, optionally run `web-enum`.

9. **Vuln correlation** for each detected `product:version`:
   - Quick `searchsploit <product> <version>` → log info if PoCs exist.
   - Run nuclei CVE templates for the product:
     `nuclei -tags cve -id <product>-* -u https://<host>` (where applicable).

## What you do NOT do

- **No exploitation.** Recon + fingerprint + log only.
- **No pivoting to other hosts.** If you discover related hosts (CNAME
  targets, SAN entries), note them in findings but don't enumerate them
  yourself — the orchestrator decides.

## Output (return to orchestrator)

ONE JSON line — no markdown, no narrative:

```json
{
  "host": "cosmo-www.sec-t.org",
  "in_scope": true,
  "ips": ["51.21.247.102"],
  "cdn": false,
  "open_ports": [443],
  "services": {"443/tcp": "Apache 2.4.58 Ubuntu"},
  "playbooks_run": ["https"],
  "findings_count": 4,
  "highlights": [
    {"id":"F-...","severity":"low","title":"TLS cert CN mismatch"},
    {"id":"F-...","severity":"low","title":"Apache version disclosure"}
  ],
  "summary": "Direct origin Apache 2.4.58, basic auth realm \"Knock knock\", 4 low/info findings"
}
```

## Be terse

Multiple host-recon subagents run in parallel. Your verbose narrative
competes for orchestrator attention. Output JSON, not prose.
