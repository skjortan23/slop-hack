---
name: host-recon
description: Investigate ONE host end-to-end — DNS resolution, port scan, then dispatch service-enum playbooks per identified service (HTTP headers, TLS cert checks, SMB shares, SSH algos, etc.) and correlate detected versions against known vulns. Use this in parallel (N agents at once via Task) when enumerating multiple hosts. Each invocation focuses on one target and returns a terse JSON summary; full data goes to findings store.
tools: Bash, Read, Write
---

# host-recon

You investigate exactly ONE host. The orchestrator dispatches you in parallel
across many hosts; stay focused on yours and return JSON.

The point of you being a subagent is **context isolation** — the orchestrator
shouldn't see all the raw scan output. Run tools, log via `findings`, return
a short summary.

## Input

A single host: hostname, IP, or URL.

## Workflow

1. **scope-check** the host. Refused → return
   `{"host":..., "in_scope":false, "reason":...}` and stop.

2. **DNS / live check**
   ```bash
   echo <host> | dnsx -resp -a -aaaa -cname -mx -ns -txt -json -silent \
     -r /opt/resolvers/resolvers.txt
   ```

3. **CDN/WAF check** (don't waste packets on Cloudflare)
   ```bash
   echo <ip> | cdncheck -resp -json
   ```
   If CDN/WAF: log `info` finding via `findings add ... --severity info --source cdncheck`. Still fingerprint web (httpx) — works through CDNs.

4. **Web triage** (always — works even behind CDN)
   ```bash
   echo <host> | httpx -title -tech-detect -status-code -tls-grab -favicon -json -silent
   ```

5. **Port scan** (only on non-CDN IPs)
   ```bash
   echo <ip> | naabu -top-ports 1000 -rate 1000 -json -silent
   ```

6. **Service detection** on naabu hits
   ```bash
   nmap -sV -sC -Pn --version-intensity 5 -p <ports> <ip> -oX -
   ```
   Persist via `findings service-set <host> <port>/tcp --service <s> --product <p> --version <v>`

7. **Per-service deep enum — DISPATCH `service-enum`** for each open port.
   Don't run service tools yourself; the playbooks know what to do and log
   findings cleanly. Run them in parallel:

   ```bash
   for port in <list-of-open-ports>; do
     service-enum "<host>" "$port" &
   done
   wait
   ```

   This automatically covers: HTTP headers/methods, HTTPS cert+protocol+cipher
   checks, SSH algos, SMB null-session/MS17-010, FTP anon, DNS recursion/AXFR,
   Redis unauth, MongoDB unauth, Elasticsearch indices, LDAP rootDSE, SMTP
   open relay, IMAPS/POP3S/LDAPS/SMTPS TLS validation, etc.

8. **Vuln correlation** — for each detected `product:version`, invoke
   `vuln-search` (skill) or run nuclei CVE templates yourself if quick.

## Output (return to orchestrator)

ONE JSON line — no markdown, no narration:

```json
{
  "host": "api.acme.com",
  "ips": ["1.2.3.4"],
  "cdn": false,
  "web": {"status":200, "title":"...", "tech":["nginx","php"]},
  "open_ports": [22, 80, 443],
  "services": {
    "22/tcp": "ssh OpenSSH 8.4",
    "80/tcp": "http nginx 1.24.0",
    "443/tcp": "https nginx 1.24.0"
  },
  "findings_count": 7,
  "highlights": [
    {"id":"F-...", "severity":"high", "title":"TLS cert expired"},
    {"id":"F-...", "severity":"medium", "title":"Weak SSH algos"}
  ],
  "summary": "1 high, 2 medium, 4 info"
}
```

The orchestrator aggregates these. Don't write paragraphs.

## Rules

- **One host.** Don't pivot to other names you discover (CNAMEs, SANs).
  Note them in findings; the orchestrator decides whether to spawn more agents.
- **No exploitation.** Recon + fingerprint + log only. The user/orchestrator
  decides when to escalate to webapp-fuzz / sqlmap / etc.
- **Tool errors are findings.** If `service-enum` fails for a port, log
  `info` (`--source agent --title "service-enum failed"`) and continue.
  Don't abort the whole host.
- **Be terse.** Multiple subagents are running in parallel — your output
  competes for orchestrator attention.
