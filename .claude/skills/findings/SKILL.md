---
name: findings
description: Record hosts, services, and security findings during a pentest engagement. Use whenever a recon, scan, or exploit skill discovers a host, identifies a service, or finds a vulnerability — call this skill to persist it. Stores one YAML file per host under $ENGAGEMENT_DIR/findings/hosts/, with services and findings nested. Also appends to an audit JSONL log. Provides export to markdown report.
---

# Findings

Persist hosts, services, and findings into structured per-host YAML files. Every other skill calls this when it discovers something worth keeping.

## Storage layout

```
$ENGAGEMENT_DIR/findings/
├── hosts/
│   ├── 192.168.1.10.yaml      # one file per host
│   ├── acme.com.yaml
│   └── api_acme_com.yaml      # unsafe chars replaced with _
└── findings.jsonl             # append-only audit log of every finding
```

## Per-host YAML schema

```yaml
host: 192.168.1.10            # IP or hostname (the file's primary key)
hostnames:                    # all known names pointing here
  - web.acme.com
  - api.acme.com
metadata:
  asn: AS13335
  cdn: false
  os_guess: linux
  notes:
    - {ts: 2026-05-08T14:22:00Z, text: "interesting box"}
last_seen: 2026-05-08T14:22:00Z

services:
  "80/tcp":
    service: http
    product: nginx
    version: "1.24.0"
    banner: "nginx/1.24.0 (Ubuntu)"
    findings:
      - id: F-a1b2c3d4
        severity: medium
        title: "Outdated nginx with known CVE"
        description: "..."
        evidence: "Server: nginx/1.24.0"
        cve: CVE-2024-XXXX
        source: nuclei
        ts: 2026-05-08T14:22:00Z
  "443/tcp":
    service: https
    ...

host_findings:                # findings not tied to a specific port
  - id: F-e5f6...
    severity: low
    title: "DNS wildcard configured"
    ...
```

## CLI — call the helper, don't write YAML by hand

```bash
findings host-set <host> [--hostname H ...] [--asn AS...] [--cdn true|false] [--note "..."]
findings service-set <host> <port>/<proto> [--service http] [--product nginx] [--version 1.24.0] [--banner "..."]
findings add <host> [--port PORT/PROTO] --severity {info,low,medium,high,critical} --title "T" [--evidence "E"] [--description "D"] [--cve CVE-...] [--source TOOL]
findings show <host>
findings list
findings export-md > $ENGAGEMENT_DIR/report.md
```

The CLI is at `/root/.claude/skills/findings/findings.py` — invoke as `findings ...` (a wrapper is on PATH) or directly:

```bash
python3 /root/.claude/skills/findings/findings.py <subcommand> ...
```

All commands print JSON status to stdout. Exit non-zero on error.

## When to call which subcommand

- **`host-set`** — first time a host appears (resolved IP, new subdomain). Idempotent — re-run to add hostnames or update metadata.
- **`service-set`** — when a port/service is identified (naabu, httpx, nmap output). Re-run to add product/version once known.
- **`add`** — every actual finding. Pick the right `--port` if it's service-specific, omit for host-level findings (DNS misconfig, leaked emails, etc.).
- **`list`** — quick host count summary.
- **`show <host>`** — dump a single host's full record.
- **`export-md`** — generate the engagement report (sorted by severity).

## Severity rubric

- `critical` — pre-auth RCE, plaintext creds, full DB access
- `high` — auth bypass, SQLi, SSRF to internal, exposed admin panel
- `medium` — outdated software with known CVEs, info disclosure of sensitive data, weak crypto
- `low` — version disclosure, missing security headers, debug pages
- `info` — observation worth noting but not exploitable on its own

## Examples

After httpx finds a live host:
```bash
findings host-set api.acme.com --hostname api.acme.com
findings service-set api.acme.com 443/tcp --service https --product nginx --version 1.24.0
```

After nuclei flags a vuln:
```bash
findings add api.acme.com --port 443/tcp \
  --severity high \
  --title "Exposed .git directory" \
  --evidence "https://api.acme.com/.git/HEAD returns 200 with 'ref: refs/heads/main'" \
  --source nuclei \
  --description "Source code disclosure via exposed git repo"
```

After scope expansion via SAN pivot:
```bash
findings host-set internal-api.acme.com --hostname internal-api.acme.com \
  --note "Discovered via TLS SAN on api.acme.com cert"
```

## Bulk ingest hints (manual for now)

When tools dump JSON, the agent should iterate and call `findings` per record, e.g.:

```bash
jq -c '.' httpx.json | while read line; do
  host=$(echo "$line" | jq -r .host)
  port=$(echo "$line" | jq -r .port)
  proto=tcp
  product=$(echo "$line" | jq -r '.tech[0] // empty')
  findings host-set "$host"
  findings service-set "$host" "$port/$proto" --service https --product "$product"
done
```
