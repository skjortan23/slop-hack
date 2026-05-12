---
name: findings
description: Record hosts, services, and security findings during a pentest engagement. Use whenever a recon, scan, or exploit skill discovers a host, identifies a service, or finds a vulnerability — call this skill to persist it. Stores one YAML file per host under $ENGAGEMENT_DIR/findings/hosts/, with services and findings nested. Also appends to an audit JSONL log. Provides export to markdown report.
---

# Findings

## CLI

```bash
findings host-set <host> [--hostname H ...] [--asn AS] [--cdn true|false] [--note "..."]
findings service-set <host> <port>/<proto> [--service http] [--product nginx] [--version 1.24.0] [--banner "..."]
findings add <host> [--port PORT/PROTO] --severity {info,low,medium,high,critical} \
                    --title "T" [--evidence "E"] [--description "D"] [--cve CVE-...] [--source TOOL]
findings show <host>
findings list
findings services --json     # list of {host, port, service, product, version}
findings export-md > $ENGAGEMENT_DIR/report.md
```

All commands print JSON status to stdout. Exit non-zero on error.

## When to call which subcommand

- `host-set` — first time a host appears (resolved IP, new subdomain). Idempotent.
- `service-set` — port/service identified (naabu, httpx, nmap). Re-run to fill product/version.
- `add` — every finding. `--port` for service-specific, omit for host-level (DNS misconfig, OSINT leak).
- `show <host>` — dump a single host record.
- `list` — host count summary.
- `services --json` — feed to vuln-check / cve-correlation per-service loops.
- `export-md` — engagement report sorted by severity.

## Severity grading

See CLAUDE.md "Severity rubric" — strict, evidence-driven. critical needs
in-band proof of exec / pre-auth real-data response. Don't inflate.

## Bulk ingest pattern

When a tool dumps JSON, iterate and call `findings` per record:
```bash
jq -c '.' httpx.json | while read line; do
  host=$(echo "$line" | jq -r .host); port=$(echo "$line" | jq -r .port)
  findings service-set "$host" "$port/tcp" --service https \
    --product "$(echo "$line" | jq -r '.tech[0] // empty')"
done
```

## Storage (FYI — don't edit YAML directly)

Per-host: `$ENGAGEMENT_DIR/findings/hosts/<host>.yaml` (unsafe chars → `_`).
Audit log: `$ENGAGEMENT_DIR/findings/findings.jsonl` (append-only).
