---
name: service-enum
description: Run a service-specific enumeration playbook against an authorized host and port. Auto-detects service from findings YAML, banner grab, or default-port mapping. Playbooks chain the right tools per service (ssh-audit on SSH, smbclient/enum4linux on SMB, redis-cli on Redis, openssl/tlsx for HTTPS cert check, etc.) and log structured findings. Use after active-recon when you want deeper enumeration of a specific identified service.
---

# service-enum

Per-service enumeration playbooks. The agent gives a host+port; the
dispatcher picks the right playbook and runs it. Each playbook persists
findings via the `findings` CLI.

## Prerequisites

- scope-check passes for the target host
- `$ENGAGEMENT_DIR` set
- (Recommended) active-recon already ran so the service name is in
  `$ENGAGEMENT_DIR/findings/hosts/<host>.yaml`

## Invoke

```bash
service-enum <host> <port> [service]
```

If `service` is omitted, the dispatcher tries:
1. The host's findings YAML (`services.<port>/tcp.service`)
2. A banner grab (SSH-, FTP, HTTP/, SMTP banner sniff)
3. Default-port mapping (22→ssh, 80→http, 443→https, 445→smb, …)

Override with the explicit name when auto-detection guesses wrong.

## Available playbooks

| Service | What it runs | Findings produced |
|---|---|---|
| `http` | curl headers + OPTIONS + robots.txt + security.txt + nmap http-enum NSE | server header disclosure, dangerous methods (PUT/TRACE), exposed paths |
| `https` | http.sh + openssl s_client + tlsx + nmap ssl-enum-ciphers + ssl-cert | weak ciphers, expired/self-signed cert, weak TLS versions, missing HSTS |
| `ssh` | banner, ssh-audit, auth-method probe | weak algos, password auth allowed, old version |
| `ftp` | banner, anon-login attempt, nmap ftp-anon | anonymous FTP, banner version disclosure |
| `smb` | smbclient -L, enum4linux-ng -A, nmap smb-vuln-* | null session, exposed shares, MS17-010, signing disabled |
| `dns` | dig version.bind, AXFR attempt, recursion check | zone transfer allowed, recursion to public, version disclosure |
| `redis` | redis-cli INFO/CONFIG GET/KEYS | unauth access, exposed keys, dangerous CONFIG |
| `mongodb` | nmap mongodb-info NSE, unauth listDatabases | no-auth Mongo, exposed DBs |
| `elasticsearch` | curl /, /_cluster/health, /_cat/indices | unauth ES, exposed indices |
| `memcached` | nc stats / version | unauth memcached |
| `rdp` | nmap rdp-enum-encryption + rdp-vuln-ms12-020 | weak encryption, BlueKeep |
| `vnc` | nmap vnc-info + vnc-brute | unauth VNC |

`ls /root/.claude/skills/service-enum/playbooks/` to see what's installed.

## Adding a new playbook

1. `cp playbooks/http.sh playbooks/<service>.sh` and edit
2. Make sure `chmod +x` (in image build, COPY preserves; otherwise set it)
3. Each playbook takes `<host> <port>` as args
4. Use `findings add ...` for any noteworthy result
5. Write raw output to `$ENGAGEMENT_DIR/recon/service-enum/<host>-<port>-<svc>.txt`

## Run multiple services in parallel

The agent can fan out across services on a host:

```bash
host=acme.example.com
for port in 22 80 443 445; do
  service-enum "$host" "$port" &
done
wait
```

Or per the orchestrator pattern, dispatch `host-recon` subagents which
internally call `service-enum` per port.

## Output

- Per-run raw output: `$ENGAGEMENT_DIR/recon/service-enum/<host>-<port>-<svc>.txt`
- Findings: in main store via `findings add ...`

## Caveats

- Playbooks send packets. `scope-check` is enforced by the agent before
  invocation, but the playbooks themselves don't re-check.
- Some playbooks try authentication/connection on common services
  (anonymous FTP, no-auth Redis). These are read-only checks, but they
  show up in target logs.
- For SMB enum on a Windows AD environment, you may want to switch from
  `enum4linux-ng` to a focused tool like `netexec` (cme) — not yet in
  the image; flag if you want it added.
