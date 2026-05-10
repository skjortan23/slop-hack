---
name: quickscan
description: Rapid port sweep + service inventory across one or many hosts. naabu-only (NO nmap — too many timeouts and weird retry logic on filtered / WAF-fronted hosts). Default port set is a curated ~80 ports of common pentest interest (SSH, FTP, SMB, RDP, web 80/443/8080/8443, databases, message brokers, dev tools, etc.). HTTP/HTTPS hits are enriched via httpx for banner + tech detection. Calls findings host-set + service-set automatically so the per-host service inventory is populated.
---

# quickscan

One-shot port + service discovery across hosts. naabu sweeps a curated
pentest port list at high rate, httpx fingerprints any HTTP/HTTPS hits.
**No nmap** — for coverage scanning across many hosts, naabu's raw socket
behavior is faster and doesn't choke on filtered / WAF-fronted hosts.

## When to use

- Right after passive-recon — get coverage across all discovered subdomains
  in seconds rather than waiting on per-host nmap runs
- For SSH/SMB/DB/dev-tool coverage — the default port set captures the
  services most likely to yield findings
- Whenever you want service inventory populated WITHOUT running the full
  host-recon workflow per host

## Usage

```bash
# Single host, default curated pentest port set (~80 ports)
quickscan example.com

# Many hosts
quickscan -l $ENGAGEMENT_DIR/recon/passive/subdomains.txt

# Explicit port list
quickscan -p 22,80,443,3306,5432 -l hosts.txt

# Full sweep (1-65535) — slow but thorough
quickscan --full target.example.com

# Tune rate (default 1000 pps)
quickscan -l hosts.txt --rate 2000

# Skip findings logging (just print)
quickscan --no-log target

# Skip httpx enrichment of HTTP/HTTPS hits
quickscan --no-http target
```

## What it does (and doesn't do)

**Does:**
1. naabu raw-socket sweep at configurable rate (default 1000 pps)
2. httpx fingerprint of every HTTP/HTTPS hit (status, title, tech, server header)
3. Auto-call (unless `--no-log`):
   - `findings host-set <host> --hostname <host>`
   - `findings service-set <host> <port>/<proto> --service <s> --product <p> --version <v> --banner <b>`
4. Print summary table or JSON

**Doesn't:**
- nmap service detection (use `service-enum <host> <port>` if you want that — it dispatches the right per-service playbook)
- vuln-check (chain that yourself: `findings services --json | jq ... | xargs vuln-check`)
- Anything intrusive — read-only port + HTTP banner

## Default port list (curated for pentest signal)

```
21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,
465,514,587,623,636,993,995,1080,1433,1521,1723,2049,
2082,2083,2087,2096,2222,2375,2376,2483,2484,3000,3128,
3268,3306,3389,4443,4444,4500,4848,4949,5000,5060,5432,
5601,5672,5900,5984,5985,6379,6443,7000,7001,7077,7474,
8000,8005,8009,8020,8022,8080,8081,8086,8088,8090,8091,
8200,8443,8500,8530,8531,8649,8888,9000,9043,9080,9090,
9092,9100,9200,9300,9418,9990,9999,10000,11211,15672,
27017,27018,27019,28017,49152,50000
```

Covers: SSH (22, 2222, 2222, 8022), HTTP variants (80, 3000, 5000, 8000s, 9000s),
HTTPS variants (443, 4443, 8443), SMB (139, 445), DBs (1433, 1521, 3306,
5432, 6379, 9200, 27017, 11211), RDP (3389), VNC (5900), AMQP/Kafka (5672,
9092), dev tools (Jenkins-ish 8080, Tomcat 8005/8009, GlassFish 4848,
WebSphere 9043, WildFly 9990, WSUS 8530), Docker (2375/2376), k8s (6443),
HashiCorp (8200/8500), CouchDB (5984), Neo4j (7474), Spark (7077), and
common web alternates.

## Output

`$ENGAGEMENT_DIR/recon/quickscan/`:
- `targets.txt` — input hosts
- `naabu.json` — open ports per host
- `httpx-input.txt`, `httpx.json` — HTTP fingerprint data

## Pairs nicely with vuln-check

After quickscan populates the per-host inventory:
```bash
findings services --json | \
  jq -r '.[] | select(.product != "") | "\(.host) \(.port|split("/")[0]) \(.product) \(.version)"' | \
  while read host port product version; do
    vuln-check "$host" "$port" "$product" "$version"
  done
```

That gives every detected (host, port, product, version) a CVE check via
nuclei templates + searchsploit, all logged as findings tied to the right
service.
