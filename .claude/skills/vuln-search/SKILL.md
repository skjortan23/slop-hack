---
name: vuln-search
description: Look up known vulnerabilities for an identified product+version (e.g. "nginx 1.24.0", "Apache 2.4.49"). Local-first — uses nuclei CVE templates (~3000, executable) and searchsploit (local exploit-db) on the box. Optionally falls back to vulnx (ProjectDiscovery online API, requires PDCP key) for structured CVE search. Logs matched CVEs as findings tied to the host+port.
---

# vuln-search

Given a product and version (e.g. `nginx 1.24.0`), find applicable known
vulnerabilities. **Local sources first** — they're instant and offline.

## Inputs

- `product`: e.g. `nginx`, `apache`, `openssh`, `wordpress`
- `version`: optional, e.g. `1.24.0`
- `host` + `port`: where the service was detected (so findings are tied to
  the right asset)

## Workflow

### Step 1 — nuclei CVE templates (LOCAL, executable)

Most useful local source. Templates encode CVE id + version matchers and
*test* the target instead of just listing IDs.

Find candidates by product:
```bash
grep -ril "<product>" /root/nuclei-templates/http/cves/ | head -40
```

For each candidate, run it against the live target:
```bash
nuclei -t /root/nuclei-templates/http/cves/2024/CVE-2024-XXXXX.yaml \
       -u https://<host>:<port> -json
```

If nuclei reports `info.severity` and a match, log:
```bash
findings add <host> --port <port>/tcp --severity high \
  --title "<CVE>: <name>" \
  --evidence "<nuclei matched-at line>" \
  --cve <CVE-ID> \
  --source nuclei
```

Faster bulk option — run all CVE templates for the product in one shot:
```bash
nuclei -tags cve -product <product> -u https://<host>:<port> -json -silent \
  -o $ENGAGEMENT_DIR/recon/active/nuclei-cves.json
```

### Step 2 — searchsploit (LOCAL, public PoCs)

```bash
searchsploit <product> <version>
searchsploit --json <product> <version> | jq '.RESULTS_EXPLOIT[]
  | {Title, "EDB-ID", Path, Date}'
```

For each match (only the ones that look version-applicable), log as `info`:
```bash
findings add <host> --port <port>/tcp --severity info \
  --title "Public PoC: <title> (EDB-<id>)" \
  --evidence "$(searchsploit -p <EDB-ID>)" \
  --source searchsploit
```

Severity is `info` because the PoC may need adaptation; only escalate after
verifying it works against the target.

### Step 3 — vulnx (ONLINE, optional)

**Only run if PDCP API key is configured** (`vulnx auth` once). Without it
vulnx returns nothing.

```bash
# Has key?
vulnx healthcheck 2>&1 | grep -qi authenticated || { echo "vulnx not auth'd, skipping"; }

# CVE detail lookup
vulnx id CVE-2024-XXXXX --json

# Search by product
vulnx search --query 'product:<product> AND severity:critical,high' --json | jq -c '.'
```

For each high/critical CVE that's plausibly applicable:
```bash
findings add <host> --port <port>/tcp --severity <high|medium> \
  --title "<CVE-ID>: <name>" \
  --description "<summary from vulnx>" \
  --cve <CVE-ID> \
  --source vulnx
```

## Don't inflate severity

A CVE with CVSS 9.8 doesn't automatically mean high/critical on **this**
target. Use the rubric:

- **critical**: nuclei template *fired* AND it's pre-auth RCE on prod.
- **high**: nuclei template fired, OR a critical CVE clearly matches the
  running version (versions overlap with `affected:`).
- **medium**: CVE matches version, exploit needs auth or non-default config.
- **low**: theoretical CVE match, no exploit, requires significant prereqs.
- **info**: PoC exists for product family, version match unclear.

If you can't confirm version range, leave at `low`/`info` and note the
uncertainty in `--description`.

## Output

After the run, summarize:
- `<n>` nuclei CVE templates matched, `<m>` fired
- `<k>` searchsploit hits (top 3 by date)
- `<j>` high/critical CVEs from vulnx (if used)
- The single most actionable finding, with CVE id

Then suggest the next move (test exploit, rotate to next service, etc.) but
do not run exploits without explicit user approval.
