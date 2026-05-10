---
name: passive-recon
description: Run passive reconnaissance against an authorized target — subdomain enumeration, ASN/CIDR discovery, archived URL collection, OSINT email/name harvesting, and Shodan banner lookup. Sends NO packets to the target itself; only queries third-party data sources. Use when the user asks to "do recon", "enumerate subdomains", "find hosts for", "OSINT", or otherwise gather information about a domain or org without scanning. Outputs structured JSON to $ENGAGEMENT_DIR/recon/passive/ and persists discovered hosts via the findings skill.
---

# Passive Recon

Gather intel about a target using only third-party sources. Sends no packets to the target.

## Prerequisites

1. Run **scope-check** for the root domain BEFORE anything else:
   ```bash
   python3 /root/.claude/skills/scope-check/check.py <target>
   ```
2. `$ENGAGEMENT_DIR` set (e.g. `/work/ENG-2026-001`).
3. Output dir: `mkdir -p $ENGAGEMENT_DIR/recon/passive`

## Inputs

- `<target>`: root domain (`acme.com`) or org name
- Optional: known ASN (`AS13335`)

## Procedure

### 1. ASN / IP space

```bash
asnmap -d <target> -json -silent \
  > $ENGAGEMENT_DIR/recon/passive/asnmap.json
whois <target> > $ENGAGEMENT_DIR/recon/passive/whois.txt
```

### 2. Subdomain enumeration (multi-source for diversity)

```bash
subfinder -d <target> -all -silent -oJ \
  -o $ENGAGEMENT_DIR/recon/passive/subfinder.json
amass enum -passive -d <target> \
  -json $ENGAGEMENT_DIR/recon/passive/amass.json
chaos -d <target> -silent \
  > $ENGAGEMENT_DIR/recon/passive/chaos.txt 2>/dev/null || true
curl -s "https://crt.sh/?q=%25.<target>&output=json" \
  | jq -r '.[].name_value' \
  | tr ',' '\n' | sort -u \
  > $ENGAGEMENT_DIR/recon/passive/crtsh.txt
```

Merge unique subdomains. **Filter to valid hostnames** — chaos and others
emit error/banner lines (`[FTL] PDCP_API_KEY not specified`, `[INF] Current
version`, etc.) that pollute the list if you just `cat` them in:

```bash
{ jq -r '.host' $ENGAGEMENT_DIR/recon/passive/subfinder.json 2>/dev/null;
  jq -r '.name' $ENGAGEMENT_DIR/recon/passive/amass.json 2>/dev/null;
  cat $ENGAGEMENT_DIR/recon/passive/chaos.txt $ENGAGEMENT_DIR/recon/passive/crtsh.txt 2>/dev/null;
} | grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' \
  | tr '[:upper:]' '[:lower:]' \
  | sort -u > $ENGAGEMENT_DIR/recon/passive/subdomains.txt

wc -l $ENGAGEMENT_DIR/recon/passive/subdomains.txt
```

### 3. Archived URLs

```bash
echo <target> | waybackurls > $ENGAGEMENT_DIR/recon/passive/wayback.txt
echo <target> | gau --threads 5 > $ENGAGEMENT_DIR/recon/passive/gau.txt
```

Skim for interesting endpoints (admin, debug, .git, .env, api, internal).

### 4. OSINT (emails, names)

```bash
timeout 90 theHarvester -d <target> -b crtsh,duckduckgo,bing,otx \
  -f $ENGAGEMENT_DIR/recon/passive/harvester
```

**DO NOT use `-b all`.** It walks every supported source serially —
including ones that require API keys we don't have, ones that rate-limit
without warning, and ones that hang for minutes. Each "all" run typically
takes 5–15 minutes and most sources fail anyway. The four sources above
work without keys and finish in <90s.

If you genuinely need more sources, add them ONE at a time after confirming
the corresponding API key is set:
- `securityTrails` — needs `SECURITYTRAILS_API_KEY`
- `shodan` — needs `SHODAN_API_KEY`
- `github-code` — needs `GITHUB_TOKEN`
- `virustotal` — needs `VIRUSTOTAL_API_KEY`

### 5. Shodan (if SHODAN_API_KEY set)

```bash
[ -n "$SHODAN_API_KEY" ] && shodan domain <target> \
  > $ENGAGEMENT_DIR/recon/passive/shodan.txt
```

## Persist findings

For every subdomain discovered, register it as a host (no IP yet — that's active-recon's job):

```bash
while read h; do
  findings host-set "$h" --hostname "$h" --note "passive-recon: subdomain"
done < $ENGAGEMENT_DIR/recon/passive/subdomains.txt
```

If the ASN is interesting, log it:

```bash
asn=$(jq -r '.asn // empty' $ENGAGEMENT_DIR/recon/passive/asnmap.json | head -1)
[ -n "$asn" ] && findings host-set <target> --asn "$asn"
```

If theHarvester finds emails, log a host-level finding:

```bash
emails=$(jq -r '.emails // [] | length' $ENGAGEMENT_DIR/recon/passive/harvester.json 2>/dev/null)
[ "$emails" -gt 0 ] && findings add <target> \
  --severity info \
  --title "Emails harvested via OSINT" \
  --evidence "$(jq -r '.emails[]' $ENGAGEMENT_DIR/recon/passive/harvester.json | head -20)" \
  --source theHarvester
```

## Failure handling

- A single tool failing is fine — keep going. Note which sources failed in your summary.
- If subfinder + amass + crt.sh ALL fail (zero subdomains across all three), STOP and tell the user. Likely network or key issue.
- If `theHarvester -b all` errors, retry with `-b crtsh,duckduckgo` (the most reliable no-key sources).

## Output summary for the user

After completion, report:
- # unique subdomains discovered (sources contributing)
- ASNs / CIDRs identified
- # emails / names from theHarvester
- Notable archived URLs (admin panels, leaked endpoints, secrets in paths)
- Shodan: # exposed services (if used)

Do NOT proceed to active-recon automatically. Ask the user for confirmation, since active-recon sends packets to the target.
