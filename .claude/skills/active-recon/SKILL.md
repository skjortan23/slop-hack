---
name: active-recon
description: Run light active reconnaissance against authorized targets — DNS resolution, live HTTP probing, TLS cert pivots, port scanning, and service fingerprinting. SENDS PACKETS to the target. Use after passive-recon when the user wants to identify live services. Use when the user asks to "scan", "find live hosts", "port scan", "fingerprint services", or "what's running on...". Outputs structured JSON to $ENGAGEMENT_DIR/recon/active/ and persists hosts/services/findings via the findings skill.
---

# Active Recon

Light-touch active reconnaissance. Probes targets directly but stops short of exploitation.

## Prerequisites

1. **scope-check** must pass for every target IP/host before probing it. Re-check any new host discovered via SAN/CNAME pivot before pivoting.
2. `passive-recon` should have run first. Uses `$ENGAGEMENT_DIR/recon/passive/subdomains.txt` as input (one host per line).
3. `$ENGAGEMENT_DIR` set; `mkdir -p $ENGAGEMENT_DIR/recon/active`.

## Procedure

### 1. Resolve subdomains → live DNS

```bash
dnsx -l $ENGAGEMENT_DIR/recon/passive/subdomains.txt \
     -resp -a -aaaa -cname -mx -ns -txt \
     -json -silent \
     -r /opt/resolvers/resolvers.txt \
  > $ENGAGEMENT_DIR/recon/active/dnsx.json

jq -r 'select(.a) | .host' $ENGAGEMENT_DIR/recon/active/dnsx.json | sort -u \
  > $ENGAGEMENT_DIR/recon/active/live-hosts.txt

jq -r '.a[]?' $ENGAGEMENT_DIR/recon/active/dnsx.json | sort -u \
  > $ENGAGEMENT_DIR/recon/active/ips.txt
```

Update findings — host-set each live host with its resolved IP(s):

```bash
jq -c 'select(.a) | {host: .host, ips: .a}' \
   $ENGAGEMENT_DIR/recon/active/dnsx.json | while read line; do
  h=$(echo "$line" | jq -r .host)
  for ip in $(echo "$line" | jq -r '.ips[]'); do
    python3 /root/.claude/skills/scope-check/check.py "$ip" >/dev/null 2>&1 || continue
    findings host-set "$ip" --hostname "$h" --note "active-recon: dnsx A"
  done
done
```

### 2. CDN / WAF detection (avoid wasting scans + report attack-surface intel)

```bash
cdncheck -i $ENGAGEMENT_DIR/recon/active/ips.txt -resp -jsonl -silent \
  > $ENGAGEMENT_DIR/recon/active/cdncheck.json

jq -r 'select(.cdn==null and .waf==null) | .input' \
   $ENGAGEMENT_DIR/recon/active/cdncheck.json \
  > $ENGAGEMENT_DIR/recon/active/scannable-ips.txt
```

Both filter scans AND record intel. Each CDN/WAF/cloud-provider hit is an
`info` finding — it shapes the attack surface even if not exploitable on its
own:

```bash
jq -c '.' $ENGAGEMENT_DIR/recon/active/cdncheck.json | while read line; do
  ip=$(echo "$line"      | jq -r '.input // empty')
  cdn=$(echo "$line"     | jq -r '.cdn // empty')
  waf=$(echo "$line"     | jq -r '.waf // empty')
  cloud=$(echo "$line"   | jq -r '.cloud // empty')
  [ -z "$ip" ] && continue

  # Update host metadata
  if [ -n "$cdn" ]; then
    findings host-set "$ip" --cdn true \
      --note "cdn=$cdn"
    findings add "$ip" --severity info \
      --title "Asset fronted by CDN: $cdn" \
      --evidence "$ip" \
      --source cdncheck \
      --description "Traffic terminates at $cdn. Direct IP scanning skipped; pivot via origin discovery if needed."
  fi
  if [ -n "$waf" ]; then
    findings add "$ip" --severity info \
      --title "WAF detected: $waf" \
      --evidence "$ip" \
      --source cdncheck \
      --description "Web Application Firewall in front of asset. Expect payload filtering on web tests."
  fi
  if [ -n "$cloud" ]; then
    findings host-set "$ip" --note "cloud=$cloud"
  fi
done
```

This means the report (`findings export-md`) will include a section listing
every Cloudflare / Akamai / AWS WAF asset, even though we didn't scan them.

### 3. HTTP probing

```bash
httpx -l $ENGAGEMENT_DIR/recon/active/live-hosts.txt \
      -title -tech-detect -status-code -content-length \
      -tls-grab -favicon -json -silent \
  > $ENGAGEMENT_DIR/recon/active/httpx.json
```

Persist services found:

```bash
jq -c '.' $ENGAGEMENT_DIR/recon/active/httpx.json | while read line; do
  host=$(echo "$line" | jq -r '.input // .host')
  port=$(echo "$line" | jq -r '.port')
  scheme=$(echo "$line" | jq -r '.scheme // "http"')
  product=$(echo "$line" | jq -r '.tech[0] // empty')
  status=$(echo "$line" | jq -r '.status_code')
  title=$(echo "$line" | jq -r '.title // empty')
  findings service-set "$host" "$port/tcp" \
    --service "$scheme" \
    ${product:+--product "$product"} \
    --banner "HTTP $status${title:+ — $title}"
done
```

Flag interesting status/titles (admin, login, debug, default install, exposed dirs):

```bash
jq -r 'select(.title | test("admin|login|debug|phpmyadmin|jenkins|grafana|kibana|gitlab"; "i")) | .url' \
   $ENGAGEMENT_DIR/recon/active/httpx.json
```

### 4. TLS cert intel — aggressive SAN pivots

This step often finds hosts that subdomain enum + crt.sh missed. Run tlsx
against BOTH the live-hosts list AND the raw IP list (so we catch hosts
that don't have public DNS but live on a known IP).

```bash
# (a) Pull SANs from confirmed live web hosts
tlsx -l $ENGAGEMENT_DIR/recon/active/live-hosts.txt \
     -san -cn -ja3 -json -silent \
  > $ENGAGEMENT_DIR/recon/active/tlsx-hosts.json

# (b) Pull SANs by connecting to each IP on common TLS ports (443, 8443, 993, 995, 465, 636)
for p in 443 8443 993 995 465 636; do
  tlsx -l $ENGAGEMENT_DIR/recon/active/ips.txt -p $p \
       -san -cn -json -silent \
    >> $ENGAGEMENT_DIR/recon/active/tlsx-ips.json
done

# Merge SAN lists from BOTH sources + Wayback URLs hostnames + crt.sh hits
{
  jq -r '.subject_an[]?, .subject_cn?' \
     $ENGAGEMENT_DIR/recon/active/tlsx-hosts.json \
     $ENGAGEMENT_DIR/recon/active/tlsx-ips.json 2>/dev/null
  cat $ENGAGEMENT_DIR/recon/passive/crtsh.txt 2>/dev/null
  awk -F/ '{print $3}' $ENGAGEMENT_DIR/recon/passive/wayback.txt 2>/dev/null
} | sed 's/^\*\.//' | sort -u | grep -E '\.[a-zA-Z]{2,}$' \
  > $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt
```

Wildcard SANs (e.g. `*.codelight.ai`) tell you the cert covers everything
under that label — enumerate aggressively. For each candidate name, check
scope, resolve, then add:

```bash
# Common subdomain prefixes to try when a wildcard cert is observed
for prefix in www app dev stage staging prod admin api auth login portal \
              dashboard internal vpn mail webmail smtp imap ftp git \
              gitlab jenkins grafana kibana metrics status docs help \
              support cdn assets static media beta old test demo qa; do
  for root in $(jq -r '.subject_an[]?' $ENGAGEMENT_DIR/recon/active/tlsx-*.json \
                  | grep '^\*\.' | sed 's/^\*\.//' | sort -u); do
    candidate="${prefix}.${root}"
    python3 /root/.claude/skills/scope-check/check.py "$candidate" >/dev/null 2>&1 || continue
    # Resolve and add only if it actually has a record
    if dnsx -silent <<<"$candidate" | grep -q .; then
      findings host-set "$candidate" --hostname "$candidate" \
        --note "wildcard SAN brute: $prefix.$root"
      echo "$candidate" >> $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt
    fi
  done
done
```

Then add every NEW resolvable name from the merged list:

```bash
sort -u $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt \
  > $ENGAGEMENT_DIR/recon/active/all-known-hosts.dedup.txt
mv $ENGAGEMENT_DIR/recon/active/all-known-hosts.dedup.txt \
   $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt

dnsx -l $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt \
     -resp -a -silent -json \
  > $ENGAGEMENT_DIR/recon/active/dnsx-pivot.json

jq -r 'select(.a) | .host' $ENGAGEMENT_DIR/recon/active/dnsx-pivot.json | sort -u \
  > $ENGAGEMENT_DIR/recon/active/live-hosts-after-pivot.txt

while read h; do
  python3 /root/.claude/skills/scope-check/check.py "$h" >/dev/null 2>&1 \
    && findings host-set "$h" --note "cert/wayback pivot"
done < $ENGAGEMENT_DIR/recon/active/live-hosts-after-pivot.txt

echo "Pivoted hosts found: $(wc -l < $ENGAGEMENT_DIR/recon/active/live-hosts-after-pivot.txt)"
```

### 5. Port scan (non-CDN IPs only)

```bash
naabu -l $ENGAGEMENT_DIR/recon/active/scannable-ips.txt \
      -top-ports 1000 -rate 1000 \
      -json -silent \
  > $ENGAGEMENT_DIR/recon/active/naabu.json
```

For full-port sweep, swap `-top-ports 1000` for `-p -` (much slower; ask user).

### 6. Service / version detection

```bash
# Build per-IP port list for nmap
jq -r '.ip + ":" + (.port|tostring)' $ENGAGEMENT_DIR/recon/active/naabu.json \
  | sort -u > $ENGAGEMENT_DIR/recon/active/open-ports.txt

ports=$(jq -r '.port' $ENGAGEMENT_DIR/recon/active/naabu.json | sort -un | paste -sd,)

nmap -sV -sC -Pn --version-intensity 5 \
     -iL $ENGAGEMENT_DIR/recon/active/scannable-ips.txt \
     -p "$ports" \
     -oA $ENGAGEMENT_DIR/recon/active/nmap
```

Parse nmap XML and persist:

```bash
# Use nmap-to-json or python xml parsing — pseudo:
python3 -c '
import xml.etree.ElementTree as ET, json, subprocess
tree = ET.parse("'$ENGAGEMENT_DIR'/recon/active/nmap.xml")
for host in tree.findall(".//host"):
  ip = host.find("address").get("addr")
  for port in host.findall(".//port"):
    p = port.get("portid"); proto = port.get("protocol")
    state = port.find("state").get("state")
    if state != "open": continue
    svc = port.find("service") or {}
    args = ["findings", "service-set", ip, f"{p}/{proto}"]
    if svc.get("name"): args += ["--service", svc.get("name")]
    if svc.get("product"): args += ["--product", svc.get("product")]
    if svc.get("version"): args += ["--version", svc.get("version")]
    subprocess.run(args, check=False)
'
```

Flag high-value services (RDP/3389, SMB/445, Redis/6379, Mongo/27017, ES/9200, RabbitMQ, ZK, Kafka, Jenkins/8080):

```bash
jq -r 'select(.port | tostring | test("^(3389|445|6379|27017|9200|11211|5672|2181|9092|8080|8443|8888)$")) | "\(.ip):\(.port)"' \
   $ENGAGEMENT_DIR/recon/active/naabu.json
```

For each, log a finding so it surfaces in the report:

```bash
findings add <ip> --port <port>/tcp --severity info \
  --title "Sensitive service exposed" \
  --evidence "<service> on <ip>:<port>" \
  --source naabu
```

### 7. Crawl (web targets)

```bash
katana -list $ENGAGEMENT_DIR/recon/active/live-hosts.txt \
       -depth 2 -jc -kf all -silent -json \
  > $ENGAGEMENT_DIR/recon/active/katana.json
```

## Constraints

- **Rate limits**: never exceed `-rate 1000` (naabu), default httpx threads, `-T4` (nmap). User can override.
- **No exploitation**: this skill scans and fingerprints only. No `nuclei -severity critical`, no sqlmap, no hydra here. That belongs to a separate exploit skill.
- **Scope drift**: every new host found via tlsx SAN, dnsx CNAME, or katana out-of-scope link MUST go through scope-check before further probing.
- **CDN respect**: never run heavy port scans against CDN IPs — both noisy and useless.

## Output summary

After completion, report:
- # live hosts (resolved)
- # IPs (scannable after CDN filter)
- # web services (status code distribution, top techs)
- # open ports total / per host
- Notable services flagged (RDP, SMB, Redis, ES, Mongo, etc.)
- New hostnames pivoted to via SAN
- Run `findings list` and include the totals

Then ask the user what to do next (deeper scan, vuln scan, exploit, more recon).
