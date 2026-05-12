---
name: active-recon
description: Run light active reconnaissance against authorized targets — DNS resolution, live HTTP probing, TLS cert pivots, port scanning, and service fingerprinting. SENDS PACKETS to the target. Use after passive-recon when the user wants to identify live services. Use when the user asks to "scan", "find live hosts", "port scan", "fingerprint services", or "what's running on...". Outputs structured JSON to $ENGAGEMENT_DIR/recon/active/ and persists hosts/services/findings via the findings skill.
---

# Active Recon

## Prerequisites

1. scope-check passes for every target. Re-check any new host discovered via SAN/CNAME pivot.
2. `passive-recon` ran first — uses `$ENGAGEMENT_DIR/recon/passive/subdomains.txt`.
3. `mkdir -p $ENGAGEMENT_DIR/recon/active`.

## 1. Resolve subdomains → live DNS

```bash
dnsx -l $ENGAGEMENT_DIR/recon/passive/subdomains.txt \
     -resp -a -aaaa -cname -mx -ns -txt \
     -json -silent -r /opt/resolvers/resolvers.txt \
  > $ENGAGEMENT_DIR/recon/active/dnsx.json

jq -r 'select(.a) | .host' $ENGAGEMENT_DIR/recon/active/dnsx.json | sort -u \
  > $ENGAGEMENT_DIR/recon/active/live-hosts.txt
jq -r '.a[]?' $ENGAGEMENT_DIR/recon/active/dnsx.json | sort -u \
  > $ENGAGEMENT_DIR/recon/active/ips.txt
```

Persist per-host (scope-check each IP before adding):
```bash
jq -c 'select(.a) | {host: .host, ips: .a}' \
   $ENGAGEMENT_DIR/recon/active/dnsx.json | while read line; do
  h=$(echo "$line" | jq -r .host)
  for ip in $(echo "$line" | jq -r '.ips[]'); do
    scope-check "$ip" >/dev/null 2>&1 || continue
    findings host-set "$ip" --hostname "$h"
  done
done
```

## 2. CDN / WAF detection

```bash
cdncheck -i $ENGAGEMENT_DIR/recon/active/ips.txt -resp -jsonl -silent \
  > $ENGAGEMENT_DIR/recon/active/cdncheck.json

jq -r 'select(.cdn==null and .waf==null) | .input' \
   $ENGAGEMENT_DIR/recon/active/cdncheck.json \
  > $ENGAGEMENT_DIR/recon/active/scannable-ips.txt
```

Every CDN/WAF/cloud-provider hit → `info` finding (shapes attack surface):
```bash
jq -c '.' $ENGAGEMENT_DIR/recon/active/cdncheck.json | while read line; do
  ip=$(echo "$line"  | jq -r '.input // empty'); [ -z "$ip" ] && continue
  cdn=$(echo "$line" | jq -r '.cdn // empty')
  waf=$(echo "$line" | jq -r '.waf // empty')
  cloud=$(echo "$line" | jq -r '.cloud // empty')
  [ -n "$cdn" ] && { findings host-set "$ip" --cdn true --note "cdn=$cdn"
                     findings add "$ip" --severity info \
                       --title "Asset fronted by CDN: $cdn" --evidence "$ip" --source cdncheck; }
  [ -n "$waf" ] && findings add "$ip" --severity info \
                     --title "WAF detected: $waf" --evidence "$ip" --source cdncheck
  [ -n "$cloud" ] && findings host-set "$ip" --note "cloud=$cloud"
done
```

## 3. HTTP probing

```bash
httpx -l $ENGAGEMENT_DIR/recon/active/live-hosts.txt \
      -title -tech-detect -status-code -content-length \
      -tls-grab -favicon -json -silent \
  > $ENGAGEMENT_DIR/recon/active/httpx.json

jq -c '.' $ENGAGEMENT_DIR/recon/active/httpx.json | while read line; do
  host=$(echo "$line"   | jq -r '.input // .host')
  port=$(echo "$line"   | jq -r '.port')
  scheme=$(echo "$line" | jq -r '.scheme // "http"')
  product=$(echo "$line" | jq -r '.tech[0] // empty')
  status=$(echo "$line" | jq -r '.status_code')
  title=$(echo "$line"  | jq -r '.title // empty')
  findings service-set "$host" "$port/tcp" --service "$scheme" \
    ${product:+--product "$product"} \
    --banner "HTTP $status${title:+ — $title}"
done
```

Flag interesting titles for follow-up:
```bash
jq -r 'select(.title | test("admin|login|debug|phpmyadmin|jenkins|grafana|kibana|gitlab"; "i")) | .url' \
   $ENGAGEMENT_DIR/recon/active/httpx.json
```

## 4. TLS SAN pivot

```bash
tlsx -l $ENGAGEMENT_DIR/recon/active/live-hosts.txt \
     -san -cn -ja3 -json -silent \
  > $ENGAGEMENT_DIR/recon/active/tlsx-hosts.json

for p in 443 8443 993 995 465 636; do
  tlsx -l $ENGAGEMENT_DIR/recon/active/ips.txt -p $p \
       -san -cn -json -silent \
    >> $ENGAGEMENT_DIR/recon/active/tlsx-ips.json
done

{ jq -r '.subject_an[]?, .subject_cn?' \
     $ENGAGEMENT_DIR/recon/active/tlsx-hosts.json \
     $ENGAGEMENT_DIR/recon/active/tlsx-ips.json 2>/dev/null
  cat $ENGAGEMENT_DIR/recon/passive/crtsh.txt 2>/dev/null
  awk -F/ '{print $3}' $ENGAGEMENT_DIR/recon/passive/wayback.txt 2>/dev/null
} | sed 's/^\*\.//' | sort -u | grep -E '\.[a-zA-Z]{2,}$' \
  > $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt

dnsx -l $ENGAGEMENT_DIR/recon/active/all-known-hosts.txt \
     -resp -a -silent -json > $ENGAGEMENT_DIR/recon/active/dnsx-pivot.json
jq -r 'select(.a) | .host' $ENGAGEMENT_DIR/recon/active/dnsx-pivot.json | sort -u \
  > $ENGAGEMENT_DIR/recon/active/live-hosts-after-pivot.txt
while read h; do
  scope-check "$h" >/dev/null 2>&1 && findings host-set "$h" --note "cert/wayback pivot"
done < $ENGAGEMENT_DIR/recon/active/live-hosts-after-pivot.txt
```

## 5. Port scan (non-CDN IPs only)

```bash
naabu -l $ENGAGEMENT_DIR/recon/active/scannable-ips.txt \
      -top-ports 1000 -rate 1000 -json -silent \
  > $ENGAGEMENT_DIR/recon/active/naabu.json
```
Full-port sweep: swap `-top-ports 1000` for `-p -` (slow; ask user).

## 6. Service / version detection

```bash
ports=$(jq -r '.port' $ENGAGEMENT_DIR/recon/active/naabu.json | sort -un | paste -sd,)
nmap -sV -sC -Pn --version-intensity 5 \
     -iL $ENGAGEMENT_DIR/recon/active/scannable-ips.txt \
     -p "$ports" -oA $ENGAGEMENT_DIR/recon/active/nmap

python3 -c '
import xml.etree.ElementTree as ET, subprocess
tree = ET.parse("'$ENGAGEMENT_DIR'/recon/active/nmap.xml")
for host in tree.findall(".//host"):
  ip = host.find("address").get("addr")
  for port in host.findall(".//port"):
    if port.find("state").get("state") != "open": continue
    p, proto = port.get("portid"), port.get("protocol")
    svc = port.find("service") or {}
    args = ["findings", "service-set", ip, f"{p}/{proto}"]
    if svc.get("name"):    args += ["--service", svc.get("name")]
    if svc.get("product"): args += ["--product", svc.get("product")]
    if svc.get("version"): args += ["--version", svc.get("version")]
    subprocess.run(args, check=False)
'
```

High-value ports to flag: 3389 RDP, 445 SMB, 6379 Redis, 27017 Mongo, 9200 ES, 11211 Memcached, 5672 AMQP, 2181 ZK, 9092 Kafka, 8080/8443 Jenkins/Tomcat.

## 7. Crawl (web targets)

```bash
katana -list $ENGAGEMENT_DIR/recon/active/live-hosts.txt \
       -depth 2 -jc -kf all -silent -json \
  > $ENGAGEMENT_DIR/recon/active/katana.json
```

## Hard rules

- Rate limits: `-rate 1000` (naabu) / `-T4` (nmap) ceiling unless user overrides.
- No exploitation here — scan and fingerprint only.
- Every pivot host (SAN, CNAME, katana out-of-link) → scope-check before probing.
- Never port-scan CDN IPs.

## Handoff to host-recon (MANDATORY for ≥4 hosts)

After this skill, if **≥4 live hosts**, dispatch `host-recon` subagents
IN PARALLEL — one Task call per host, all in one assistant message.
Cap 8 per batch.

For 1–3 hosts: run service-enum / web-enum / vuln-search inline.
