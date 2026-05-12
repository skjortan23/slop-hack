#!/bin/bash
# slop-engagement: deterministic end-to-end engagement chain.
#
# Runs the full passive→active→service-enum→webapp→vuln chain against a
# root domain (or single host) WITHOUT relying on the LLM to remember the
# playbook order. The LLM stays in the picture only for severity reasoning
# at the end if you choose to invoke claude on the report.
#
# Usage:
#   slop-engagement <root-domain>                  # full engagement
#   slop-engagement <host>                         # single-host (no passive enum)
#   slop-engagement <root> --single-host           # treat root as a single live host
#   slop-engagement <root> --no-webapp             # skip webapp fuzz/confirm chain
#   slop-engagement <root> --depth deep            # full port sweep, deeper nuclei
#
# Designed to be run inside the slop-hack container with $ENGAGEMENT_DIR set
# and scope.yaml present. Every step is bounded by `timeout` and writes
# structured output to $ENGAGEMENT_DIR.

set -u
shopt -s nullglob

ROOT="${1:-}"
shift || true
if [ -z "$ROOT" ]; then
  cat <<EOF
usage: slop-engagement <root-domain-or-host> [--single-host] [--no-webapp] [--depth shallow|normal|deep]

Reads scope.yaml from /scope/. Writes to \$ENGAGEMENT_DIR (default /work/default).
EOF
  exit 2
fi

SINGLE_HOST=0
DO_WEBAPP=1
DEPTH="normal"

while [ $# -gt 0 ]; do
  case "$1" in
    --single-host) SINGLE_HOST=1 ;;
    --no-webapp)   DO_WEBAPP=0 ;;
    --depth)       DEPTH="$2"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

: "${ENGAGEMENT_DIR:=/work/default}"
mkdir -p "$ENGAGEMENT_DIR/recon/passive" \
         "$ENGAGEMENT_DIR/recon/active" \
         "$ENGAGEMENT_DIR/webapp" \
         "$ENGAGEMENT_DIR/findings/hosts"

LOG="$ENGAGEMENT_DIR/engagement.log"
exec > >(tee -a "$LOG") 2>&1

say() { printf '\n=== [%s] %s ===\n' "$(date +%H:%M:%S)" "$*"; }

say "engagement start: target=$ROOT depth=$DEPTH webapp=$DO_WEBAPP single_host=$SINGLE_HOST"
say "engagement dir: $ENGAGEMENT_DIR"

# ── scope check ──
say "scope-check $ROOT"
if ! scope-check "$ROOT" >/dev/null 2>&1; then
  echo "ABORT: $ROOT is not in scope (per scope.yaml)" >&2
  scope-check "$ROOT"
  exit 1
fi
echo "  in scope"

# ── preflight: net-health ──
say "preflight — net-health"
NET_STATE=$(net-health --json 2>/dev/null | jq -r '.state' 2>/dev/null || echo "unknown")
echo "  state: $NET_STATE"
case "$NET_STATE" in
  egress-broken)
    echo "ABORT: net-health reports egress-broken — check network before running engagement" >&2
    exit 2
    ;;
  port-scan-suppressed)
    echo "  ⚠ port-scan suppressed — naabu will return 0; HTTP-only enumeration will still work"
    echo "  ⚠ findings tagged with port_scan_suppressed=true"
    PORT_SCAN_SUPPRESSED=1
    ;;
  partial-degraded|unknown)
    echo "  ⚠ network partially degraded — proceeding but expect reduced port-scan coverage"
    PORT_SCAN_SUPPRESSED=0
    ;;
  healthy)
    PORT_SCAN_SUPPRESSED=0
    ;;
esac

# ── phase 1: passive recon (skip if --single-host) ──
HOSTS_FILE="$ENGAGEMENT_DIR/recon/passive/subdomains.txt"
if [ "$SINGLE_HOST" -eq 1 ]; then
  say "single-host mode — treating $ROOT as the only target"
  echo "$ROOT" > "$HOSTS_FILE"
else
  say "phase 1 — passive recon"

  echo "  · subfinder"
  timeout 60 subfinder -d "$ROOT" -all -silent \
    > "$ENGAGEMENT_DIR/recon/passive/subfinder.txt" 2>/dev/null || true

  echo "  · amass passive"
  timeout 120 amass enum -passive -d "$ROOT" \
    -o "$ENGAGEMENT_DIR/recon/passive/amass.txt" >/dev/null 2>&1 || true

  echo "  · crt.sh"
  timeout 30 curl -sf "https://crt.sh/?q=%.$ROOT&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | tr ',' '\n' \
    > "$ENGAGEMENT_DIR/recon/passive/crtsh.txt" || true

  if [ "$DEPTH" = "deep" ]; then
    echo "  · theHarvester"
    timeout 90 theHarvester -d "$ROOT" -b crtsh,duckduckgo,bing,otx \
      -f "$ENGAGEMENT_DIR/recon/passive/harvester" >/dev/null 2>&1 || true
  fi

  echo "  · merging + filtering to valid hostnames"
  {
    cat "$ENGAGEMENT_DIR/recon/passive/subfinder.txt" 2>/dev/null
    cat "$ENGAGEMENT_DIR/recon/passive/amass.txt" 2>/dev/null
    cat "$ENGAGEMENT_DIR/recon/passive/crtsh.txt" 2>/dev/null
    echo "$ROOT"
  } | grep -E '^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$' \
    | tr '[:upper:]' '[:lower:]' \
    | sort -u > "$HOSTS_FILE"

  echo "  → $(wc -l < "$HOSTS_FILE") unique subdomains from CT/passive"

  # Subdomain brute (unconditional) — CT logs miss subdomains covered by a
  # wildcard cert (caught app.codelight.ai which crt.sh missed). Also misses
  # subdomains where no cert was ever issued (internal-only services that
  # got a public DNS A record). This is cheap (60 DNS queries) so run always.
  echo "  · brute-forcing common subdomain prefixes"
  BRUTE_CANDS="$ENGAGEMENT_DIR/recon/passive/brute-cands.txt"
  > "$BRUTE_CANDS"
  for prefix in \
      app api admin dev staging prod beta qa test preview \
      www mail smtp imap pop mx \
      portal dashboard console manage \
      new old v1 v2 \
      ci build deploy jenkins gitlab git registry pipeline \
      cdn static assets media files images \
      monitor status metrics health \
      shop store billing account profile login signup \
      auth oauth sso \
      internal private vpn \
      cpanel webmin plesk control \
      graphql api2 api-v1 api-v2 \
      docs help support kb \
      demo sandbox training; do
    echo "${prefix}.${ROOT}" >> "$BRUTE_CANDS"
  done
  timeout 60 dnsx -nc -l "$BRUTE_CANDS" -resp -a -silent \
    -r /opt/resolvers/resolvers.txt 2>/dev/null \
    | awk '/\[A\]/ {print $1}' | sort -u \
    > "$ENGAGEMENT_DIR/recon/passive/brute-resolved.txt"

  NEW_HOSTS=$(comm -23 \
      "$ENGAGEMENT_DIR/recon/passive/brute-resolved.txt" \
      "$HOSTS_FILE" 2>/dev/null)
  if [ -n "$NEW_HOSTS" ]; then
    echo "$NEW_HOSTS" >> "$HOSTS_FILE"
    sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
    echo "  → +$(echo "$NEW_HOSTS" | wc -l | tr -d ' ') subdomains via brute:"
    echo "$NEW_HOSTS" | head -10 | sed 's/^/      /'
  else
    echo "  → no new subdomains from brute"
  fi

  echo "  → $(wc -l < "$HOSTS_FILE") unique subdomains total"
fi

# ── phase 2: dnsx — annotate with DNS, but don't gate on it ──
# Earlier architecture filtered hosts by dnsx -a result. dnsx is brittle
# (rate-limit, partial failures, resolver flakiness). We saw 7/73 hosts
# silently drop here. Instead: keep ALL hosts from passive-recon as
# candidates, let httpx in phase 3 decide what's actually live.
say "phase 2 — DNS annotate (non-gating)"
LIVE_FILE="$ENGAGEMENT_DIR/recon/active/live-hosts.txt"
timeout 120 dnsx -nc -retry 3 -l "$HOSTS_FILE" -resp -a -cname -silent \
  -r /opt/resolvers/resolvers.txt 2>/dev/null \
  > "$ENGAGEMENT_DIR/recon/active/dnsx.txt" || true

# All passive-recon hosts go into live-hosts — even if dnsx didn't resolve
# them this run (httpx is the actual liveness check downstream).
cp "$HOSTS_FILE" "$LIVE_FILE"

# Hosts with CNAME but no A — subdomain takeover candidates.
# We want these in the live list AND surfaced as a finding so the agent
# / report doesn't miss them. dangling CNAME = potential takeover.
DANGLING_FILE="$ENGAGEMENT_DIR/recon/active/dangling-cname.txt"
awk '/\[CNAME\]/ { print $1 " " $3 }' \
  "$ENGAGEMENT_DIR/recon/active/dnsx.txt" \
  | sort -u > "$DANGLING_FILE.all"
# Keep only those whose source host does NOT appear in $LIVE_FILE
> "$DANGLING_FILE"
while read -r host cname; do
  if ! grep -qFx "$host" "$LIVE_FILE"; then
    echo "$host CNAME $cname" >> "$DANGLING_FILE"
    # Add this host to the live list — the agent should investigate
    echo "$host" >> "$LIVE_FILE"
    # Log immediate finding so it's not lost
    findings host-set "$host" --hostname "$host" \
      --note "dangling CNAME → $cname (no A record)" >/dev/null 2>&1
    findings add "$host" \
      --severity medium \
      --title "Dangling CNAME — potential subdomain takeover candidate" \
      --evidence "DNS CNAME: $host → $cname; CNAME target does not resolve to A record. If '$cname' is registrable, attacker could claim it." \
      --source slop-engagement >/dev/null 2>&1
  fi
done < "$DANGLING_FILE.all"
sort -u "$LIVE_FILE" -o "$LIVE_FILE"
DANGLING_COUNT=$(wc -l < "$DANGLING_FILE" 2>/dev/null || echo 0)
[ "$DANGLING_COUNT" -gt 0 ] && echo "  → $DANGLING_COUNT dangling CNAME(s) — flagged as medium-severity takeover candidates"
LIVE_COUNT=$(wc -l < "$LIVE_FILE")
echo "  → $LIVE_COUNT live hosts"

if [ "$LIVE_COUNT" -eq 0 ]; then
  echo "ABORT: no hosts resolved" >&2
  exit 1
fi

# Log every live host into findings (creates per-host YAMLs)
while read -r h; do
  findings host-set "$h" --hostname "$h" >/dev/null 2>&1
done < "$LIVE_FILE"

# ── phase 3: httpx DIRECTLY on every live host (not gated by naabu) ──
# This is the critical change vs prior architecture: even when naabu can't
# get through (Cloudflare drops SYN, WAF filters, etc.), we ALWAYS attempt
# HTTP fingerprint on every live host. That guarantees the webapp pipeline
# in phase 4 has something to work with.
say "phase 3 — HTTP probing (every live host, 80+443)"
HTTPX_OUT="$ENGAGEMENT_DIR/recon/active/httpx-direct.json"
# Keep the URL list lean: just 80 and 443. Extra ports (8080/8443/8000)
# add noise on CDN-fronted targets (Cloudflare doesn't proxy them by
# default) and cause httpx to fan out to many connections, tripping
# rate limits and dropping responses inconsistently.
# After this initial probe, the agent can probe specific extra ports
# per-host if the surface looks interesting.
{
  while read -r h; do
    echo "https://$h"
    echo "http://$h"
  done < "$LIVE_FILE"
} > "$ENGAGEMENT_DIR/recon/active/httpx-urls.txt"

# Rate-limit aggressively to keep Cloudflare/CDN happy. The chain is
# bounded by total wall-clock, not single-host speed.
timeout 300 sh -c "httpx -l '$ENGAGEMENT_DIR/recon/active/httpx-urls.txt' \
  -title -tech-detect -server -status-code -follow-redirects \
  -no-color -silent -json -timeout 20 \
  -rate-limit 10 -threads 5 \
  > '$HTTPX_OUT'" 2>/dev/null || true

# Log each HTTP-responsive host as a service in findings
WEB_HOSTS=$(jq -r '.host' "$HTTPX_OUT" 2>/dev/null | sort -u)
HTTP_HIT_COUNT=$(jq -r '.host' "$HTTPX_OUT" 2>/dev/null | wc -l | tr -d ' ')
echo "  → $HTTP_HIT_COUNT HTTP endpoints responsive"

if [ -s "$HTTPX_OUT" ]; then
  while read -r line; do
    [ -z "$line" ] && continue
    host=$(echo "$line" | jq -r '.host')
    port=$(echo "$line" | jq -r '.port')
    scheme=$(echo "$line" | jq -r '.scheme')
    server=$(echo "$line" | jq -r '.webserver // .server // ""')
    tech=$(echo "$line" | jq -r '.tech // [] | join(",")')
    title=$(echo "$line" | jq -r '.title // ""')
    status=$(echo "$line" | jq -r '.status_code')
    findings host-set "$host" --hostname "$host" >/dev/null 2>&1
    args=("$host" "${port}/tcp" "--service" "$scheme")
    [ -n "$server" ] && [ "$server" != "null" ] && args+=("--product" "$server")
    banner="HTTP $status${title:+ \"$title\"}${tech:+ tech=$tech}"
    args+=("--banner" "$banner")
    findings service-set "${args[@]}" >/dev/null 2>&1
  done < <(jq -c '.' "$HTTPX_OUT")
fi

# ── phase 3b: quickscan for non-HTTP services (additive, not gating) ──
say "phase 3b — quickscan (non-HTTP port discovery)"
QS_PORTS=""
case "$DEPTH" in
  shallow) QS_PORTS="-p 22,80,443,8080,8443" ;;
  deep)    QS_PORTS="--full" ;;
  *)       QS_PORTS="" ;;
esac
timeout 600 quickscan -l "$LIVE_FILE" $QS_PORTS 2>&1 \
  | grep -vE "(getcwd|^\[naabu\]|^\[httpx\])" \
  | tail -10 || true

# ── phase 4: webapp pipeline — runs whenever ANY HTTP host responds ──
if [ "$DO_WEBAPP" -eq 1 ] && [ -n "$WEB_HOSTS" ]; then
  say "phase 4 — webapp pipeline (per HTTP host)"
  echo "  web hosts (from httpx phase 3): $(echo "$WEB_HOSTS" | wc -l | tr -d ' ')"

  # Pull OpenAPI per host where available; import into endpoints.jsonl
  while read -r host; do
    [ -z "$host" ] && continue
    spec="$ENGAGEMENT_DIR/webapp/${host//\//_}-openapi.json"
    echo "  · curl https://$host/openapi.json"
    timeout 15 curl -sk -m 12 "https://$host/openapi.json" -o "$spec" 2>/dev/null
    if [ -s "$spec" ] && head -c 1 "$spec" | grep -q '{'; then
      echo "    ✓ got $(wc -c <"$spec") bytes — importing"
      openapi-import "$spec" --base-url "https://$host" 2>&1 | tail -3
    else
      rm -f "$spec"
    fi
  done <<< "$WEB_HOSTS"

  # If we have any endpoints, run authcheck (MANDATORY — not optional)
  if [ -s "$ENGAGEMENT_DIR/webapp/endpoints.jsonl" ]; then
    echo
    say "phase 4a — endpoint-authcheck (every endpoint without auth)"
    timeout 300 endpoint-authcheck --rate-limit 0.3 2>&1 | tail -30 || true

    echo
    say "phase 4b — webapp-fuzz (nuclei DAST)"
    URLS="$ENGAGEMENT_DIR/webapp/fuzz-urls.txt"
    jq -r '.url_template' "$ENGAGEMENT_DIR/webapp/endpoints.jsonl" \
      | sed 's/{[^}]*}/1/g' | sort -u > "$URLS"
    if [ -s "$URLS" ]; then
      timeout 600 nuclei -l "$URLS" -dast \
        -severity low,medium,high,critical \
        -rate-limit 50 \
        -json-export "$ENGAGEMENT_DIR/webapp/dast.json" \
        -silent 2>&1 | tail -5 || true
      DAST_HITS=$(wc -l < "$ENGAGEMENT_DIR/webapp/dast.json" 2>/dev/null || echo 0)
      echo "  → $DAST_HITS DAST hits"
    fi
  else
    echo "  no openapi.json found on any web host — skipping authcheck/fuzz"
  fi
elif [ "$DO_WEBAPP" -eq 1 ]; then
  say "phase 4 — webapp pipeline skipped (no HTTP-responsive hosts)"
fi

# ── phase 5: vuln-check per detected service version ──
say "phase 5 — vuln-check across detected services"
findings services --json 2>/dev/null \
  | jq -r '.[] | select(.product != "") | "\(.host) \(.port|split("/")[0]) \(.product) \(.version)"' \
  | while read -r host port product version; do
      [ -z "$product" ] && continue
      echo "  · vuln-check $host $port $product $version"
      timeout 120 vuln-check "$host" "$port" "$product" "$version" 2>&1 \
        | tail -3 || true
    done

# ── phase 6: report ──
say "phase 6 — report"
findings export-md > "$ENGAGEMENT_DIR/report.md"
echo "  → $ENGAGEMENT_DIR/report.md"

# ── summary ──
say "engagement complete"
findings list 2>/dev/null | head -30
echo
echo "severity breakdown:"
jq -r '.severity' "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | sort | uniq -c
echo
echo "high/critical findings (the actionable ones):"
jq -r 'select(.severity=="high" or .severity=="critical") | "  [\(.severity)] \(.host): \(.title)"' \
  "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null
echo
echo "log:    $LOG"
echo "report: $ENGAGEMENT_DIR/report.md"
