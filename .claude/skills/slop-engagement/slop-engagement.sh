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

  echo "  → $(wc -l < "$HOSTS_FILE") unique subdomains discovered"
fi

# ── phase 2: dnsx — narrow to live hosts ──
say "phase 2 — DNS resolve"
LIVE_FILE="$ENGAGEMENT_DIR/recon/active/live-hosts.txt"
timeout 60 dnsx -nc -l "$HOSTS_FILE" -resp -a -cname -silent \
  -r /opt/resolvers/resolvers.txt 2>/dev/null \
  > "$ENGAGEMENT_DIR/recon/active/dnsx.txt" || true

# Hosts with A records — proceed normally
awk '/\[A\]/ { print $1 }' \
  "$ENGAGEMENT_DIR/recon/active/dnsx.txt" \
  | sort -u > "$LIVE_FILE"

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

# ── phase 3: quickscan (sweep all live hosts, populate service inventory) ──
say "phase 3 — quickscan (port + service inventory)"
QS_PORTS=""
case "$DEPTH" in
  shallow) QS_PORTS="-p 22,80,443,8080,8443" ;;
  deep)    QS_PORTS="--full" ;;
  *)       QS_PORTS="" ;;  # use defaults (~80 pentest ports)
esac

timeout 600 quickscan -l "$LIVE_FILE" $QS_PORTS 2>&1 \
  | grep -vE "(getcwd|^\[naabu\]|^\[httpx\])" \
  | tail -30 || true

# ── phase 4: per-host webapp pipeline ──
if [ "$DO_WEBAPP" -eq 1 ]; then
  say "phase 4 — webapp pipeline (per HTTP host)"

  # Collect web hosts from findings inventory
  WEB_HOSTS=$(findings services --json 2>/dev/null \
    | jq -r '.[] | select(.service | test("^http")) | .host' \
    | sort -u)

  if [ -z "$WEB_HOSTS" ]; then
    echo "  no web hosts in inventory — skipping webapp pipeline"
  else
    echo "  web hosts: $(echo "$WEB_HOSTS" | wc -l | tr -d ' ')"

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

    # If we have any endpoints, run authcheck + fuzz + confirm
    if [ -s "$ENGAGEMENT_DIR/webapp/endpoints.jsonl" ]; then
      echo
      say "phase 4a — endpoint-authcheck"
      timeout 300 endpoint-authcheck --rate-limit 0.3 2>&1 \
        | tail -25 || true

      echo
      say "phase 4b — webapp-fuzz (nuclei DAST)"
      # Build URL list from endpoints
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
    fi
  fi
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
