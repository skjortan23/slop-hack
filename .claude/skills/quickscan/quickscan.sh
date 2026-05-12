#!/bin/bash
# quickscan: naabu → httpx → findings, as a native bash pipeline.
# Replaces the prior Python wrapper which had subprocess+pipe-buffering hangs
# when invoking httpx with `-silent -json > file`.
#
# Usage:
#   quickscan -l <targets-file>        # one host per line
#   quickscan <host>                   # single host
#   quickscan --full -l ...            # full-port (-p -) sweep
#   quickscan --no-http -l ...         # skip httpx enrichment
#   quickscan --no-log -l ...          # don't write findings, just print
#
# Output: one JSON line per (host, port) to stdout.

set -u

# Curated pentest port list — same as the old Python version.
DEFAULT_PORTS="21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,\
465,514,587,623,636,993,995,1080,\
1433,1521,1830,2483,2484,3306,5432,33060,\
5984,6379,6380,7474,7687,\
8086,8123,9042,9160,11211,\
26257,27017,27018,27019,28015,28017,28018,\
5672,9092,15672,\
1723,2049,2082,2083,2087,2096,2222,2375,2376,3000,3128,3268,\
3389,4443,4444,4500,4848,4949,5000,5060,5601,5900,5985,\
6443,7000,7001,7077,8000,8005,8009,8020,8022,8080,8081,\
8088,8090,8091,8161,8200,8443,8500,8530,8531,8649,8888,\
9000,9001,9043,9080,9090,9100,9200,9300,9418,9990,9999,\
10000,16379,26379,49152,50000,50070,50090"

TARGETS_FILE=""
SINGLE_HOST=""
PORTS="$DEFAULT_PORTS"
DO_HTTPX=1
DO_LOG=1
RATE=1000

while [ $# -gt 0 ]; do
  case "$1" in
    -l)         TARGETS_FILE="$2"; shift ;;
    -p)         PORTS="$2"; shift ;;
    --full)     PORTS="-" ;;
    --no-http)  DO_HTTPX=0 ;;
    --no-log)   DO_LOG=0 ;;
    --rate)     RATE="$2"; shift ;;
    --help|-h)
      sed -n '2,12p' "$0"
      exit 0 ;;
    *)
      if [ -z "$SINGLE_HOST" ] && [ -z "$TARGETS_FILE" ] && [[ "$1" != -* ]]; then
        SINGLE_HOST="$1"
      else
        echo "unknown flag: $1" >&2; exit 2
      fi ;;
  esac
  shift
done

if [ -z "$TARGETS_FILE" ] && [ -z "$SINGLE_HOST" ]; then
  echo "usage: quickscan [-l <file>] [<host>] [-p ports] [--full] [--no-http] [--no-log] [--rate N]" >&2
  exit 2
fi

# Build naabu input: a temp file containing all targets
TMP_TARGETS=$(mktemp)
trap 'rm -f "$TMP_TARGETS" "$NAABU_OUT" "$HTTPX_OUT"' EXIT

if [ -n "$TARGETS_FILE" ]; then
  cat "$TARGETS_FILE" > "$TMP_TARGETS"
fi
[ -n "$SINGLE_HOST" ] && echo "$SINGLE_HOST" >> "$TMP_TARGETS"
sort -u "$TMP_TARGETS" -o "$TMP_TARGETS"

NAABU_OUT=$(mktemp)
HTTPX_OUT=$(mktemp)

# Phase 1 — naabu port scan
if [ "$PORTS" = "-" ]; then
  NAABU_PFLAG="-p -"
else
  NAABU_PFLAG="-p $PORTS"
fi

echo "[quickscan] naabu $NAABU_PFLAG against $(wc -l < "$TMP_TARGETS") target(s)" >&2
# shellcheck disable=SC2086
naabu -list "$TMP_TARGETS" $NAABU_PFLAG -rate "$RATE" -silent -json \
  > "$NAABU_OUT" 2>/dev/null || true

HITS=$(wc -l < "$NAABU_OUT" | tr -d ' ')
echo "[quickscan] naabu found $HITS open port(s)" >&2

# Phase 2 — httpx enrichment (always probe common web ports too,
# even if naabu missed them — Cloudflare/WAF often drop SYN but serve HTTP)
HTTP_PROBE_PORTS="80 443 8000 8080 8081 8088 8443 8888 9000 9080 9090 9200 5000 5601 7474 8500"

declare -A FINGERPRINTS  # key = "host:port", val = JSON of httpx attrs

if [ "$DO_HTTPX" -eq 1 ]; then
  # Build httpx URL list: naabu HTTP-class hits + always-probe common web ports
  HTTPX_IN=$(mktemp)
  trap 'rm -f "$TMP_TARGETS" "$NAABU_OUT" "$HTTPX_OUT" "$HTTPX_IN"' EXIT

  # naabu hits that look HTTP-class
  jq -r 'select(.port | tostring | test("^(80|443|8000|8080|8081|8088|8443|8888|9000|9080|9090|9200|5000|5601|7474|8500)$")) | .host + ":" + (.port|tostring)' \
    "$NAABU_OUT" 2>/dev/null > "$HTTPX_IN"

  # Always-probe common web ports
  while read -r h; do
    for p in $HTTP_PROBE_PORTS; do
      echo "$h:$p" >> "$HTTPX_IN"
    done
  done < "$TMP_TARGETS"
  sort -u "$HTTPX_IN" -o "$HTTPX_IN"

  echo "[quickscan] httpx fingerprinting $(wc -l < "$HTTPX_IN") endpoint(s)" >&2
  # NO -silent — the silent-mode buffering interacts badly with output redirect
  # when stdout isn't a TTY (the bug the old Python wrapper hit). Plain JSON +
  # 2>/dev/null is fast and reliable.
  httpx -l "$HTTPX_IN" -title -tech-detect -server -status-code \
        -no-color -json -timeout 5 2>/dev/null > "$HTTPX_OUT" || true

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    host=$(jq -r '.host // .input' <<<"$line")
    port=$(jq -r '.port' <<<"$line")
    [ -z "$host" ] || [ -z "$port" ] && continue
    FINGERPRINTS["$host:$port"]="$line"
  done < "$HTTPX_OUT"
fi

# Phase 3 — emit unified JSON + log to findings
emit() {
  local host="$1" port="$2"
  local scheme="tcp" service="" product="" version="" banner="" title=""

  # Default service from port number
  case "$port" in
    21)    service="ftp" ;; 22)   service="ssh" ;; 23)  service="telnet" ;;
    25)    service="smtp" ;; 53)  service="dns" ;; 110) service="pop3" ;;
    135)   service="msrpc" ;; 139) service="smb" ;; 143) service="imap" ;;
    161)   service="snmp" ;; 389) service="ldap" ;; 445) service="smb" ;;
    993)   service="imaps" ;; 995) service="pop3s" ;;
    1433)  service="mssql" ;; 1521|1830|2483|2484) service="oracle" ;;
    3306|33060) service="mysql" ;; 3389) service="rdp" ;;
    5432)  service="postgres" ;; 5672) service="amqp" ;; 5900) service="vnc" ;;
    5984)  service="couchdb" ;; 6379|6380|16379|26379) service="redis" ;;
    6443)  service="k8s-api" ;; 8086) service="influxdb" ;;
    8200)  service="vault" ;; 8500) service="consul" ;;
    9042|9160) service="cassandra" ;; 9092) service="kafka" ;;
    9200|9300) service="elasticsearch" ;; 11211) service="memcached" ;;
    15672) service="rabbitmq" ;; 27017|27018|27019|28017) service="mongodb" ;;
    80|443|3000|5000|7000|8000|8080|8081|8088|8090|8888|9000|9080|9090|9999)
      service="http" ;;
    *)     service="unknown" ;;
  esac

  # Override with httpx fingerprint if available
  local fp="${FINGERPRINTS[$host:$port]:-}"
  if [ -n "$fp" ]; then
    service="http"
    product=$(jq -r '.tech // [] | .[0] // ""' <<<"$fp" | awk -F: '{print $1}')
    version=$(jq -r '.tech // [] | .[0] // ""' <<<"$fp" | awk -F: '{print $2}')
    banner=$(jq -r '.webserver // .server // ""' <<<"$fp")
    title=$(jq -r '.title // ""' <<<"$fp")
    [ -z "$banner" ] && [ -n "$title" ] && banner="$title"
  fi

  # Emit JSON line
  jq -c -n \
    --arg host "$host" --argjson port "$port" \
    --arg service "$service" --arg product "$product" --arg version "$version" \
    --arg banner "$banner" \
    '{host:$host, port:$port, service:$service, product:$product, version:$version, banner:$banner}'

  # Log to findings
  if [ "$DO_LOG" -eq 1 ]; then
    findings host-set "$host" --hostname "$host" >/dev/null 2>&1 || true
    args=("$host" "$port/tcp" "--service" "$service")
    [ -n "$product" ] && args+=("--product" "$product")
    [ -n "$version" ] && args+=("--version" "$version")
    [ -n "$banner" ]  && args+=("--banner" "$banner")
    findings service-set "${args[@]}" >/dev/null 2>&1 || true
  fi
}

# Union of (a) naabu hits and (b) httpx hits — covers WAF-fronted HTTP that
# naabu's SYN scan dropped
{
  jq -r '.host + " " + (.port|tostring)' "$NAABU_OUT" 2>/dev/null
  for k in "${!FINGERPRINTS[@]}"; do
    echo "${k/:/ }"
  done
} | sort -u | while read -r host port; do
  [ -n "$host" ] && [ -n "$port" ] && emit "$host" "$port"
done

echo "[quickscan] done" >&2
