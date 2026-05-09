#!/bin/bash
# HTTP service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-80}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
proto="${PROTO:-http}"   # https.sh re-invokes with PROTO=https
out="$out_dir/${host}-${port}-${proto}.txt"
url="${proto}://${host}:${port}"

{
  echo "=== HEAD / ==="
  curl -sIk "$url/" -m 10 --connect-timeout 5

  echo
  echo "=== OPTIONS / ==="
  curl -sIk -X OPTIONS "$url/" -m 10 --connect-timeout 5

  echo
  echo "=== robots.txt ==="
  curl -sk "$url/robots.txt" -m 5 --connect-timeout 5 | head -40

  echo
  echo "=== /.well-known/security.txt ==="
  curl -sk "$url/.well-known/security.txt" -m 5 --connect-timeout 5 | head -20

  echo
  echo "=== nmap http-enum (top hits) ==="
  nmap -Pn -p "$port" --script http-enum --script-args http-enum.fingerprintfile=/usr/share/nmap/nselib/data/http-fingerprints.lua \
       "$host" 2>&1 | grep -A1 "http-enum" | head -40
} | tee "$out"

# --- findings ---

# Server header disclosure
server=$(awk -F': *' 'tolower($1)=="server"{print $2; exit}' "$out" | tr -d '\r')
if [ -n "$server" ]; then
  findings add "$host" --port "$port/tcp" --severity low \
    --title "HTTP Server header discloses software version" \
    --evidence "Server: $server" \
    --source service-enum
fi

# Powered-by header
powered=$(awk -F': *' 'tolower($1)=="x-powered-by"{print $2; exit}' "$out" | tr -d '\r')
if [ -n "$powered" ]; then
  findings add "$host" --port "$port/tcp" --severity low \
    --title "X-Powered-By header discloses framework" \
    --evidence "X-Powered-By: $powered" \
    --source service-enum
fi

# Dangerous HTTP methods
allow=$(awk -F': *' 'tolower($1)=="allow"{print $2; exit}' "$out" | tr -d '\r')
if echo "$allow" | grep -qiE "\b(PUT|DELETE|TRACE|TRACK|CONNECT)\b"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "Dangerous HTTP methods allowed" \
    --evidence "Allow: $allow" \
    --source service-enum
fi

# robots leaks
if grep -qE "Disallow:.*\b(admin|backup|config|internal|debug|test|dev|staging|private)\b" "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "robots.txt references sensitive paths" \
    --evidence "$(grep -E 'Disallow' "$out" | grep -iE 'admin|backup|config|internal|debug|private' | head -5)" \
    --source service-enum
fi

# nmap http-enum hits
if grep -E "/\S+:.*(possibly|interesting)" "$out" >/dev/null 2>&1; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "nmap http-enum: interesting paths found" \
    --evidence "$(grep -E "/\S+:" "$out" | head -10)" \
    --source nmap
fi
