#!/bin/bash
# HTTPS service playbook. Args: <host> <port>
# Runs the HTTP playbook over TLS, then the shared TLS check.
set -u
host="${1:?host}"; port="${2:-443}"

# 1. HTTP-layer checks (headers, methods, robots, etc.) — done over TLS
PROTO=https /root/.claude/skills/service-enum/playbooks/http.sh "$host" "$port"

# 2. TLS-layer checks (cert, ciphers, protocols)
/root/.claude/skills/service-enum/playbooks/_lib/tls-check.sh "$host" "$port"

# Missing HSTS header check (HTTPS-specific)
http_out="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum/${host}-${port}-https.txt"
if [ -f "$http_out" ] && ! grep -qi "strict-transport-security:" "$http_out"; then
  findings add "$host" --port "$port/tcp" --severity low \
    --title "Missing HSTS header on HTTPS" \
    --evidence "no Strict-Transport-Security in response headers" \
    --source service-enum
fi
