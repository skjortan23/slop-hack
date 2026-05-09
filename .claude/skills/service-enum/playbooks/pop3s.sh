#!/bin/bash
# POP3S service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-995}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-pop3s.txt"

/root/.claude/skills/service-enum/playbooks/_lib/tls-check.sh "$host" "$port"

{
  echo "=== POP3 banner + CAPA over TLS ==="
  ( echo "CAPA"; echo "QUIT"; sleep 1 ) | \
    timeout 8 openssl s_client -quiet -connect "${host}:${port}" \
      -servername "$host" 2>/dev/null | head -10

  echo
  echo "=== nmap pop3-capabilities ==="
  nmap -Pn -p "$port" --script pop3-capabilities "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -30
} | tee "$out"
