#!/bin/bash
# SMTPS / submissions service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-465}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-smtps.txt"

/root/.claude/skills/service-enum/playbooks/_lib/tls-check.sh "$host" "$port"

{
  echo "=== SMTP EHLO over TLS ==="
  ( echo "EHLO slop-hack"; echo "QUIT"; sleep 1 ) | \
    timeout 8 openssl s_client -quiet -connect "${host}:${port}" \
      -servername "$host" 2>/dev/null | head -20

  echo
  echo "=== nmap smtp-commands + smtp-open-relay ==="
  nmap -Pn -p "$port" --script smtp-commands,smtp-open-relay "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# --- findings ---
if grep -qi "open relay" "$out"; then
  findings add "$host" --port "$port/tcp" --severity high \
    --title "SMTP open relay" \
    --evidence "$(grep -i relay "$out" | head -3)" \
    --source nmap
fi
if grep -qE "AUTH (PLAIN|LOGIN)" "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "SMTP plaintext auth mechanisms exposed" \
    --evidence "$(grep -E 'AUTH ' "$out" | head -3)" --source service-enum
fi
