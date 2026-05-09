#!/bin/bash
# IMAPS service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-993}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-imaps.txt"

# TLS-layer checks
/root/.claude/skills/service-enum/playbooks/_lib/tls-check.sh "$host" "$port"

{
  echo "=== IMAP CAPABILITY (over TLS) ==="
  ( echo "a CAPABILITY"; echo "b LOGOUT"; sleep 1 ) | \
    timeout 8 openssl s_client -quiet -connect "${host}:${port}" \
      -servername "$host" 2>/dev/null | head -10

  echo
  echo "=== nmap imap-capabilities ==="
  nmap -Pn -p "$port" --script imap-capabilities,imap-ntlm-info "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# --- findings ---
if grep -qE "AUTH=PLAIN|AUTH=LOGIN" "$out" && ! grep -qi "TLS" "$out"; then
  findings add "$host" --port "$port/tcp" --severity low \
    --title "IMAPS exposes plaintext-equivalent auth mechanisms" \
    --evidence "$(grep -E 'AUTH=' "$out" | head -3)" --source service-enum
fi
