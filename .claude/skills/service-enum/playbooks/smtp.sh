#!/bin/bash
# SMTP (with STARTTLS where present). Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-25}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-smtp.txt"

{
  echo "=== banner + EHLO ==="
  ( echo "EHLO slop-hack"; echo "QUIT"; sleep 1 ) | \
    timeout 8 ncat --recv-only "$host" "$port" 2>/dev/null | head -20 || \
    ( echo "EHLO slop-hack"; echo "QUIT"; sleep 1 ) | \
    timeout 8 nc "$host" "$port" 2>/dev/null | head -20

  echo
  echo "=== nmap smtp-commands + smtp-open-relay + smtp-enum-users ==="
  nmap -Pn -p "$port" --script smtp-commands,smtp-open-relay "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# Run TLS check via STARTTLS if EHLO advertised it
if grep -qE "STARTTLS" "$out"; then
  /root/.claude/skills/service-enum/playbooks/_lib/tls-check.sh "$host" "$port" smtp
fi

# --- findings ---
if grep -qi "open relay" "$out"; then
  findings add "$host" --port "$port/tcp" --severity high \
    --title "SMTP open relay" \
    --evidence "$(grep -i relay "$out" | head -3)" --source nmap
fi
if grep -qE "VRFY|EXPN" "$out" && ! grep -qE "VRFY: (disabled|denied)" "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "SMTP VRFY/EXPN enabled (user enumeration)" \
    --evidence "$(grep -E 'VRFY|EXPN' "$out" | head -3)" --source service-enum
fi
