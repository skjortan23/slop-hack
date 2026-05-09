#!/bin/bash
# FTP service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-21}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-ftp.txt"

{
  echo "=== banner ==="
  timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port; head -3 <&3; exec 3<&-" 2>/dev/null

  echo
  echo "=== anonymous login attempt ==="
  curl -sS --connect-timeout 5 -m 15 -u "anonymous:anon@example.com" \
    "ftp://${host}:${port}/" 2>&1 | head -40

  echo
  echo "=== nmap ftp-anon + ftp-bounce + ftp-syst ==="
  nmap -Pn -p "$port" --script ftp-anon,ftp-syst,ftp-bounce "$host" 2>&1 \
    | sed -n "/PORT/,/Service/p" | head -40
} | tee "$out"

# --- findings ---

banner=$(head -5 "$out" | grep -E "^220" | head -1)
if [ -n "$banner" ]; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "FTP banner discloses version" \
    --evidence "$banner" --source service-enum
fi

# Anonymous login
if grep -qiE "230 (login|user) (logged in|.*anonymous)|Anonymous FTP login allowed" "$out"; then
  findings add "$host" --port "$port/tcp" --severity high \
    --title "Anonymous FTP login allowed" \
    --evidence "$(grep -iE '230|anonymous' "$out" | head -5)" \
    --source nmap
fi

# Bounce vulnerability
if grep -qi "ftp-bounce: bounce working" "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "FTP bounce attack possible" \
    --evidence "$(grep -i bounce "$out" | head -3)" \
    --source nmap
fi
