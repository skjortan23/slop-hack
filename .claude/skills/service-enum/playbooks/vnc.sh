#!/bin/bash
# VNC service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-5900}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-vnc.txt"

{
  echo "=== banner ==="
  timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port; head -1 <&3; exec 3<&-" 2>/dev/null

  echo
  echo "=== nmap vnc-info + realvnc-auth-bypass ==="
  nmap -Pn -p "$port" --script "vnc-info,vnc-title,realvnc-auth-bypass" "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# --- findings ---

# RealVNC auth bypass
if grep -qi "VULNERABLE.*realvnc" "$out"; then
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "RealVNC auth bypass (CVE-2006-2369)" \
    --evidence "$(grep -A3 -i realvnc "$out" | head -8)" --source nmap
fi

# No-auth VNC (Security types include None/0)
if grep -qiE "Security types?:.*None|Security types?:.*\b0\b" "$out"; then
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "VNC accepts no-auth connections" \
    --evidence "$(grep -i 'security type' "$out" | head -3)" --source nmap
fi

# Banner / version disclosure
banner=$(head -3 "$out" | grep -E "^RFB " | head -1)
if [ -n "$banner" ]; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "VNC version disclosure" \
    --evidence "$banner" --source service-enum
fi
