#!/bin/bash
# SMB service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-445}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-smb.txt"

{
  echo "=== smbclient -L (null session, list shares) ==="
  smbclient -L "//${host}" -N -t 5 2>&1 | head -40

  echo
  echo "=== enum4linux-ng (basic) ==="
  if command -v enum4linux-ng >/dev/null; then
    timeout 60 enum4linux-ng -A "$host" 2>&1 | head -150
  elif command -v enum4linux >/dev/null; then
    timeout 60 enum4linux -a "$host" 2>&1 | head -150
  else
    echo "(enum4linux-ng / enum4linux not installed)"
  fi

  echo
  echo "=== nmap smb-os-discovery + smb-vuln-* ==="
  nmap -Pn -p "$port" -sV --script "smb-os-discovery,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb2-security-mode" \
    "$host" 2>&1 | sed -n '/PORT/,/Service/p' | head -80
} | tee "$out"

# --- findings ---

# Null session - shares listed
if grep -qE "^\s+(Disk|IPC|Print)\s+" "$out"; then
  shares=$(grep -E "^\s+(Disk|IPC|Print)\s+" "$out" | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "SMB null session — shares enumerable" \
    --evidence "shares: $shares" --source smbclient
fi

# MS17-010 (EternalBlue)
if grep -qi "VULNERABLE.*MS17-010" "$out"; then
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "MS17-010 (EternalBlue) — pre-auth RCE" \
    --evidence "$(grep -A3 -i ms17-010 "$out" | head -8)" \
    --source nmap
fi

# MS08-067
if grep -qi "VULNERABLE.*MS08-067" "$out"; then
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "MS08-067 — pre-auth RCE" \
    --evidence "$(grep -A3 -i ms08-067 "$out" | head -8)" \
    --source nmap
fi

# SMB signing disabled
if grep -qiE "message_signing.*disabled|signing\s*:\s*disabled" "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "SMB signing disabled (relay attack possible)" \
    --evidence "$(grep -iE 'sign' "$out" | head -3)" \
    --source nmap
fi

# OS / domain disclosure
if grep -qE "OS:\s+Windows|Computer name:|NetBIOS" "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "SMB OS / domain information disclosure" \
    --evidence "$(grep -E 'OS:|Computer|Domain|NetBIOS' "$out" | head -5)" \
    --source nmap
fi
