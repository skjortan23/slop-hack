#!/bin/bash
# RDP service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-3389}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-rdp.txt"

{
  echo "=== nmap rdp-enum-encryption + rdp-vuln-ms12-020 + rdp-ntlm-info ==="
  nmap -Pn -p "$port" --script "rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info" \
    "$host" 2>&1 | sed -n '/PORT/,/Service/p' | head -80
} | tee "$out"

# --- findings ---

# BlueKeep / MS17-010-class? actually MS12-020 is the relevant one nmap detects
if grep -qi "VULNERABLE.*MS12-020" "$out"; then
  findings add "$host" --port "$port/tcp" --severity high \
    --title "MS12-020 — RDP DoS / RCE" \
    --evidence "$(grep -A3 -i ms12-020 "$out" | head -8)" \
    --source nmap
fi

# Weak protocol (no NLA / standard RDP security)
if grep -qiE "Security level: [0-2]\b|Security mode: standard" "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "RDP weak/no NLA — credential capture / DoS risk" \
    --evidence "$(grep -iE 'security' "$out" | head -3)" \
    --source nmap
fi

# OS / hostname disclosure
if grep -qE "Target_Name:|NetBIOS_Domain_Name:|DNS_Computer_Name:" "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "RDP NTLM info disclosure (host/domain)" \
    --evidence "$(grep -E 'Target_|NetBIOS_|DNS_' "$out" | head -5)" \
    --source nmap
fi
