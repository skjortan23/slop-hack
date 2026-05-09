#!/bin/bash
# LDAP service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-389}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-ldap.txt"

{
  echo "=== anonymous root DSE bind ==="
  timeout 8 ldapsearch -x -H "ldap://${host}:${port}" -s base -b "" \
    "(objectclass=*)" 2>&1 | head -60

  echo
  echo "=== nmap ldap-rootdse + ldap-search ==="
  nmap -Pn -p "$port" --script ldap-rootdse "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# --- findings ---
if grep -qE "namingContexts:|defaultNamingContext:|rootDomainNamingContext:" "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "LDAP anonymous bind allowed (rootDSE readable)" \
    --evidence "$(grep -E 'namingContexts:|defaultNamingContext:' "$out" | head -3)" \
    --source ldapsearch
fi
