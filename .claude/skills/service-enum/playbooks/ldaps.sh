#!/bin/bash
# LDAPS service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-636}"

# TLS-layer first
/root/.claude/skills/service-enum/playbooks/_lib/tls-check.sh "$host" "$port"

# Then standard LDAP enum over TLS
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-ldaps.txt"

{
  echo "=== anonymous rootDSE over TLS ==="
  timeout 8 ldapsearch -x -H "ldaps://${host}:${port}" -s base -b "" \
    -o tls_reqcert=never \
    "(objectclass=*)" 2>&1 | head -60
} | tee "$out"

if grep -qE "namingContexts:|defaultNamingContext:|rootDomainNamingContext:" "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "LDAPS anonymous bind allowed" \
    --evidence "$(grep -E 'namingContexts:|defaultNamingContext:' "$out" | head -3)" \
    --source ldapsearch
fi
