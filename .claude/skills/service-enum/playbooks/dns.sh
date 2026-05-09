#!/bin/bash
# DNS service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-53}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-dns.txt"

# Try to derive a domain to test AXFR against. The user may pass it as $TARGET_DOMAIN.
domain="${TARGET_DOMAIN:-}"

{
  echo "=== version.bind ==="
  dig @"$host" -p "$port" version.bind chaos txt +short +timeout=5 2>&1
  dig @"$host" -p "$port" hostname.bind chaos txt +short +timeout=5 2>&1

  echo
  echo "=== recursion check ==="
  dig @"$host" -p "$port" www.google.com +short +timeout=5 2>&1 | head -3

  if [ -n "$domain" ]; then
    echo
    echo "=== AXFR ${domain} ==="
    dig @"$host" -p "$port" "$domain" AXFR +timeout=10 2>&1 | head -100
  else
    echo
    echo "(AXFR skipped — set TARGET_DOMAIN env var to test zone transfer)"
  fi

  echo
  echo "=== nmap dns-recursion + dns-cache-snoop ==="
  nmap -Pn -p "$port" -sU --script dns-recursion,dns-cache-snoop "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# --- findings ---

# Version disclosure
ver=$(grep -E "^\"" "$out" | head -1 | tr -d '"')
if [ -n "$ver" ] && ! echo "$ver" | grep -qi "refused\|denied\|servfail"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "DNS version.bind disclosed" \
    --evidence "$ver" --source dig
fi

# Open recursion
if grep -qE "^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" "$out" \
   && ! grep -qE "^;.*REFUSED|^;.*SERVFAIL" "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "DNS open recursion — usable for amplification" \
    --evidence "Resolved external query through this server" --source dig
fi

# AXFR successful (zone transfer)
if [ -n "$domain" ] && grep -qE "^${domain}\.\s+\S+\s+IN\s+SOA" "$out"; then
  records=$(grep -cE "^\S+\s+\S+\s+IN\s+" "$out")
  findings add "$host" --port "$port/tcp" --severity high \
    --title "DNS zone transfer (AXFR) allowed for ${domain}" \
    --evidence "${records} records dumped via AXFR" --source dig
fi
