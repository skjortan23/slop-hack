#!/bin/bash
# tls-check.sh — generic TLS cert + protocol + cipher check.
# Called by any TLS-capable playbook (https, imaps, smtps, ldaps, etc.)
#
# Usage: tls-check.sh <host> <port> [starttls-proto]
#   starttls-proto: smtp | imap | pop3 | ftp | xmpp | xmpp-server | irc | postgres | mysql | lmtp | nntp | sieve | ldap
set -u
host="${1:?host}"; port="${2:?port}"; starttls="${3:-}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-tls.txt"

s_args=()
[ -n "$starttls" ] && s_args+=(-starttls "$starttls")

{
  echo "=== openssl s_client (cert + chain) ==="
  echo | timeout 10 openssl s_client -servername "$host" -connect "${host}:${port}" "${s_args[@]}" 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null

  echo
  echo "=== tlsx validation (versions/ciphers/expired/self-signed/wildcard) ==="
  # NOTE: -san/-cn can NOT be combined with other probes (tlsx fatal error),
  # so we split into two passes.
  echo "${host}:${port}" | tlsx -tls-version -cipher \
       -expired -self-signed -mismatched -untrusted -wildcard-cert \
       -json -silent 2>/dev/null
  echo
  echo "=== tlsx subject (san/cn) ==="
  echo "${host}:${port}" | tlsx -san -cn -json -silent 2>/dev/null

  echo
  echo "=== nmap ssl-enum-ciphers ==="
  if [ -n "$starttls" ]; then
    nmap -Pn -p "$port" --script ssl-enum-ciphers \
         --script-args "ssl-enum-ciphers.starttls=${starttls}" "$host" 2>&1 \
      | sed -n '/PORT/,/Service/p' | head -100
  else
    nmap -Pn -p "$port" --script ssl-enum-ciphers "$host" 2>&1 \
      | sed -n '/PORT/,/Service/p' | head -100
  fi
} | tee "$out"

# --- findings ---

# Cert expiry
not_after=$(grep "notAfter=" "$out" | head -1 | sed 's/notAfter=//')
if [ -n "$not_after" ]; then
  exp_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  days_left=$(( (exp_epoch - now_epoch) / 86400 ))
  if [ "$exp_epoch" -gt 0 ] && [ "$days_left" -lt 0 ]; then
    findings add "$host" --port "$port/tcp" --severity high \
      --title "TLS certificate expired" \
      --evidence "notAfter: $not_after (${days_left} days)" \
      --source openssl
  elif [ "$exp_epoch" -gt 0 ] && [ "$days_left" -lt 14 ]; then
    findings add "$host" --port "$port/tcp" --severity medium \
      --title "TLS certificate expires in ${days_left} days" \
      --evidence "notAfter: $not_after" \
      --source openssl
  fi
fi

# tlsx validation flags
if grep -qE '"self_signed":\s*true' "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "Self-signed TLS certificate" \
    --evidence "tlsx flagged self_signed" --source tlsx
fi
if grep -qE '"mismatched":\s*true' "$out"; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "TLS hostname mismatch" \
    --evidence "tlsx flagged mismatched" --source tlsx
fi
if grep -qE '"untrusted":\s*true' "$out"; then
  findings add "$host" --port "$port/tcp" --severity low \
    --title "Untrusted TLS certificate chain" \
    --evidence "tlsx flagged untrusted" --source tlsx
fi
if grep -qE '"wildcard_certificate":\s*true' "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "Wildcard TLS certificate in use" \
    --evidence "tlsx flagged wildcard_certificate=true" --source tlsx
fi
# Fallback: extract wildcard SANs from openssl X509 output (when tlsx is silent)
if grep -qE 'DNS:\*\.' "$out" && ! grep -qE '"wildcard_certificate":\s*true' "$out"; then
  wsan=$(grep -oE 'DNS:\*\.[a-zA-Z0-9.-]+' "$out" | head -3 | paste -sd',')
  findings add "$host" --port "$port/tcp" --severity info \
    --title "Wildcard TLS certificate (from openssl SAN)" \
    --evidence "wildcard SANs: $wsan" --source openssl
fi

# Weak protocols (anything older than TLSv1.2 is medium)
if grep -qE "^\|\s+(SSLv[23]|TLSv1\.[01]):" "$out"; then
  weak=$(grep -E "^\|\s+(SSLv[23]|TLSv1\.[01]):" "$out" | head -3)
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "Weak TLS protocol versions accepted" \
    --evidence "$weak" --source nmap
fi

# Weak ciphers (RC4/3DES/NULL/EXPORT/CBC graded poorly)
if grep -qE "(RC4|3DES|NULL|EXPORT).*\b(C|D|E|F)\b" "$out"; then
  weak=$(grep -E "(RC4|3DES|NULL|EXPORT|CBC).*\b(C|D|E|F)\b" "$out" | head -5)
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "Weak TLS cipher suites accepted" \
    --evidence "$weak" --source nmap
fi
