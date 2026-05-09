#!/bin/bash
# Redis service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-6379}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-redis.txt"

{
  echo "=== INFO ==="
  redis-cli -h "$host" -p "$port" --no-auth-warning -t 5 INFO 2>&1 | head -60

  echo
  echo "=== CONFIG GET dir / dbfilename / requirepass ==="
  redis-cli -h "$host" -p "$port" --no-auth-warning -t 5 CONFIG GET dir 2>&1
  redis-cli -h "$host" -p "$port" --no-auth-warning -t 5 CONFIG GET dbfilename 2>&1
  redis-cli -h "$host" -p "$port" --no-auth-warning -t 5 CONFIG GET requirepass 2>&1

  echo
  echo "=== DBSIZE / sample KEYS ==="
  redis-cli -h "$host" -p "$port" --no-auth-warning -t 5 DBSIZE 2>&1
  redis-cli -h "$host" -p "$port" --no-auth-warning -t 5 --scan --pattern '*' 2>&1 | head -20
} | tee "$out"

# --- findings ---

# Unauth access — INFO returned data instead of NOAUTH
if grep -qE "^# Server" "$out"; then
  ver=$(grep -E "^redis_version:" "$out" | head -1 | cut -d: -f2 | tr -d '\r')
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "Unauthenticated Redis exposed" \
    --evidence "redis_version: $ver — INFO accessible without password" \
    --source redis-cli
fi

# requirepass empty (CONFIG GET returned empty value)
if grep -qE "^requirepass$|requirepass\s*$|\"requirepass\",\s*\"\"" "$out" \
   && ! grep -qi "NOAUTH\|denied" "$out"; then
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "Redis CONFIG GET requirepass returned empty" \
    --evidence "no password configured" --source redis-cli
fi

# Sample of accessible keys
keycount=$(grep -E "^[0-9]+$" "$out" | head -1)
if [ -n "$keycount" ] && [ "$keycount" -gt 0 ] 2>/dev/null && grep -qE "^# Server" "$out"; then
  findings add "$host" --port "$port/tcp" --severity high \
    --title "Redis data accessible (${keycount} keys)" \
    --evidence "$(redis-cli -h $host -p $port --scan --pattern '*' 2>/dev/null | head -10)" \
    --source redis-cli
fi
