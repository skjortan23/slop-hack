#!/bin/bash
# SSH service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-22}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-ssh.txt"

{
  echo "=== banner ==="
  timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port; head -1 <&3; exec 3<&-" 2>/dev/null

  echo
  echo "=== ssh-audit ==="
  ssh-audit -p "$port" "$host" 2>&1 | head -120

  echo
  echo "=== auth methods (probe with bogus user) ==="
  ssh -p "$port" -v -o BatchMode=yes -o StrictHostKeyChecking=no \
      -o ConnectTimeout=5 -o NumberOfPasswordPrompts=0 \
      noone-not-a-real-user@"$host" 2>&1 \
    | grep -iE "auth|offering|received|publickey|password|keyboard|gssapi" \
    | head -20
} | tee "$out"

# --- findings ---

banner=$(head -3 "$out" | grep -i "^SSH-" | head -1)
if [ -n "$banner" ]; then
  # Banner version disclosure
  findings add "$host" --port "$port/tcp" --severity info \
    --title "SSH banner discloses version" \
    --evidence "$banner" \
    --source service-enum
fi

# ssh-audit warnings (kex/encryption/mac/host-key)
warns=$(grep -E "\(warn\)|\(fail\)" "$out" | head -10)
if [ -n "$warns" ]; then
  findings add "$host" --port "$port/tcp" --severity medium \
    --title "Weak SSH algorithms (kex/cipher/mac/host-key)" \
    --evidence "$warns" \
    --source ssh-audit
fi

# Password auth allowed
if grep -qiE "password|keyboard-interactive" "$out"; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "SSH password / keyboard-interactive authentication enabled" \
    --evidence "$(grep -iE "auth|offering" "$out" | head -3)" \
    --source service-enum
fi

# Old OpenSSH (very rough)
old=$(echo "$banner" | grep -oE "OpenSSH_[0-9]+\.[0-9]+" | head -1)
if [ -n "$old" ]; then
  major=$(echo "$old" | grep -oE "[0-9]+\.[0-9]+" | head -1)
  awk -v v="$major" 'BEGIN{exit (v<7.4)}' && \
    findings add "$host" --port "$port/tcp" --severity medium \
      --title "Outdated OpenSSH version (<7.4)" \
      --evidence "$banner" \
      --source service-enum
fi
