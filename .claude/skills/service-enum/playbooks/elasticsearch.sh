#!/bin/bash
# Elasticsearch service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-9200}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-elasticsearch.txt"

base="http://${host}:${port}"

{
  echo "=== GET / ==="
  curl -sk -m 8 "${base}/" | head -40

  echo
  echo "=== GET /_cluster/health ==="
  curl -sk -m 8 "${base}/_cluster/health" | head -30

  echo
  echo "=== GET /_cat/indices?v ==="
  curl -sk -m 10 "${base}/_cat/indices?v" | head -40
} | tee "$out"

# --- findings ---

# Unauth Elasticsearch
if grep -qE '"cluster_name"\s*:|"version"\s*:\s*\{' "$out"; then
  ver=$(grep -oE '"number"\s*:\s*"[^"]+"' "$out" | head -1 | sed 's/.*"\(.*\)".*/\1/')
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "Unauthenticated Elasticsearch exposed" \
    --evidence "version: ${ver:-unknown}" \
    --source curl
fi

# Indices listed (sensitive data risk)
if grep -qE "^(green|yellow|red)\s+(open|close)" "$out"; then
  count=$(grep -cE "^(green|yellow|red)\s+(open|close)" "$out")
  sample=$(grep -E "^(green|yellow|red)" "$out" | head -10)
  findings add "$host" --port "$port/tcp" --severity high \
    --title "Elasticsearch indices enumerable (${count})" \
    --evidence "$sample" \
    --source curl
fi
