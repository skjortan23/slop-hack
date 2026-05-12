#!/bin/bash
# slop-status — peek at the current engagement's progress.
# Run inside the slop-hack container from any shell.
#
# Usage:
#   slop-status                      # one-shot snapshot
#   slop-status --tail <spec>        # tail the last 5 tool calls of one specialist
#   slop-status --watch              # refresh every 20s until all specialists done

set -u
: "${ENGAGEMENT_DIR:=/work/default}"

case "${1:-}" in
  --tail)
    spec="${2:?usage: slop-status --tail <spec>}"
    f="$ENGAGEMENT_DIR/specialists/${spec}.jsonl"
    [ -f "$f" ] || { echo "no such specialist trace: $f" >&2; exit 1; }
    jq -r 'select(.type=="assistant") | .message.content[]? |
      if .type=="tool_use" then "TOOL " + .name + ": " + ((.input.command // .input.prompt // (.input|tostring))[0:160])
      elif .type=="text" then "TEXT  " + (.text[0:200])
      else empty end' "$f" 2>/dev/null | tail -10
    exit 0 ;;
  --watch)
    while true; do
      clear
      "$0"
      echo
      echo "(refreshing every 20s; ^C to stop)"
      sleep 20
    done ;;
esac

# Default: one-shot snapshot

# Chain phase
echo "## Chain"
if [ -f "$ENGAGEMENT_DIR/engagement.log" ]; then
  grep -E '^=== \[' "$ENGAGEMENT_DIR/engagement.log" | tail -3
fi

# Specialist status
echo
echo "## Specialists"
SDIR="$ENGAGEMENT_DIR/specialists"
if [ -d "$SDIR" ]; then
  for spec in auth-bypass injection takeover-tls disclosure cve-correlation; do
    f="$SDIR/$spec.jsonl"
    if [ -f "$f" ]; then
      turns=$(grep -c '"type":"assistant"' "$f" 2>/dev/null)
      last_tool=$(jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | .name' "$f" 2>/dev/null | tail -1)
      last_cmd=$(jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use" and .name=="Bash") | .input.command' "$f" 2>/dev/null | tail -1 | head -c 100)
      if jq -e 'select(.type=="result")' "$f" >/dev/null 2>&1; then
        mark="✓ DONE"
      else
        mark="· running"
      fi
      printf "  %-15s %-10s turns=%-3d last=%s\n" "$spec" "$mark" "$turns" "${last_tool:-?}"
      [ -n "$last_cmd" ] && printf "    └─ %s\n" "$last_cmd"
    else
      printf "  %-15s not-started\n" "$spec"
    fi
  done
fi

# Findings summary
echo
echo "## Findings ($(wc -l < "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | tr -d ' ') total)"
if [ -s "$ENGAGEMENT_DIR/findings/findings.jsonl" ]; then
  jq -r '.severity' "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | sort | uniq -c
  echo
  echo "  critical/high titles:"
  jq -r 'select(.severity=="critical" or .severity=="high") | "  " + .severity + "\t" + (.cve // "-") + "\t" + .title' \
    "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | sort -u | head -10
fi
