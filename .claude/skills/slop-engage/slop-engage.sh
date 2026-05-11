#!/bin/bash
# slop-engage: deterministic chain + agent-driven follow-up.
#
# Phase 0 (deterministic): runs slop-engagement to populate findings store,
#         service inventory, endpoint inventory, openapi-imported endpoints.
#
# Phase 1 (agent):         drops claude in with that state and a goal-directed
#         prompt. The agent spends every turn on interpretation / deep-dives
#         / attack chaining instead of remembering to run subfinder.
#
# Usage:
#   slop-engage <root-or-host>
#   slop-engage <root> --goal "find auth bypasses and RCE"
#   slop-engage <root> --single-host
#   slop-engage <root> --no-agent      # just the deterministic chain
#   slop-engage <root> --max-turns 40  # agent budget after chain
#
# Defaults: goal = "find high/critical findings (RCE, auth bypass, exposed
# admin, source/secret disclosure, SSRF, SQLi). adapt approach to surface."

set -u
ROOT="${1:-}"
shift || true
if [ -z "$ROOT" ]; then
  cat <<EOF
usage: slop-engage <target> [--goal "..."] [--single-host] [--no-webapp] [--depth shallow|normal|deep] [--no-agent] [--max-turns N]
EOF
  exit 2
fi

GOAL=""
NO_AGENT=0
MAX_TURNS=40
CHAIN_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --goal)        GOAL="$2"; shift ;;
    --no-agent)    NO_AGENT=1 ;;
    --max-turns)   MAX_TURNS="$2"; shift ;;
    --single-host|--no-webapp) CHAIN_ARGS+=("$1") ;;
    --depth)       CHAIN_ARGS+=("$1" "$2"); shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ -z "$GOAL" ]; then
  GOAL="Find high/critical findings (RCE, auth bypass, exposed admin without auth, source/secret disclosure, SSRF, SQLi, IDOR, subdomain takeover). Adapt approach to the surface you see."
fi

: "${ENGAGEMENT_DIR:=/work/default}"

echo "=== slop-engage ==="
echo "target:     $ROOT"
echo "goal:       $GOAL"
echo "engagement: $ENGAGEMENT_DIR"
echo "agent:      $([ "$NO_AGENT" -eq 1 ] && echo "skipped" || echo "yes, max-turns=$MAX_TURNS")"
echo

# ── phase 0: deterministic coverage ──
echo "=== phase 0 — deterministic coverage ==="
slop-engagement "$ROOT" "${CHAIN_ARGS[@]}"
echo

if [ "$NO_AGENT" -eq 1 ]; then
  echo "=== --no-agent — done. ==="
  exit 0
fi

# ── phase 1: agent picks up ──
echo "=== phase 1 — agent picks up from chain output ==="

# Build a state summary for the agent prompt
FCOUNT=$(wc -l < "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null || echo 0)
HCOUNT=$(ls "$ENGAGEMENT_DIR/findings/hosts/" 2>/dev/null | wc -l | tr -d ' ')
ECOUNT=$(wc -l < "$ENGAGEMENT_DIR/webapp/endpoints.jsonl" 2>/dev/null || echo 0)

# Compose the goal-directed prompt
PROMPT="ENGAGEMENT STATE (populated by deterministic chain):
- hosts enumerated: $HCOUNT
- findings logged: $FCOUNT
- endpoints (from openapi/proxy): $ECOUNT
- engagement dir: $ENGAGEMENT_DIR

GOAL: $GOAL

State is already populated. DO NOT re-run passive-recon, dnsx, quickscan, openapi-import — they've ran. Start by reading what's there:
  findings list
  findings services --findings
  jq -r '.severity' \$ENGAGEMENT_DIR/findings/findings.jsonl | sort | uniq -c

Then do PENTESTER work:
- Look at the highest-severity findings first and decide if they chain to something worse
- Examine the per-host YAMLs in findings/hosts/ — anything unusual?
- For any web host with endpoints.jsonl, you can run webapp-fuzz, endpoint-authcheck if not done
- For any service with version, check vuln-search / vuln-check if not done
- Pivot to interesting threads. Don't follow a script.
- When you find something exploitable, log it via 'findings add' with strict severity rubric.

At the end:
- findings export-md > \$ENGAGEMENT_DIR/report.md (refresh report)
- output JSON summary: {goal_progress, new_findings, top_actionable, attack_chains_found}"

claude -p --output-format stream-json --verbose --max-turns "$MAX_TURNS" "$PROMPT" \
  > "$ENGAGEMENT_DIR/agent-followup-trace.jsonl"

# Show what the agent did
echo
echo "=== agent follow-up summary ==="
jq -r 'select(.type=="result") | "turns=\(.num_turns) duration=\(.duration_ms/1000)s denials=\(.permission_denials|length)"' \
  "$ENGAGEMENT_DIR/agent-followup-trace.jsonl"
echo
jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | .name' \
  "$ENGAGEMENT_DIR/agent-followup-trace.jsonl" 2>/dev/null | sort | uniq -c
echo
jq -r 'select(.type=="result") | .result // "<null — agent hit max-turns>"' \
  "$ENGAGEMENT_DIR/agent-followup-trace.jsonl" | head -50

echo
echo "=== final findings ==="
jq -r '.severity' "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | sort | uniq -c
echo
echo "report: $ENGAGEMENT_DIR/report.md"
echo "trace:  $ENGAGEMENT_DIR/agent-followup-trace.jsonl"
