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
MODE="specialists"   # specialists (default, parallel) | single (one general agent)
CHAIN_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --goal)        GOAL="$2"; shift ;;
    --no-agent)    NO_AGENT=1 ;;
    --max-turns)   MAX_TURNS="$2"; shift ;;
    --single)      MODE="single" ;;
    --specialists) MODE="specialists" ;;
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
echo "=== phase 1 — agent picks up from chain output (mode=$MODE) ==="

# Build a state summary used by all agent prompts
FCOUNT=$(wc -l < "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null || echo 0)
HCOUNT=$(ls "$ENGAGEMENT_DIR/findings/hosts/" 2>/dev/null | wc -l | tr -d ' ')
ECOUNT=$(wc -l < "$ENGAGEMENT_DIR/webapp/endpoints.jsonl" 2>/dev/null || echo 0)

STATE_HEADER="ENGAGEMENT STATE (populated by deterministic chain):
- hosts enumerated: $HCOUNT
- findings logged so far: $FCOUNT
- endpoints (from openapi/proxy): $ECOUNT
- engagement dir: $ENGAGEMENT_DIR

State is already populated. DO NOT re-run passive-recon, dnsx, quickscan,
openapi-import — they've ran. Start by reading the existing state:
  findings list
  findings services --findings
  jq -r '.severity' \$ENGAGEMENT_DIR/findings/findings.jsonl | sort | uniq -c

When you find something exploitable, log it via 'findings add' with strict
severity rubric. Do not duplicate findings already in the store."

run_agent() {
  local name="$1" trace_file="$2" prompt="$3"
  echo "  · launching specialist: $name"
  claude -p --output-format stream-json --verbose --max-turns "$MAX_TURNS" "$prompt" \
    > "$trace_file" 2>&1 &
}

if [ "$MODE" = "single" ]; then
  PROMPT="$STATE_HEADER

GOAL (from operator): $GOAL

Adapt approach to surface. Look at the highest-severity findings first,
decide if they chain to something worse. Examine per-host YAMLs in
findings/hosts/. Pivot to interesting threads. Don't follow a script.

At the end:
- findings export-md > \$ENGAGEMENT_DIR/report.md
- output JSON summary: {goal_progress, new_findings, top_actionable}"

  run_agent "single" "$ENGAGEMENT_DIR/agent-followup-trace.jsonl" "$PROMPT"
  wait
else
  # specialists mode — N parallel goal-focused agents
  SPECIALISTS_DIR="$ENGAGEMENT_DIR/specialists"
  mkdir -p "$SPECIALISTS_DIR"

  run_agent "auth-bypass" "$SPECIALISTS_DIR/auth-bypass.jsonl" "$STATE_HEADER

SPECIALIST GOAL: Find auth bypass and access control gaps.
- For each web host with endpoints.jsonl, run endpoint-authcheck if not yet done
- For every endpoint that returns 200 / 200-with-data / 422, evaluate the auth boundary — is this expected? if not, log medium/high
- Check for IDOR by varying numeric IDs in URL paths (try /users/1, /users/2 on auth'd endpoints with no credentials)
- Check for method-swap (GET → POST/PUT/DELETE) on documented routes that have auth on GET
- Webhooks especially: GitHub webhooks, etc, that should validate signatures

Strict rubric: log high only if a specific protected resource returns
actual data unauthenticated.

End with: findings export-md > \$ENGAGEMENT_DIR/specialists/auth-bypass-report.md
JSON: {findings_added, top_findings}"

  run_agent "injection" "$SPECIALISTS_DIR/injection.jsonl" "$STATE_HEADER

SPECIALIST GOAL: Find injection candidates (SQLi, XSS, SSTI, command injection, SSRF).
- For each web host with endpoints.jsonl, run webapp-fuzz (nuclei DAST)
- For any DAST candidate, run webapp-confirm to escalate or dismiss
- Look at all endpoints with query/body params — those are injection surface
- Try canary payloads on path parameters too: /api/foo/{{7*7}}, /api/foo/<script>...
- For webhook + scan endpoints, attempt SSRF via URL-shaped input
- Document confirmed cases at high; candidates at medium

End with: findings export-md > \$ENGAGEMENT_DIR/specialists/injection-report.md
JSON: {findings_added, confirmed_count, candidate_count}"

  run_agent "takeover-tls" "$SPECIALISTS_DIR/takeover-tls.jsonl" "$STATE_HEADER

SPECIALIST GOAL: Find subdomain takeovers + TLS/crypto issues.
- Look at every host yaml in findings/hosts/ for dangling-CNAME notes (from slop-engagement phase 2)
- For each: dig the CNAME target. If target doesn't resolve / NXDOMAIN → check if domain is registrable via whois.codelight.ai-style probe. If registrable → escalate to high.
- For each TLS cert observed in scans, check: expired, CN/SAN mismatch, weak algorithms, wildcard scope, CT log curiosities
- For each host, check redirect chains for open redirect on Location header
- Check cert transparency: any unexpected certs issued for the org's domains?

End with: findings export-md > \$ENGAGEMENT_DIR/specialists/takeover-tls-report.md
JSON: {findings_added, takeover_candidates, tls_issues}"

  run_agent "disclosure" "$SPECIALISTS_DIR/disclosure.jsonl" "$STATE_HEADER

SPECIALIST GOAL: Find source / secret / sensitive disclosure.
- For every web host: curl /.git/HEAD, /.env, /.env.local, /.env.production, /backup, /backup.sql, /database.sql, /config.php.bak, /id_rsa, /.DS_Store, /package.json, /Dockerfile, /docker-compose.yml
- Pull JS bundles found in static/assets — grep for: API keys, AWS keys, github tokens, Stripe keys, Sentry DSNs, internal hostnames, debug flags
- Look at /openapi.json for paths suggesting internal/debug endpoints
- Check robots.txt + sitemap.xml + /.well-known/ for revealed paths
- For any 200 response, scan first 4kb for: 'password', 'secret', 'token', 'apiKey', 'BEGIN PRIVATE KEY'

Found secrets → critical (real secret found) or high (path that should be private)
Information disclosure (versions, internal IPs) → low

End with: findings export-md > \$ENGAGEMENT_DIR/specialists/disclosure-report.md
JSON: {findings_added, secrets_found, version_disclosures}"

  run_agent "cve-correlation" "$SPECIALISTS_DIR/cve-correlation.jsonl" "$STATE_HEADER

SPECIALIST GOAL: Match detected service versions to known CVEs and produce confirmed-version findings.
- Get the services inventory: findings services --json
- For each (host, port, product, version) with version != null, run: vuln-check <host> <port> <product> <version>
- Read the resulting findings — for each CVE template hit, verify the version actually falls in the affected range. nuclei templates have version matchers but be skeptical of substring matches.
- For each searchsploit hit, verify the title actually applies to the running version + platform. Drop false positives.
- Promote real version-matched CVEs to medium or high based on impact

End with: findings export-md > \$ENGAGEMENT_DIR/specialists/cve-correlation-report.md
JSON: {findings_added, cves_confirmed, false_positives_dropped}"

  echo
  echo "=== 5 specialists running in parallel — waiting for all ==="
  wait
  echo
  echo "=== specialists done ==="
fi

# Show what the agents did
echo
for f in "$ENGAGEMENT_DIR/agent-followup-trace.jsonl" "$ENGAGEMENT_DIR"/specialists/*.jsonl; do
  [ -f "$f" ] || continue
  name=$(basename "$f" .jsonl)
  turns=$(jq -r 'select(.type=="result") | .num_turns' "$f" 2>/dev/null | head -1)
  dur=$(jq -r 'select(.type=="result") | .duration_ms/1000' "$f" 2>/dev/null | head -1)
  tools=$(jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | .name' "$f" 2>/dev/null | wc -l | tr -d ' ')
  printf "  %-20s turns=%-4s duration=%-7s tools=%s\n" "$name" "${turns:-?}" "${dur:-?}s" "$tools"
done

echo
echo "=== final findings ==="
jq -r '.severity' "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | sort | uniq -c
echo
echo "report: $ENGAGEMENT_DIR/report.md"
echo "trace:  $ENGAGEMENT_DIR/agent-followup-trace.jsonl"
