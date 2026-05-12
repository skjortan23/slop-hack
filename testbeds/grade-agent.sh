#!/bin/bash
# Agent-path regression: pre-populate services for the 3 testbeds, run the
# cve-correlation specialist (claude -p with the updated prompt), then check
# that it auto-invoked vuln-check per service and the same Tier 2 findings
# landed.

set -u
ENGAGEMENT_ID="ENG-grade-agent-$(date +%s)"
mkdir -p /Users/skjortan/projects/slop-hack/work/"$ENGAGEMENT_ID"/specialists

# A trimmed copy of the cve-correlation prompt from slop-engage.sh — kept
# in sync manually for now (single source of truth would be a heredoc shared
# between the two scripts; small enough that we accept the duplication).
PROMPT='CONTRACT — read this first, every turn:
You have 80 turns. After EACH probe, log the result with `findings add`
BEFORE moving to the next candidate. Examples:
  Confirmed exploit  → findings add <host> --severity high --title "..." \
                                            --evidence "..." --source <class>-confirmed
  Dead-end           → findings add <host> --severity info --title "..." \
                                            --evidence "..." --source <class>-deadend
Untested = useless. NEVER silently skip a candidate.

SPECIALIST GOAL: For every service in findings, run vuln-check to correlate
against CVE templates AND prove RCE / file disclosure. vuln-check grades
severity automatically by tier:
  tier2 critical = in-band exec/disclosure (uid=, /etc/passwd content)
  tier1 high     = OOB callback via interactsh
  tier0 medium   = version banner match only

Process:
1. findings services --json | jq -c .
2. For each (host, port, product, version):
     vuln-check <host> <port> <product> <version>
3. Read the new findings and write a brief report:
     jq -c "select(.source | startswith(\"nuclei-cve-tier\"))" \
       $ENGAGEMENT_DIR/findings/findings.jsonl
4. cat > $ENGAGEMENT_DIR/specialists/cve-correlation-report.md ...

End when all services have been checked.'

ENGAGEMENT_ID="$ENGAGEMENT_ID" ANTHROPIC_MODEL="qwen36" \
docker compose run --rm -T slop-hack bash -c "
set -u
echo '=== pre-populate services ==='
findings host-set host.docker.internal --hostname host.docker.internal
findings service-set host.docker.internal 18000/tcp --service http --product apache --version 2.4.49
findings service-set host.docker.internal 18001/tcp --service http --product struts --version 2.3
findings service-set host.docker.internal 18002/tcp --service http --product tomcat --version 8.5.19

echo '=== invoking cve-correlation specialist (max-turns 40) ==='
claude -p --output-format stream-json --verbose --max-turns 40 '$PROMPT' \
  > /work/$ENGAGEMENT_ID/specialists/cve-correlation.jsonl 2>&1

echo
echo '=== assistant tool calls (last 10 commands) ==='
jq -r 'select(.type==\"assistant\") | .message.content[]? | select(.type==\"tool_use\" and .name==\"Bash\") | .input.command' \
  /work/$ENGAGEMENT_ID/specialists/cve-correlation.jsonl 2>/dev/null | tail -10

echo
echo '=== Critical/high findings landed ==='
jq -r 'select(.severity==\"critical\" or .severity==\"high\") | \"\(.severity)\t\(.port)\t\(.cve // \"-\")\t\(.title)\"' \
  /work/$ENGAGEMENT_ID/findings/findings.jsonl 2>/dev/null | sort -u

echo
echo '=== GRADE ==='
RES=0
for spec in 'apache:18000:CVE-2021-41773' 'struts:18001:CVE-2017-9791,CVE-2017-5638,CVE-2013-2251' 'tomcat:18002:CVE-2017-12615,CVE-2017-12617'; do
  prod=\${spec%%:*}; rest=\${spec#*:}; port=\${rest%%:*}; cves=\${rest##*:}
  hit=0
  for cve in \$(echo \"\$cves\" | tr ',' ' '); do
    grep -qi \"\$cve\" /work/$ENGAGEMENT_ID/findings/findings.jsonl 2>/dev/null && hit=1 && break
  done
  if [ \"\$hit\" -eq 1 ]; then echo \"  ✓ \$prod :\$port\"; else echo \"  ✗ \$prod :\$port MISSED\"; RES=1; fi
done
exit \$RES
"
