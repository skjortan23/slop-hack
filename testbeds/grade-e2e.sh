#!/bin/bash
# End-to-end agent grade: spin up the cve-correlation specialist with the 3
# testbeds pre-populated as services. It should:
#   1. Run vuln-check per service → tier-graded findings (nuclei matched)
#   2. Dispatch exploit-agent in PARALLEL per CVE candidate
#   3. exploit-agent reads template + CVE info, crafts its own exploit,
#      captures multi-command output, logs critical with concrete proof
#
# Pass criterion: at least one finding with --source exploit-agent containing
# real exec proof per testbed.

set -u
ENGAGEMENT_ID="ENG-e2e-$(date +%s)"
WORK=/Users/skjortan/projects/slop-hack/work/"$ENGAGEMENT_ID"
mkdir -p "$WORK/specialists"

# Copy the prompt into work/ so it's readable from inside the container
cp /Users/skjortan/projects/slop-hack/testbeds/cve-correlation-prompt.txt \
   "$WORK/specialists/prompt.txt"

ENGAGEMENT_ID="$ENGAGEMENT_ID" ANTHROPIC_MODEL="qwen36" \
docker compose run --rm -T slop-hack bash <<'BASH'
set -u

echo "=== pre-populate services ==="
findings host-set host.docker.internal --hostname host.docker.internal
findings service-set host.docker.internal 18000/tcp --service http --product apache --version 2.4.49
findings service-set host.docker.internal 18001/tcp --service http --product struts --version 2.3
findings service-set host.docker.internal 18002/tcp --service http --product tomcat --version 8.5.19

echo
echo "=== invoking cve-correlation specialist (max-turns 60) ==="
PROMPT=$(cat $ENGAGEMENT_DIR/specialists/prompt.txt)
claude -p --output-format stream-json --verbose --max-turns 60 "$PROMPT" \
  > $ENGAGEMENT_DIR/specialists/cve-correlation.jsonl 2>&1

echo
echo "=== Task dispatch count (exploit-agent subagents launched) ==="
jq -r 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use" and .name=="Task") | .input.subagent_type' \
  $ENGAGEMENT_DIR/specialists/cve-correlation.jsonl 2>/dev/null | sort | uniq -c

echo
echo "=== Findings with exploit-agent source (concrete proof) ==="
jq -r 'select(.source == "exploit-agent" or (.source // "" | startswith("exploit-"))) | "\(.severity)\t\(.port)\t\(.cve // "-")\t\(.title)"' \
  $ENGAGEMENT_DIR/findings/findings.jsonl 2>/dev/null | sort -u

echo
echo "=== All critical/high findings ==="
jq -r 'select(.severity=="critical" or .severity=="high") | "\(.severity)\t\(.source)\t\(.cve // "-")\t\(.title)"' \
  $ENGAGEMENT_DIR/findings/findings.jsonl 2>/dev/null | sort -u

echo
echo "=== GRADE ==="
RES=0
for spec in 'apache:18000:CVE-2021-41773' 'struts:18001:CVE-2017-5638,CVE-2013-2251,CVE-2017-9791' 'tomcat:18002:CVE-2017-12615,CVE-2017-12617'; do
  prod=${spec%%:*}; rest=${spec#*:}; port=${rest%%:*}; cves=${rest##*:}
  hit=0
  for cve in $(echo "$cves" | tr ',' ' '); do
    jq -e --arg cve "$cve" --arg port "$port/tcp" \
       'select(.source | startswith("exploit-")) | select((.cve // "" | ascii_downcase) == ($cve | ascii_downcase)) | select(.port == $port)' \
       $ENGAGEMENT_DIR/findings/findings.jsonl >/dev/null 2>&1 && hit=1 && break
  done
  if [ "$hit" -eq 1 ]; then
    echo "  ✓ $prod :$port — exploit-agent confirmed"
  else
    echo "  ✗ $prod :$port — NO exploit-agent confirmation"
    RES=1
  fi
done
exit $RES
BASH
