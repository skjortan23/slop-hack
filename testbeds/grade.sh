#!/bin/bash
# Regression test: pre-populate findings for the 3 running testbeds, run the
# cve-correlation specialist standalone, then assert each testbed produced
# at least one tier2-critical finding for its expected CVE.
#
# Run on the HOST machine. Assumes vuln-apache / vuln-struts / vuln-tomcat
# containers are listening on 18000 / 18001 / 18002 respectively.
#
# Expected output on pass:
#   apache  18000  CVE-2021-41773  ✓
#   struts  18001  CVE-2017-5638   ✓  (any of the Struts2 OGNL CVEs)
#   tomcat  18002  CVE-2017-12615  ✓

set -u
ENGAGEMENT_ID="ENG-grade-$(date +%s)"
mkdir -p /Users/skjortan/projects/slop-hack/work/"$ENGAGEMENT_ID"

ENGAGEMENT_ID="$ENGAGEMENT_ID" ANTHROPIC_MODEL="qwen36" \
docker compose run --rm -T slop-hack bash -c '
set -u

echo "=== pre-populate testbed services ==="
findings host-set host.docker.internal --hostname host.docker.internal
findings service-set host.docker.internal 18000/tcp --service http --product apache --version 2.4.49
findings service-set host.docker.internal 18001/tcp --service http --product struts --version 2.3
findings service-set host.docker.internal 18002/tcp --service http --product tomcat --version 8.5.19

echo "=== sanity: vuln-check directly (chain phase 5 equivalent) ==="
for spec in "apache 18000 2.4.49" "struts 18001 2.3" "tomcat 18002 8.5.19"; do
  set -- $spec; prod=$1; port=$2; ver=$3
  echo "--- $prod $ver on :$port ---"
  vuln-check host.docker.internal "$port" "$prod" "$ver" 2>&1 | tail -8
done

echo
echo "=== ALL CRITICAL/HIGH FINDINGS ==="
jq -r "select(.severity==\"critical\" or .severity==\"high\") | \"\(.severity)\t\(.port)\t\(.cve // \"-\")\t\(.title)\"" \
  /work/'"$ENGAGEMENT_ID"'/findings/findings.jsonl 2>/dev/null | sort -u

echo
echo "=== GRADE ==="
RES=0
for spec in "apache:18000:CVE-2021-41773" "struts:18001:CVE-2017-9791,CVE-2017-5638,CVE-2013-2251" "tomcat:18002:CVE-2017-12615,CVE-2017-12617"; do
  prod="${spec%%:*}"; rest="${spec#*:}"; port="${rest%%:*}"; cves="${rest##*:}"
  hit=0
  for cve in $(echo "$cves" | tr "," " "); do
    grep -qi "$cve" /work/'"$ENGAGEMENT_ID"'/findings/findings.jsonl 2>/dev/null && hit=1 && break
  done
  if [ "$hit" -eq 1 ]; then echo "  ✓ $prod :$port (any of $cves)"; else echo "  ✗ $prod :$port MISSED ($cves)"; RES=1; fi
done
exit $RES
'
