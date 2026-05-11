#!/usr/bin/env python3
"""net-health: detect rate-limiting / port-scan suppression before running
an engagement.

Probes three independent signals against known-good baseline targets:
1. DNS resolution (dig)
2. TCP CONNECT via curl
3. SYN-scan via naabu

Compares results to classify network state:
- healthy            — all three signals work as expected
- port-scan-suppressed — curl works, naabu finds 0 — our SYN packets are being dropped
- egress-broken      — even DNS or basic TCP fails — nothing reaches outside
- partial-degraded   — mixed signals; flag and proceed with caution

Usage:
    net-health                     # default baseline checks
    net-health --target <host>     # also probe a specific target to compare
    net-health --json              # machine-readable

Exit codes:
    0 — healthy
    1 — port-scan suppressed (HTTP works, raw scan doesn't — use HTTP-only mode)
    2 — egress broken (nothing reaches outside)
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# Known-up baseline targets — pick services with very high uptime, multiple
# protocols, and well-known open ports
BASELINE = [
    {"host": "1.1.1.1",          "port": 443, "desc": "Cloudflare DNS"},
    {"host": "8.8.8.8",          "port": 443, "desc": "Google DNS"},
    {"host": "scanme.nmap.org",  "port": 22,  "desc": "Nmap-sanctioned scan target"},
]


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def dns_works(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def curl_check(host: str, port: int, timeout: int = 5) -> dict:
    """Return {ok: bool, status: int, ms: int}."""
    t0 = time.time()
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    rc, out, _ = run(
        ["curl", "-sk", "-o", "/dev/null",
         "-w", "%{http_code}",
         "-m", str(timeout), "--connect-timeout", str(timeout),
         url],
        timeout=timeout + 2,
    )
    ms = int((time.time() - t0) * 1000)
    try:
        status = int(out)
    except Exception:
        status = 0
    return {"ok": status != 0, "status": status, "ms": ms}


def naabu_check(host: str, port: int, timeout: int = 15) -> dict:
    """Return {ok: bool, hits: int}."""
    rc, out, _ = run(
        ["naabu", "-host", host, "-p", str(port),
         "-rate", "100", "-c", "10", "-silent"],
        timeout=timeout,
    )
    hits = sum(1 for line in out.splitlines() if line.strip())
    return {"ok": hits > 0, "hits": hits}


def probe(host: str, port: int) -> dict:
    return {
        "host": host,
        "port": port,
        "dns": dns_works(host),
        "curl": curl_check(host, port),
        "naabu": naabu_check(host, port),
    }


def classify(results: list[dict]) -> str:
    any_dns = any(r["dns"] for r in results)
    any_curl_ok = any(r["curl"]["ok"] for r in results)
    any_naabu_ok = any(r["naabu"]["ok"] for r in results)

    if not any_dns and not any_curl_ok:
        return "egress-broken"
    if any_curl_ok and not any_naabu_ok:
        return "port-scan-suppressed"
    if any_curl_ok and any_naabu_ok:
        # Both working — healthy. But check if some specific ones failed
        any_naabu_miss = any(not r["naabu"]["ok"] for r in results)
        if any_naabu_miss:
            return "partial-degraded"
        return "healthy"
    return "partial-degraded"


def main() -> int:
    ap = argparse.ArgumentParser(prog="net-health")
    ap.add_argument("--target", help="also probe a specific target (port 443)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    targets = list(BASELINE)
    if args.target:
        targets.append({"host": args.target, "port": 443, "desc": "user target"})

    print("probing baseline + targets...", file=sys.stderr)
    results = []
    for t in targets:
        r = probe(t["host"], t["port"])
        r["desc"] = t["desc"]
        results.append(r)
        sym = "✓" if (r["curl"]["ok"] and r["naabu"]["ok"]) else "✗"
        print(f"  {sym} {t['host']}:{t['port']} dns={r['dns']} "
              f"curl={r['curl']['status']}({r['curl']['ms']}ms) "
              f"naabu={r['naabu']['hits']}",
              file=sys.stderr)

    state = classify(results)

    summary = {
        "state": state,
        "results": results,
        "recommendation": {
            "healthy": "proceed normally",
            "port-scan-suppressed": "naabu/SYN scan being dropped — use HTTP-only mode (httpx/curl). Findings will be web-layer only.",
            "egress-broken": "nothing reaches outside — fix network before running engagement",
            "partial-degraded": "some baselines failed but not all — proceed with reduced expectations on port scanning",
        }[state],
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"\n=== net-health: {state.upper()} ===")
        print(f"recommendation: {summary['recommendation']}")

    return {
        "healthy": 0,
        "partial-degraded": 0,
        "port-scan-suppressed": 1,
        "egress-broken": 2,
    }[state]


if __name__ == "__main__":
    sys.exit(main())
