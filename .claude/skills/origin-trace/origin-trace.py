#!/usr/bin/env python3
"""origin-trace: try to discover the real origin IP behind a CDN/WAF.

Free-only techniques (no API keys required):
1. Subdomain enumeration (subfinder + crt.sh) — find any sub with non-CDN IP
2. Common origin-revealing subdomain probe (direct./origin./cpanel./mail./...)
3. MX record lookup — mail servers rarely behind CDN
4. cdncheck filter — narrow candidates to non-CDN IPs
5. Host-header bypass — send `Host: target.com` to each candidate IP, compare
   response hash to target's baseline. Match = confirmed origin.

Usage:
    origin-trace <hostname>
    origin-trace <hostname> --no-bruteforce       (skip common-sub probe)
    origin-trace <hostname> --json                (structured output)

Limitations:
- All passive / free-tier techniques. Won't find an origin that's well-hidden
  (no public subdomain bypass, mail elsewhere, no historical DNS leaks).
- For higher-fidelity origin discovery, add Shodan / Censys / SecurityTrails
  API keys and use their cert-hash search.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
OUT_DIR = ENG_DIR / "recon" / "origin-trace"

COMMON_ORIGIN_SUBS = [
    # Direct/origin patterns
    "direct", "origin", "real", "backend", "origin-www", "www-origin",
    # Environments
    "dev", "staging", "stage", "test", "qa", "uat", "alpha", "beta",
    "preprod", "preview",
    # Admin/internal
    "admin", "internal", "private", "vpn", "ssh", "shell", "manage",
    # File / FTP
    "ftp", "sftp", "files", "static", "storage", "uploads",
    # Mail (usually not proxied)
    "mail", "smtp", "imap", "pop", "webmail", "mx", "mx1", "mx2",
    # Hosting panels
    "cpanel", "whm", "plesk", "webmin", "control", "panel",
    # Legacy
    "old", "legacy", "v1", "v2", "old-www", "www2",
    # Monitoring / dev tools
    "monitor", "metrics", "stats", "status", "munin", "grafana",
    "ci", "build", "deploy", "jenkins", "gitlab", "git", "registry",
]


def run(cmd, *, input_text=None, timeout=30):
    try:
        r = subprocess.run(cmd, input=input_text, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def resolve(host):
    """Return list of A-record IPs for host via dnsx."""
    rc, out, _ = run(["dnsx", "-silent", "-a", "-resp"], input_text=host, timeout=8)
    ips = []
    for line in out.splitlines():
        m = re.search(r"\[A\]\s*\[?(\d+\.\d+\.\d+\.\d+)\]?", line)
        if m:
            ips.append(m.group(1))
    return ips


def cdn_detect(ip):
    """Return CDN/WAF/cloud name for an IP, or empty string."""
    rc, out, _ = run(["cdncheck", "-resp", "-jsonl", "-silent"],
                     input_text=ip, timeout=8)
    for line in out.splitlines():
        try:
            r = json.loads(line)
            for k in ("cdn_name", "waf_name", "cloud_name"):
                if r.get(k):
                    return r[k]
        except Exception:
            continue
    return ""


def subfinder_quick(host):
    rc, out, _ = run(["subfinder", "-d", host, "-silent", "-timeout", "10"],
                     timeout=60)
    return [l.strip().lower() for l in out.splitlines() if l.strip()]


def crtsh_query(host):
    rc, out, _ = run(["curl", "-sf", "-m", "30",
                      f"https://crt.sh/?q=%.{host}&output=json"],
                     timeout=35)
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    names = set()
    for entry in data:
        for part in (entry.get("name_value") or "").split("\n"):
            p = part.strip().lower()
            if p and "." in p and not p.startswith("*"):
                names.add(p)
    return sorted(names)


def mx_records(host):
    rc, out, _ = run(["dig", "+short", host, "MX"], timeout=10)
    servers = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[0].isdigit():
            servers.append({"priority": int(parts[0]),
                            "host": parts[1].rstrip(".")})
    return servers


def fetch_baseline(target):
    """GET https://target/ — return (sha256, content_length)."""
    rc, out, _ = run(["curl", "-sk", "-m", "10", f"https://{target}/"], timeout=12)
    return (
        hashlib.sha256(out.encode()).hexdigest(),
        len(out),
        out[:200],
    )


def host_header_bypass(candidate_ip, target_host, baseline_hash, baseline_len):
    """Send Host: target to candidate_ip; compare body hash + length."""
    for proto in ("https", "http"):
        rc, out, _ = run(
            ["curl", "-sk", "-o", "-",
             "-H", f"Host: {target_host}",
             "-m", "10", f"{proto}://{candidate_ip}/"],
            timeout=12,
        )
        if not out:
            continue
        body_hash = hashlib.sha256(out.encode()).hexdigest()
        body_len = len(out)
        if body_hash == baseline_hash:
            return True, proto, "exact body match"
        # Even partial similarity (length within 10%) is suspicious
        if baseline_len > 0 and abs(body_len - baseline_len) / baseline_len < 0.1 and body_len > 100:
            return True, proto, f"length match ({body_len} vs {baseline_len})"
    return False, "", ""


def main() -> int:
    ap = argparse.ArgumentParser(prog="origin-trace")
    ap.add_argument("host")
    ap.add_argument("--no-bruteforce", action="store_true",
                    help="skip common-origin-subdomain brute force")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    target = args.host.strip().lower()
    log = lambda *a: print(*a, file=sys.stderr)

    result = {
        "target": target,
        "techniques_used": [],
        "candidate_origin_ips": [],
    }

    # Baseline
    log(f"[1/5] Resolving {target}...")
    target_ips = resolve(target)
    cdn_name = ""
    if target_ips:
        cdn_name = cdn_detect(target_ips[0])
    result["target_ips"] = target_ips
    result["cdn"] = cdn_name

    if not target_ips:
        log("  no DNS resolution — abort")
        print(json.dumps(result, indent=2) if args.json else f"FAIL: {target} did not resolve")
        return 1

    log(f"  → {target_ips}, cdn={cdn_name or 'NONE'}")

    # Subdomain enumeration
    log("[2/5] subfinder + crt.sh...")
    subs = set(subfinder_quick(target))
    crtsh = crtsh_query(target)
    subs.update(crtsh)
    log(f"  → {len(subs)} subdomains found ({len(crtsh)} from crt.sh)")
    result["techniques_used"].append("subfinder")
    if crtsh:
        result["techniques_used"].append("crt.sh")

    # Common origin subdomain brute
    if not args.no_bruteforce:
        log(f"[3/5] Probing {len(COMMON_ORIGIN_SUBS)} common origin subs...")
        for prefix in COMMON_ORIGIN_SUBS:
            subs.add(f"{prefix}.{target}")
        result["techniques_used"].append("common-sub-bruteforce")
    else:
        log("[3/5] Skipping common-sub bruteforce (--no-bruteforce)")

    # Resolve all subs, classify
    log(f"[4/5] Resolving {len(subs)} candidates + cdncheck...")
    non_cdn = []
    cdn_ips = set()
    for sub in sorted(subs):
        ips = resolve(sub)
        for ip in ips:
            if ip in cdn_ips:
                continue
            cn = cdn_detect(ip)
            if cn:
                cdn_ips.add(ip)
            else:
                non_cdn.append({"sub": sub, "ip": ip})

    result["non_cdn_subs"] = non_cdn
    log(f"  → {len(non_cdn)} subs resolve to non-CDN IPs")

    # MX records (and resolve their hosts)
    log("[5/5] MX records + host-header bypass...")
    mx = mx_records(target)
    result["mx_records"] = mx
    for m in mx:
        ips = resolve(m["host"])
        for ip in ips:
            if not cdn_detect(ip):
                if not any(c["ip"] == ip for c in non_cdn):
                    non_cdn.append({"sub": m["host"], "ip": ip, "via": "MX"})
    result["techniques_used"].append("mx-lookup")

    # Host-header bypass against non-CDN candidates
    baseline_hash, baseline_len, baseline_snippet = fetch_baseline(target)
    result["target_baseline"] = {
        "sha256_prefix": baseline_hash[:16],
        "length": baseline_len,
    }
    result["techniques_used"].append("host-header-bypass")

    candidates = non_cdn[:20]  # cap to keep runtime reasonable
    for cand in candidates:
        confirmed, proto, evidence = host_header_bypass(
            cand["ip"], target, baseline_hash, baseline_len
        )
        if confirmed:
            result["candidate_origin_ips"].append({
                "ip": cand["ip"],
                "via_subdomain": cand["sub"],
                "proto": proto,
                "evidence": evidence,
            })

    # Output
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n=== origin-trace: {target} ===")
        print(f"Public IPs: {target_ips}")
        print(f"CDN detected: {cdn_name or 'NONE'}")
        print(f"Subdomains examined: {len(subs)} (crt.sh: {len(crtsh)}, brute: {len(COMMON_ORIGIN_SUBS) if not args.no_bruteforce else 0})")
        print(f"Subdomains with non-CDN IPs: {len(non_cdn)}")
        for n in non_cdn[:15]:
            via = f" (via {n['via']})" if n.get("via") else ""
            print(f"  {n['sub']} → {n['ip']}{via}")
        if mx:
            print(f"\nMX records:")
            for m in mx:
                print(f"  {m['priority']} {m['host']}")
        if result["candidate_origin_ips"]:
            print("\n*** CANDIDATE ORIGIN IPs (Host-header bypass succeeded):")
            for c in result["candidate_origin_ips"]:
                print(f"  ★ {c['ip']} via {c['via_subdomain']} — {c['evidence']}")
        else:
            print("\nNo origin candidates confirmed via host-header bypass.")
            print("(Origin is well-hidden, OR needs API-keyed sources: Shodan/Censys/SecurityTrails)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
