#!/usr/bin/env python3
"""vuln-check: run local CVE checks for a detected product+version against
a specific host+port and log findings via the findings CLI.

Usage:
    vuln-check <host> <port> <product> [version]

Example:
    vuln-check 0x08.sec-t.org 443 wordpress 6.9.4
    vuln-check api.example.com 443 nginx 1.24.0

Workflow:
1. Find nuclei CVE templates matching the product (grep nuclei-templates/http/cves/)
2. Run candidate templates against the target
3. Run searchsploit <product> <version> for public PoCs
4. Log findings via `findings add` with proper severity, --cve, and source

Designed for host-recon subagents to call after detecting a service version,
so the per-host YAML accumulates CVE findings tied to the right port.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

CVES_DIRS = [
    Path("/root/nuclei-templates/http/cves"),
    Path("/root/nuclei-templates/http/vulnerabilities"),
]


def find_templates(product: str, limit: int = 30) -> list[str]:
    """grep -ril for the product across nuclei CVE templates dirs."""
    found = []
    for d in CVES_DIRS:
        if not d.exists():
            continue
        try:
            out = subprocess.run(
                ["grep", "-ril", "--include=*.yaml", product, str(d)],
                capture_output=True, text=True, timeout=30,
            )
            for line in out.stdout.splitlines():
                if line and line not in found:
                    found.append(line)
                if len(found) >= limit:
                    return found
        except Exception:
            continue
    return found


def run_nuclei(host: str, port: int, templates: list[str]) -> list[dict]:
    """Run nuclei against the selected templates, return parsed JSON hits."""
    if not templates:
        return []
    target = f"https://{host}:{port}" if port in (443, 8443) else f"http://{host}:{port}"
    out_file = Path(f"/tmp/vc-nuclei-{os.getpid()}.json")
    try:
        cmd = (
            ["nuclei", "-target", target, "-t"] + templates +
            ["-json-export", str(out_file),
             "-silent", "-timeout", "8", "-rate-limit", "30"]
        )
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if out_file.exists() and out_file.stat().st_size > 2:
            with open(out_file) as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        print(f"  nuclei error: {e}", file=sys.stderr)
    finally:
        try:
            out_file.unlink()
        except Exception:
            pass
    return []


def run_searchsploit(product: str, version: str = "") -> list[dict]:
    cmd = ["searchsploit", product]
    if version:
        cmd.append(version)
    cmd += ["--json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(out.stdout) if out.stdout else {}
        return (data.get("RESULTS_EXPLOIT") or [])[:10]
    except Exception:
        return []


def log_finding(host, port, *, severity, title, evidence, source, cve=None):
    args = [
        "findings", "add", host,
        "--port", f"{port}/tcp",
        "--severity", severity,
        "--title", title,
        "--evidence", evidence[:512],
        "--source", source,
    ]
    if cve:
        args += ["--cve", cve]
    try:
        subprocess.run(args, check=False, capture_output=True, timeout=10)
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(prog="vuln-check")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("product")
    ap.add_argument("version", nargs="?", default="")
    args = ap.parse_args()

    templates = find_templates(args.product)
    nuclei_hits = run_nuclei(args.host, args.port, templates)
    for hit in nuclei_hits:
        info = hit.get("info") or {}
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        cve = cves[0] if cves else None

        log_finding(
            args.host, args.port,
            severity=info.get("severity", "info"),
            title=info.get("name") or hit.get("template-id", "nuclei finding"),
            evidence=f"matched at {hit.get('matched-at', '?')} via template {hit.get('template-id', '?')}",
            source="nuclei-cves",
            cve=cve,
        )

    ss_hits = run_searchsploit(args.product, args.version)
    # Filter searchsploit hits — drop low-confidence substring matches.
    # A real hit should have:
    # 1. Product name appears in the title (case-insensitive, word boundary)
    # 2. If version was passed, the title should reference a relevant version
    #    range (a "< X.Y" or "X.Y" prefix that could plausibly include ours)
    # 3. Path should not be obviously another product's directory
    #    (e.g. "windows/local" hits when we asked for Linux Apache)
    product_lc = args.product.lower()
    version = args.version.strip()
    filtered = []
    for hit in ss_hits:
        title = (hit.get("Title") or "")
        title_lc = title.lower()
        path = (hit.get("Path") or "").lower()

        # 1. Product must appear as a word in the title
        import re as _re
        if not _re.search(rf"\b{_re.escape(product_lc)}\b", title_lc):
            continue
        # 2. Reject combo titles where product is paired with something else
        #    that's clearly the actual target ("Apache + PHP < 5.3" when we
        #    asked about Apache alone is too noisy)
        if " + " in title and product_lc not in title_lc.split(" + ")[0]:
            continue
        # 3. Reject platform mismatch for obvious cases
        #    cloudflare WARP is Windows-only — don't match for *nix server
        if "warp" in title_lc and "unquoted service path" in title_lc:
            continue
        # 4. If version provided and title has explicit version constraint,
        #    do best-effort range check
        if version:
            # Find "<= X" / "< X" / "X.Y" patterns in title
            m = _re.search(r"<\s*=?\s*(\d+(?:\.\d+)+)", title_lc)
            if m:
                try:
                    cap = m.group(1)
                    # crude major.minor comparison — if our version is
                    # numerically greater, it's not in range
                    def _to_tuple(v):
                        return tuple(int(x) for x in v.split(".") if x.isdigit())
                    if _to_tuple(version) >= _to_tuple(cap):
                        continue
                except Exception:
                    pass

        filtered.append(hit)
        if len(filtered) >= 5:
            break

    for hit in filtered:
        title = hit.get("Title", "")
        edb_id = hit.get("EDB-ID", "")
        log_finding(
            args.host, args.port,
            severity="info",
            title=f"Public PoC: {title[:80]} (EDB-{edb_id})",
            evidence=f"searchsploit hit: {title}; path: {hit.get('Path', '')}",
            source="searchsploit",
        )

    summary = {
        "host": args.host,
        "port": args.port,
        "product": args.product,
        "version": args.version,
        "templates_matched": len(templates),
        "nuclei_hits": len(nuclei_hits),
        "searchsploit_hits": len(ss_hits),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
