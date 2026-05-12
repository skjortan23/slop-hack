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
    Path("/root/.local/nuclei-templates/http/cves"),
    Path("/root/.local/nuclei-templates/http/vulnerabilities"),
    # Legacy paths (pre-nuclei-v3) — kept for backward compat / other images
    Path("/root/nuclei-templates/http/cves"),
    Path("/root/nuclei-templates/http/vulnerabilities"),
]


def find_templates(product: str, version: str = "", limit: int = 200) -> list[str]:
    """Find nuclei templates matching the product. Prefer templates that also
    mention the version (so e.g. apache 2.4.49 → CVE-2021-41773 is at the top
    of the list, not at position 70 where the 30-template default would miss
    it)."""
    found = []
    version_priority = []
    for d in CVES_DIRS:
        if not d.exists():
            continue
        try:
            out = subprocess.run(
                ["grep", "-ril", "--include=*.yaml", product, str(d)],
                capture_output=True, text=True, timeout=30,
            )
            for line in out.stdout.splitlines():
                if not line:
                    continue
                if version and version in line:
                    if line not in version_priority:
                        version_priority.append(line)
                elif version:
                    # quick check: file content contains the version?
                    try:
                        if version in Path(line).read_text(errors="ignore"):
                            if line not in version_priority:
                                version_priority.append(line)
                            continue
                    except Exception:
                        pass
                if line not in found and line not in version_priority:
                    found.append(line)
        except Exception:
            continue
    # version-matched templates first, rest after; cap total at limit
    return (version_priority + found)[:limit]


def run_nuclei(host: str, port: int, templates: list[str]) -> list[dict]:
    """Run nuclei against the selected templates, return parsed JSON hits."""
    if not templates:
        return []
    target = f"https://{host}:{port}" if port in (443, 8443) else f"http://{host}:{port}"
    out_file = Path(f"/tmp/vc-nuclei-{os.getpid()}.json")
    try:
        # nuclei -t accepts comma-separated paths (not space-separated). The
        # old `["-t"] + templates` form caused all but the first template to
        # be treated as targets, silently dropping everything we wanted to run.
        cmd = (
            ["nuclei", "-target", target,
             "-t", ",".join(templates),
             "-json-export", str(out_file),
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


# Tier 2 patterns — matcher proves command execution / file-content disclosure.
# If a nuclei template matches on these, the hit is real exploit confirmation.
_TIER2_PATTERNS = [
    r"\broot:.*:0:0:",          # /etc/passwd
    r"\buid=\d+\([a-z]",          # `id` output
    r"\[boot loader\]",            # win.ini
    r"\[fonts\]",                  # win.ini
    r"PRIVATE KEY",                # ssh keys / pem
    r"AWS_SECRET_ACCESS_KEY",      # AWS creds
    r"BEGIN RSA PRIVATE KEY",
    r"<\?xml.*entity",             # XXE
    r"\\windows\\system32",        # win path disclosure
]


_EXPLOIT_TAGS = {"rce", "lfi", "sqli", "ssti", "xxe", "cmd-injection",
                 "file-disclosure", "traversal", "deserialization",
                 "code-injection", "command-injection", "auth-bypass"}
_OOB_TAGS = {"ssrf", "blind", "oob", "log4j", "log4shell"}
_VERSION_TAGS = {"tech", "detect", "panel", "fingerprint", "exposed", "disclosure"}


def classify_nuclei_hit(hit: dict) -> tuple[str, str]:
    """Decide tier from template tags + response content.

    Tier 2 (in-band proof of exec / file content) → critical
    Tier 1 (OOB callback via interactsh)          → high
    Tier 0 (version banner / fingerprint only)    → medium

    Returns (tier_label, severity).
    """
    import re as _re

    info = hit.get("info") or {}
    tags = set((info.get("tags") or []))
    response = hit.get("response") or ""
    if isinstance(response, list):
        response = "\n".join(str(x) for x in response)

    # 1. Strong in-band signature in response → unambiguous Tier 2
    if any(_re.search(p, response, _re.I) for p in _TIER2_PATTERNS):
        return ("tier2", "critical")

    # 2. Template tags identify exploit class
    if tags & _EXPLOIT_TAGS:
        # Exploit-class template that fired its matcher = in-band exploit proven
        return ("tier2", "critical")

    if tags & _OOB_TAGS:
        return ("tier1", "high")

    # 3. Check template file for interactsh use
    tmpl_path = hit.get("template-path") or hit.get("template") or ""
    if tmpl_path and Path(tmpl_path).exists():
        try:
            tmpl_src = Path(tmpl_path).read_text(errors="ignore")
            if "{{interactsh" in tmpl_src or "interactsh-url" in tmpl_src:
                return ("tier1", "high")
        except Exception:
            pass

    # 4. Version/fingerprint-only template
    return ("tier0", "medium")


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

    templates = find_templates(args.product, args.version)
    nuclei_hits = run_nuclei(args.host, args.port, templates)
    for hit in nuclei_hits:
        info = hit.get("info") or {}
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        cve = cves[0] if cves else None

        # Classify by matcher type — overrides template's declared severity.
        # See CLAUDE.md "tier-graded severity": critical=Tier 2 (in-band exec),
        # high=Tier 1 (OOB callback), medium=Tier 0 (version banner only).
        tier, graded_severity = classify_nuclei_hit(hit)
        title = info.get("name") or hit.get("template-id", "nuclei finding")
        title = f"[{tier}] {title}"

        evidence_parts = [
            f"matched at {hit.get('matched-at', '?')}",
            f"template {hit.get('template-id', '?')}",
        ]
        # Include a snippet of the matched response if we have it (proof line)
        for key in ("matched-line", "extracted-results"):
            v = hit.get(key)
            if v:
                snippet = (v[0] if isinstance(v, list) else str(v))[:200]
                evidence_parts.append(f"proof: {snippet}")
                break

        log_finding(
            args.host, args.port,
            severity=graded_severity,
            title=title,
            evidence=" | ".join(evidence_parts),
            source=f"nuclei-cve-{tier}",
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
