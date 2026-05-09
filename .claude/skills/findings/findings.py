#!/usr/bin/env python3
"""Findings logger — per-host YAML + append-only JSONL audit log.

Layout:
  $ENGAGEMENT_DIR/findings/hosts/<safe-host>.yaml
  $ENGAGEMENT_DIR/findings/findings.jsonl

ENGAGEMENT_DIR defaults to /work/default if unset.
"""
import sys
import os
import re
import json
import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required (apt install python3-yaml)", file=sys.stderr)
    sys.exit(2)


SEVERITIES = ["info", "low", "medium", "high", "critical"]

# Map common scheme/service names to their transport so non-standard port specs
# like "443/https" get normalized to "443/tcp" — keeps reports consistent.
_SCHEME_TO_PROTO = {
    "http": "tcp", "https": "tcp", "ssh": "tcp", "ftp": "tcp", "smtp": "tcp",
    "smtps": "tcp", "imap": "tcp", "imaps": "tcp", "pop3": "tcp", "pop3s": "tcp",
    "ldap": "tcp", "ldaps": "tcp", "smb": "tcp", "rdp": "tcp", "vnc": "tcp",
    "mysql": "tcp", "postgres": "tcp", "redis": "tcp", "mongodb": "tcp",
    "elasticsearch": "tcp", "memcached": "tcp", "telnet": "tcp",
    "dns": "udp", "ntp": "udp", "snmp": "udp", "tftp": "udp", "dhcp": "udp",
}


def normalize_port(port_str: str) -> str:
    """Normalize a port argument to '<num>/<tcp|udp>' form.

    Accepts: '443', '443/tcp', '443/udp', '443/https' (→ '443/tcp')
    """
    if not port_str:
        return port_str
    if "/" not in port_str:
        return f"{port_str}/tcp"
    num, _, proto = port_str.partition("/")
    proto = proto.lower()
    if proto in ("tcp", "udp"):
        return f"{num}/{proto}"
    if proto in _SCHEME_TO_PROTO:
        return f"{num}/{_SCHEME_TO_PROTO[proto]}"
    # Unknown — leave as-is but the caller probably has a typo
    print(f"warning: unknown port proto '{proto}' in '{port_str}' — keeping as-is", file=sys.stderr)
    return port_str


def engagement_dir():
    d = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
    (d / "findings" / "hosts").mkdir(parents=True, exist_ok=True)
    return d


def safe_filename(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host)


def host_path(host: str) -> Path:
    return engagement_dir() / "findings" / "hosts" / (safe_filename(host) + ".yaml")


def load_host(host: str) -> dict:
    p = host_path(host)
    if p.exists():
        with open(p) as f:
            data = yaml.safe_load(f) or {}
        data.setdefault("host", host)
        data.setdefault("hostnames", [])
        data.setdefault("metadata", {})
        data.setdefault("services", {})
        data.setdefault("host_findings", [])
        return data
    return {
        "host": host,
        "hostnames": [],
        "metadata": {},
        "services": {},
        "host_findings": [],
    }


def save_host(data: dict) -> None:
    with open(host_path(data["host"]), "w") as f:
        yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def gen_id(host: str, body: str) -> str:
    h = hashlib.sha1(f"{host}:{body}".encode()).hexdigest()[:8]
    return f"F-{h}"


def append_jsonl(record: dict) -> None:
    p = engagement_dir() / "findings" / "findings.jsonl"
    with open(p, "a") as f:
        f.write(json.dumps(record) + "\n")


def cmd_host_set(args):
    h = load_host(args.host)
    if args.hostname:
        for hn in args.hostname:
            if hn not in h["hostnames"]:
                h["hostnames"].append(hn)
    if args.asn:
        h["metadata"]["asn"] = args.asn
    if args.cdn is not None:
        h["metadata"]["cdn"] = args.cdn
    if args.os_guess:
        h["metadata"]["os_guess"] = args.os_guess
    if args.note:
        h["metadata"].setdefault("notes", []).append({"ts": now(), "text": args.note})
    h["last_seen"] = now()
    save_host(h)
    print(json.dumps({"ok": True, "host": h["host"], "path": str(host_path(args.host))}))


def cmd_service_set(args):
    h = load_host(args.host)
    key = normalize_port(args.port_proto)
    svc = h["services"].get(key) or {"findings": []}
    if args.service:
        svc["service"] = args.service
    if args.product:
        svc["product"] = args.product
    if args.version:
        svc["version"] = args.version
    if args.banner:
        svc["banner"] = args.banner
    svc.setdefault("findings", [])
    h["services"][key] = svc
    h["last_seen"] = now()
    save_host(h)
    print(json.dumps({"ok": True, "host": args.host, "service": key}))


def cmd_add(args):
    if args.severity not in SEVERITIES:
        print(f"severity must be one of {SEVERITIES}", file=sys.stderr)
        sys.exit(2)
    h = load_host(args.host)
    fid = gen_id(args.host, args.title + (args.evidence or ""))
    finding = {
        "id": fid,
        "severity": args.severity,
        "title": args.title,
        "description": args.description,
        "evidence": args.evidence,
        "cve": args.cve,
        "source": args.source,
        "ts": now(),
    }
    finding = {k: v for k, v in finding.items() if v is not None}
    if args.port:
        port_key = normalize_port(args.port)
        svc = h["services"].setdefault(port_key, {"findings": []})
        svc.setdefault("findings", []).append(finding)
    else:
        h["host_findings"].append(finding)
    h["last_seen"] = now()
    save_host(h)
    append_jsonl({"host": args.host, "port": args.port, **finding})
    print(json.dumps({"ok": True, "id": fid}))


def cmd_show(args):
    h = load_host(args.host)
    print(yaml.safe_dump(h, sort_keys=False, default_flow_style=False))


def cmd_list(args):
    d = engagement_dir() / "findings" / "hosts"
    rows = []
    for f in sorted(d.glob("*.yaml")):
        data = yaml.safe_load(f.read_text()) or {}
        n = len(data.get("host_findings") or [])
        for _, svc in (data.get("services") or {}).items():
            n += len(svc.get("findings") or [])
        rows.append({
            "host": data.get("host"),
            "hostnames": data.get("hostnames") or [],
            "services": len(data.get("services") or {}),
            "findings": n,
            "last_seen": data.get("last_seen"),
        })
    print(json.dumps(rows, indent=2))


def cmd_export_md(args):
    d = engagement_dir() / "findings" / "hosts"
    sev_rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    all_findings = []
    for f in sorted(d.glob("*.yaml")):
        data = yaml.safe_load(f.read_text()) or {}
        for fi in data.get("host_findings") or []:
            all_findings.append({**fi, "host": data["host"], "port": None})
        for port, svc in (data.get("services") or {}).items():
            for fi in svc.get("findings") or []:
                all_findings.append({**fi, "host": data["host"], "port": port})
    all_findings.sort(key=lambda x: sev_rank.get(x.get("severity", "info"), 99))

    out = ["# Engagement findings\n"]
    eng = os.environ.get("ENGAGEMENT_DIR", "/work/default").split("/")[-1]
    out.append(f"_Engagement: `{eng}` — generated {now()}_\n")

    counts = {s: 0 for s in SEVERITIES}
    for fi in all_findings:
        counts[fi.get("severity", "info")] = counts.get(fi.get("severity", "info"), 0) + 1
    out.append("## Summary\n")
    out.append("| Severity | Count |")
    out.append("|---|---|")
    for s in reversed(SEVERITIES):
        out.append(f"| {s} | {counts.get(s, 0)} |")
    out.append("")

    out.append("## Findings\n")
    for fi in all_findings:
        sev = fi.get("severity", "?").upper()
        out.append(f"### [{sev}] {fi.get('title', '(no title)')}")
        loc = f"`{fi.get('host')}`"
        if fi.get("port"):
            loc += f" / `{fi['port']}`"
        out.append(f"- Location: {loc}")
        if fi.get("cve"):
            out.append(f"- CVE: {fi['cve']}")
        if fi.get("source"):
            out.append(f"- Source: {fi['source']}")
        if fi.get("ts"):
            out.append(f"- Found: {fi['ts']}")
        if fi.get("description"):
            out.append(f"\n{fi['description']}\n")
        if fi.get("evidence"):
            out.append("\n```")
            out.append(str(fi["evidence"]))
            out.append("```\n")
        out.append("")
    print("\n".join(out))


def main():
    p = argparse.ArgumentParser(prog="findings")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("host-set", help="upsert a host")
    s.add_argument("host")
    s.add_argument("--hostname", action="append")
    s.add_argument("--asn")
    s.add_argument("--cdn", type=lambda x: x.lower() == "true")
    s.add_argument("--os-guess", dest="os_guess")
    s.add_argument("--note")
    s.set_defaults(func=cmd_host_set)

    s = sub.add_parser("service-set", help="upsert a service on a host")
    s.add_argument("host")
    s.add_argument("port_proto", help="e.g. 443/tcp")
    s.add_argument("--service")
    s.add_argument("--product")
    s.add_argument("--version")
    s.add_argument("--banner")
    s.set_defaults(func=cmd_service_set)

    s = sub.add_parser("add", help="record a finding")
    s.add_argument("host")
    s.add_argument("--port", help="port/proto if service-specific")
    s.add_argument("--severity", required=True, choices=SEVERITIES)
    s.add_argument("--title", required=True)
    s.add_argument("--evidence")
    s.add_argument("--description")
    s.add_argument("--cve")
    s.add_argument("--source")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("show")
    s.add_argument("host")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("export-md")
    s.set_defaults(func=cmd_export_md)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
