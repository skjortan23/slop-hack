#!/usr/bin/env python3
"""Process flows.jsonl into a deduped endpoint inventory.

Path-templates numeric / uuid / hash segments. Merges params from all
observed instances of the same (method, host, path-template, content-type).
"""
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
WEBAPP = ENG_DIR / "webapp"
FLOWS = WEBAPP / "flows.jsonl"
ENDPOINTS = WEBAPP / "endpoints.jsonl"

NUM_RE = re.compile(r"^\d+$")
UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", re.I)
HASH_RE = re.compile(r"^[a-f0-9]{32,}$", re.I)


def path_template(path: str) -> str:
    out = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if NUM_RE.match(seg):
            out.append("{id}")
        elif UUID_RE.match(seg):
            out.append("{uuid}")
        elif HASH_RE.match(seg):
            out.append("{hash}")
        else:
            out.append(seg)
    return "/".join(out)


def extract_params(rec: dict) -> dict:
    qparams = list(parse_qs(urlparse(rec.get("url", "")).query).keys())
    bparams: list[str] = []
    ct = rec.get("request_content_type", "")
    body = rec.get("request_body", "") or ""
    if "application/x-www-form-urlencoded" in ct and body:
        bparams = list(parse_qs(body).keys())
    elif "application/json" in ct and body:
        try:
            j = json.loads(body)
            if isinstance(j, dict):
                bparams = list(j.keys())
        except Exception:
            pass
    return {"query": qparams, "body": bparams}


def main() -> int:
    if not FLOWS.exists():
        print(f"no flows file at {FLOWS}", file=sys.stderr)
        return 1

    seen: dict[tuple, dict] = {}
    with open(FLOWS) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            method = rec.get("method", "")
            host = rec.get("host", "")
            scheme = rec.get("scheme", "https")
            port = rec.get("port", 443)
            path_only = rec.get("path", "").split("?")[0]
            tpl = path_template(path_only)
            ct = rec.get("request_content_type", "")
            key = (method, host, tpl, ct)
            params = extract_params(rec)
            if key in seen:
                seen[key]["params"]["query"] = sorted(set(seen[key]["params"]["query"] + params["query"]))
                seen[key]["params"]["body"] = sorted(set(seen[key]["params"]["body"] + params["body"]))
                seen[key]["count"] += 1
            else:
                seen[key] = {
                    "method": method,
                    "host": host,
                    "port": port,
                    "scheme": scheme,
                    "path": tpl,
                    "example_path": path_only,
                    "url_template": f"{scheme}://{host}{tpl}",
                    "params": params,
                    "auth": rec.get("auth", "none"),
                    "request_content_type": ct,
                    "response_status": rec.get("status", 0),
                    "count": 1,
                }

    WEBAPP.mkdir(parents=True, exist_ok=True)
    with open(ENDPOINTS, "w") as out:
        for ep in seen.values():
            out.write(json.dumps(ep) + "\n")

    summary = {
        "total_endpoints": len(seen),
        "by_method": {},
        "by_auth": {},
        "with_params": 0,
        "output": str(ENDPOINTS),
    }
    for ep in seen.values():
        summary["by_method"][ep["method"]] = summary["by_method"].get(ep["method"], 0) + 1
        summary["by_auth"][ep["auth"]] = summary["by_auth"].get(ep["auth"], 0) + 1
        if ep["params"]["query"] or ep["params"]["body"]:
            summary["with_params"] += 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
