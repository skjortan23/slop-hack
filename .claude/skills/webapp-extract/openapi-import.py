#!/usr/bin/env python3
"""Import an OpenAPI / Swagger spec into the same endpoints.jsonl shape
that webapp-extract emits.

Useful when:
  - The proxy crawl missed endpoints only invoked from JS / on user action
  - You have a spec but no live capture
  - You want to fuzz an API surface that's documented but not crawled

Usage:
  openapi-import <spec.json>                          # uses spec's own servers[]
  openapi-import <spec.json> --base-url URL           # override
  openapi-import <spec.json> --default-host HOST      # fallback when spec omits server

Output: $ENGAGEMENT_DIR/webapp/endpoints.jsonl  (merged with existing if present)
"""
import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
OUT = ENG_DIR / "webapp" / "endpoints.jsonl"


def parse_servers(spec, base_url_override=None, default_host=None):
    """Return list of (scheme, host, port, basepath) tuples."""
    servers = []
    if base_url_override:
        u = urlparse(base_url_override)
        servers.append((
            u.scheme or "https",
            u.hostname,
            u.port or (443 if (u.scheme or "https") == "https" else 80),
            (u.path or "").rstrip("/"),
        ))
        return servers

    if "servers" in spec:  # OpenAPI 3.x
        for s in spec["servers"]:
            url = s.get("url", "")
            for vname, vdata in (s.get("variables") or {}).items():
                url = url.replace("{" + vname + "}", str(vdata.get("default", "")))
            u = urlparse(url)
            host = u.hostname or default_host
            if not host:
                continue
            servers.append((
                u.scheme or "https",
                host,
                u.port or (443 if (u.scheme or "https") == "https" else 80),
                (u.path or "").rstrip("/"),
            ))
    elif "host" in spec:  # Swagger 2.0
        host = spec["host"]
        scheme = (spec.get("schemes") or ["https"])[0]
        basepath = (spec.get("basePath") or "").rstrip("/")
        if ":" in host:
            h, p = host.rsplit(":", 1)
            servers.append((scheme, h, int(p), basepath))
        else:
            servers.append((scheme, host, 443 if scheme == "https" else 80, basepath))

    if not servers and default_host:
        servers.append(("https", default_host, 443, ""))
    return servers


def detect_auth(operation, global_security, sec_schemes):
    sec = operation.get("security")
    if sec is None:
        sec = global_security or []
    if not sec:
        return "none"
    for req in sec:
        for scheme_name in req.keys():
            scheme = sec_schemes.get(scheme_name, {})
            t = (scheme.get("type") or "").lower()
            if t == "http":
                return (scheme.get("scheme") or "basic").lower()
            elif t in ("oauth2", "openidconnect"):
                return "bearer"
            elif t == "apikey":
                return "apikey"
            return "none"
    return "none"


def extract_params(operation):
    out = {"query": [], "body": [], "path": [], "header": []}
    for p in operation.get("parameters") or []:
        loc = p.get("in", "")
        name = p.get("name", "")
        if not name:
            continue
        if loc == "query":
            out["query"].append(name)
        elif loc == "path":
            out["path"].append(name)
        elif loc == "header":
            out["header"].append(name)
        elif loc == "body":
            out["body"].append(name)  # Swagger 2.0 body params

    # OpenAPI 3.x requestBody
    rb = operation.get("requestBody")
    if rb:
        for _, content_def in (rb.get("content") or {}).items():
            schema = content_def.get("schema") or {}
            props = schema.get("properties") or {}
            out["body"].extend(props.keys())
            break  # one content-type's properties is enough

    return {k: sorted(set(v)) for k, v in out.items()}


def get_request_content_type(operation):
    rb = operation.get("requestBody")
    if not rb:
        # Swagger 2.0 fallback
        for ct in operation.get("consumes") or []:
            return ct
        return ""
    for ct in (rb.get("content") or {}).keys():
        return ct
    return ""


def get_first_2xx(operation):
    for code in (operation.get("responses") or {}).keys():
        if str(code).startswith("2"):
            try:
                return int(code)
            except ValueError:
                pass
    return 200


def load_existing(out_path):
    """Return dict keyed by (method, host, path, ctype) → endpoint record."""
    seen = {}
    if not out_path.exists():
        return seen
    with open(out_path) as f:
        for line in f:
            try:
                ep = json.loads(line)
                key = (
                    ep.get("method", ""),
                    ep.get("host", ""),
                    ep.get("path", ""),
                    ep.get("request_content_type", ""),
                )
                seen[key] = ep
            except Exception:
                continue
    return seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("spec_file")
    ap.add_argument("--base-url", help="override server URL (e.g. https://api.acme.com)")
    ap.add_argument("--default-host", help="fallback host if spec omits server info")
    args = ap.parse_args()

    spec_path = Path(args.spec_file)
    if not spec_path.is_file():
        print(f"spec file not found: {spec_path}", file=sys.stderr)
        return 1

    try:
        spec = json.loads(spec_path.read_text())
    except Exception as e:
        print(f"failed to parse spec as JSON: {e}", file=sys.stderr)
        return 1

    sec_schemes = (
        (spec.get("components") or {}).get("securitySchemes")
        or spec.get("securityDefinitions")
        or {}
    )
    global_security = spec.get("security") or []
    servers = parse_servers(spec, args.base_url, args.default_host)
    if not servers:
        print("no server info in spec — pass --base-url or --default-host", file=sys.stderr)
        return 1

    OUT.parent.mkdir(parents=True, exist_ok=True)
    seen = load_existing(OUT)
    pre_count = len(seen)
    added = 0
    merged = 0

    paths = spec.get("paths") or {}
    for path, path_def in paths.items():
        if not isinstance(path_def, dict):
            continue
        shared_params = path_def.get("parameters") or []
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            op = path_def.get(method)
            if not isinstance(op, dict):
                continue

            merged_op = dict(op)
            merged_op["parameters"] = list(op.get("parameters") or []) + list(shared_params)

            params = extract_params(merged_op)
            ctype = get_request_content_type(merged_op)
            auth = detect_auth(merged_op, global_security, sec_schemes)
            status = get_first_2xx(merged_op)

            for scheme, host, port, basepath in servers:
                full_path = f"{basepath}{path}" if basepath else path
                url = f"{scheme}://{host}{full_path}"
                key = (method.upper(), host, full_path, ctype)

                if key in seen:
                    existing = seen[key]
                    existing.setdefault("params", {"query": [], "body": []})
                    existing["params"]["query"] = sorted(set(
                        (existing["params"].get("query") or []) + params["query"]
                    ))
                    existing["params"]["body"] = sorted(set(
                        (existing["params"].get("body") or []) + params["body"]
                    ))
                    if "openapi-import" not in (existing.get("source") or ""):
                        existing["source"] = ((existing.get("source") or "") + ",openapi-import").lstrip(",")
                    merged += 1
                else:
                    seen[key] = {
                        "method": method.upper(),
                        "host": host,
                        "port": port,
                        "scheme": scheme,
                        "path": full_path,
                        "example_path": full_path,
                        "url_template": url,
                        "params": params,
                        "auth": auth,
                        "request_content_type": ctype,
                        "response_status": status,
                        "count": 1,
                        "source": "openapi-import",
                    }
                    added += 1

    with open(OUT, "w") as f:
        for ep in seen.values():
            f.write(json.dumps(ep) + "\n")

    summary = {
        "spec": str(spec_path),
        "servers": [{"scheme": s, "host": h, "port": p, "basepath": bp} for (s, h, p, bp) in servers],
        "endpoints_in_spec": added + merged,
        "new_endpoints_added": added,
        "merged_into_existing": merged,
        "total_endpoints_after": len(seen),
        "previously_present": pre_count,
        "output": str(OUT),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
