#!/usr/bin/env python3
"""endpoint-authcheck: for each endpoint in endpoints.jsonl, send the request
WITHOUT auth and classify the response. Surfaces endpoints that should require
authentication but don't enforce it.

Complements webapp-fuzz (injection) by covering access-control gaps.

Usage:
    endpoint-authcheck                                 # process endpoints.jsonl
    endpoint-authcheck --limit 20                      # cap probes
    endpoint-authcheck --rate-limit 0.5                # seconds between probes
    endpoint-authcheck --url URL --method GET          # one-shot
    endpoint-authcheck --json                          # JSON summary

Classification per response:
- 401/403                       → auth-enforced (info only; expected for protected endpoints)
- 200 with real data            → UNAUTH-EXECUTES (high — endpoint executed pre-auth)
- 422/400 + validation error    → auth-not-enforced-before-validation (medium — endpoint reachable without creds)
- 405 method-not-allowed        → method-check-before-auth (info — endpoint exists)
- 404                           → not-found (skip)
- 500                           → server-error (low — endpoint reached, weak handling)
- 5xx/timeout/network           → skip
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
WEBAPP = ENG_DIR / "webapp"
ENDPOINTS_FILE = WEBAPP / "endpoints.jsonl"
RESULTS_FILE = WEBAPP / "authcheck-results.jsonl"

# Patterns indicating a body is an auth-required error (so even with 200 we'd dismiss)
AUTH_ERROR_PATTERNS = [
    re.compile(r'"detail"\s*:\s*"(missing|invalid|expired|unauthorized|forbidden)', re.I),
    re.compile(r'"error"\s*:\s*"(unauthorized|forbidden|auth required)', re.I),
    re.compile(r'unauthorized', re.I),
]

# Patterns indicating a body is real data (not an auth error)
DATA_INDICATORS = [
    re.compile(r'\[\s*\{', re.S),         # JSON array of objects
    re.compile(r'"id"\s*:\s*[0-9"]', re.S),
    re.compile(r'"name"\s*:\s*"[^"]+', re.S),
    re.compile(r'"data"\s*:\s*\[', re.S),
    re.compile(r'"results"\s*:\s*\[', re.S),
    re.compile(r'"items"\s*:\s*\[', re.S),
    re.compile(r'"total"\s*:\s*\d', re.S),
    re.compile(r'"users"\s*:\s*\[', re.S),
]

# Paths that are public by design — skip the finding for these
PUBLIC_PATH_PATTERNS = [
    re.compile(r'^/$'),
    re.compile(r'^/docs/?$', re.I),
    re.compile(r'^/redoc/?$', re.I),
    re.compile(r'^/openapi\.json$', re.I),
    re.compile(r'^/swagger\b', re.I),
    re.compile(r'^/static/'),
    re.compile(r'^/assets/'),
    re.compile(r'^/favicon\.'),
    re.compile(r'^/robots\.txt$'),
    re.compile(r'^/sitemap', re.I),
    re.compile(r'^/health/?$', re.I),
    re.compile(r'^/healthz/?$', re.I),
    re.compile(r'^/status/?$', re.I),
    re.compile(r'^/ping/?$', re.I),
    re.compile(r'^/metrics/?$', re.I),
    re.compile(r'^/\.well-known/'),
]

# Auth-handling paths — public by design, 422 on these is expected
AUTH_PATH_PATTERNS = [
    re.compile(r'/auth/(login|register|forgot|reset|verify|callback|logout)\b', re.I),
    re.compile(r'/auth/(github|google|oauth|sso)\b', re.I),
    re.compile(r'/login\b', re.I),
    re.compile(r'/register\b', re.I),
    re.compile(r'/signup\b', re.I),
    re.compile(r'/oauth/', re.I),
    re.compile(r'/sso/', re.I),
]


def _is_public_path(path: str) -> bool:
    return any(rx.search(path) for rx in PUBLIC_PATH_PATTERNS)


def _is_auth_path(path: str) -> bool:
    return any(rx.search(path) for rx in AUTH_PATH_PATTERNS)


def _looks_like_html(body: str) -> bool:
    head = (body or "")[:200].lower().strip()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<body" in head


# Auth-error key names we expect in a {"detail":"..."} / {"error":"..."} envelope
_AUTH_ERR_KEYS = {"detail", "error", "message", "errors"}


def _is_data_json(body: str) -> bool:
    """True if body parses as a JSON OBJECT with substantive content (not just
    an auth-error envelope like {"detail": "Missing token"})."""
    try:
        obj = json.loads(body)
    except Exception:
        return False
    if isinstance(obj, list):
        return len(obj) > 0
    if not isinstance(obj, dict):
        return False
    keys = set(obj.keys())
    # If the only keys are auth-error keys with short string values, it's an error envelope
    if keys and keys.issubset(_AUTH_ERR_KEYS):
        for v in obj.values():
            if isinstance(v, str) and len(v) < 200:
                continue
            return True  # value is large or non-string → real data
        return False
    # Multiple keys with mixed types → real data (e.g. config endpoint)
    return len(keys) >= 2


# Operational config = worker counts, max_tokens, feature-flag-style fields.
# Per CLAUDE.md anti-inflation rule #2 these are LOW, not HIGH, when leaked
# unauth. A key is "operational" if it matches one of these substrings.
_OP_CONFIG_KEY_HINTS = (
    "worker", "workers_max", "max_token", "max_tokens", "rate_limit",
    "concurrency", "queue", "pool_size", "thread", "feature", "flag",
    "enabled", "audit", "review", "fix", "overview", "available",
)


def _is_operational_config(body: str) -> bool:
    """True if body is a JSON object whose values are all numeric/bool/short-str
    AND whose keys look like operational config (worker counts, flags, max_*).
    No secrets, no PII, no internal hostnames → LOW per anti-inflation rule."""
    try:
        obj = json.loads(body)
    except Exception:
        return False
    if not isinstance(obj, dict) or not obj:
        return False
    for v in obj.values():
        if isinstance(v, (int, float, bool)):
            continue
        if isinstance(v, str) and len(v) < 40 and "://" not in v and "=" not in v:
            continue
        return False  # nested object, long string, URL, conn-string → not op-config
    keys_lc = " ".join(obj.keys()).lower()
    return any(hint in keys_lc for hint in _OP_CONFIG_KEY_HINTS)


def _is_health_booleans(body: str) -> bool:
    """True if body is a JSON object whose values are all boolean — pure
    health/status flags, downgrade to info."""
    try:
        obj = json.loads(body)
    except Exception:
        return False
    if not isinstance(obj, dict) or not obj:
        return False
    return all(isinstance(v, bool) for v in obj.values())


def expand_path(path: str) -> str:
    """Replace template tokens with placeholder values."""
    return (path
            .replace("{id}", "1")
            .replace("{uuid}", "00000000-0000-0000-0000-000000000000")
            .replace("{hash}", "0" * 32)
            # Common FastAPI-style params
            .replace("{token_id}", "1")
            .replace("{job_id}", "1")
            .replace("{scan_id}", "1")
            .replace("{repo_id}", "1")
            .replace("{repo_full_name}", "owner/repo")
            .replace("{target_user_id}", "1")
            .replace("{filename}", "test.txt")
            .replace("{repo}", "test"))


def build_body(params: list) -> str:
    """Build a JSON body from declared body params."""
    if not params:
        return "{}"
    return json.dumps({p: "test" for p in params[:10]})


def probe(ep: dict, timeout: float = 10) -> dict:
    method = (ep.get("method") or "GET").upper()
    host = ep.get("host", "")
    port = ep.get("port", 443)
    scheme = ep.get("scheme", "https")
    path = expand_path(ep.get("path") or ep.get("example_path") or "/")

    url = f"{scheme}://{host}:{port}{path}" if port not in (80, 443) else f"{scheme}://{host}{path}"

    headers = ["-H", "Accept: application/json"]
    body_args = []
    body_params = (ep.get("params") or {}).get("body") or []
    ctype = ep.get("request_content_type") or "application/json"

    if method in ("POST", "PUT", "PATCH"):
        body = build_body(body_params)
        headers += ["-H", f"Content-Type: {ctype}"]
        body_args = ["-d", body]

    cmd = ["curl", "-sk", "-o", "-",
           "-w", "\n___STATUS:%{http_code}___",
           "-m", str(timeout),
           "-X", method, url] + headers + body_args

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        out = r.stdout
    except Exception as e:
        return {"error": str(e), "url": url, "method": method, "status": 0}

    m = re.search(r"___STATUS:(\d{3})___$", out.rstrip())
    status = int(m.group(1)) if m else 0
    body = out[:m.start()] if m else out

    return {
        "url": url,
        "method": method,
        "status": status,
        "body_size": len(body),
        "body_snippet": body[:300],
    }


def classify(probe_result: dict, path: str = "") -> dict:
    """Return classification + suggested severity + reason."""
    status = probe_result["status"]
    body = probe_result.get("body_snippet", "") or ""
    size = probe_result.get("body_size", 0)
    path = path or "/"

    # Path-aware early exits
    public_by_design = _is_public_path(path)
    auth_route = _is_auth_path(path)

    if status == 0:
        return {"bucket": "network_error", "severity": None, "log": False}
    if status == 404:
        return {"bucket": "not_found", "severity": None, "log": False}
    if status in (401, 403):
        return {"bucket": "auth_enforced", "severity": "info", "log": False,
                "reason": f"{status} — auth required"}
    if status == 405:
        return {"bucket": "method_not_allowed", "severity": None, "log": False,
                "reason": "405 — method check before auth (not a vuln)"}

    if status == 200:
        is_auth_err = any(rx.search(body) for rx in AUTH_ERROR_PATTERNS)
        has_data = (
            any(rx.search(body) for rx in DATA_INDICATORS)
            or size > 200
            or _is_data_json(body)
        )

        if is_auth_err:
            return {"bucket": "auth_enforced_200", "severity": "info", "log": False,
                    "reason": "200 but body is auth-error (e.g., missing token)"}

        # Public-by-design — don't flag at all
        if public_by_design:
            return {"bucket": "public_by_design", "severity": "info", "log": False,
                    "reason": f"public-by-design path ({path})"}

        # POST/PUT/PATCH/DELETE that returns 200 without auth = endpoint
        # accepted a state-changing request. Worth flagging even if body
        # is small — webhooks, action endpoints.
        method = probe_result.get("method", "GET").upper()
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return {"bucket": "UNAUTH_STATE_CHANGE", "severity": "high", "log": True,
                    "reason": f"{method} accepted without auth, status 200 (size={size})"}

        if not has_data:
            return {"bucket": "empty_200", "severity": "info", "log": False,
                    "reason": f"200 with empty/trivial body (size={size})"}

        # SPA catch-all detection — non-/api/ path returning HTML
        # AND HTML body → most likely the SPA's index.html being served for
        # an unknown route. NOT a real data exposure.
        if _looks_like_html(body) and not path.startswith("/api/"):
            return {"bucket": "spa_catchall", "severity": "info", "log": False,
                    "reason": f"path returns SPA HTML (likely client-side route, not real data)"}
        if _looks_like_html(body) and path.startswith("/api/"):
            # /api/* should be JSON. HTML on /api/* = routing fall-through —
            # not a real data exposure but worth noting at info
            return {"bucket": "api_html_fallthrough", "severity": "info",
                    "log": False,
                    "reason": "/api/* path returning HTML — SPA catch-all, not real data"}

        # Real /api/* JSON response with data → genuine finding
        if path.startswith("/api/"):
            return {"bucket": "UNAUTH_EXECUTES", "severity": "high", "log": True,
                    "reason": f"200 with JSON data on /api/* (size={size})"}

        # Other non-API non-public — could still be sensitive, log as low
        return {"bucket": "unauth_non_api_data", "severity": "low", "log": True,
                "reason": f"200 with data on non-API path (size={size})"}

    if status in (400, 422):
        # Auth-public routes are designed to validate input even without auth
        if auth_route:
            return {"bucket": "auth_route_validation", "severity": "info",
                    "log": False,
                    "reason": f"{status} on auth-public route — expected (validation runs pre-auth)"}
        return {"bucket": "validation_only", "severity": "medium", "log": True,
                "reason": f"{status} — endpoint reachable without auth, rejected on validation"}
    if status >= 500:
        return {"bucket": "server_error", "severity": "low", "log": True,
                "reason": f"{status} server error — endpoint reached, weak handling"}
    if 300 <= status < 400:
        loc_match = re.search(r"location:\s*(\S+)", body, re.I)
        target = loc_match.group(1) if loc_match else ""
        return {"bucket": "redirect", "severity": "info", "log": False,
                "reason": f"{status} redirect → {target}"}
    return {"bucket": f"http_{status}", "severity": "info", "log": False,
            "reason": f"unexpected {status}"}


def log_finding(host, port, *, severity, title, evidence, source="endpoint-authcheck"):
    subprocess.run(
        ["findings", "add", host,
         "--port", f"{port}/tcp",
         "--severity", severity,
         "--title", title,
         "--evidence", evidence[:512],
         "--source", source],
        check=False, capture_output=True, timeout=10,
    )


def main() -> int:
    ap = argparse.ArgumentParser(prog="endpoint-authcheck")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--rate-limit", type=float, default=0.3, dest="rate")
    ap.add_argument("--url", help="one-shot mode")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--no-log", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    endpoints = []
    if args.url:
        u = urllib.parse.urlparse(args.url)
        endpoints.append({
            "method": args.method,
            "host": u.hostname or "",
            "port": u.port or (443 if u.scheme == "https" else 80),
            "scheme": u.scheme or "https",
            "path": u.path or "/",
        })
    elif ENDPOINTS_FILE.exists():
        with open(ENDPOINTS_FILE) as f:
            for line in f:
                try:
                    endpoints.append(json.loads(line))
                except Exception:
                    continue
    else:
        print(f"no endpoints at {ENDPOINTS_FILE} — run webapp-extract or openapi-import first",
              file=sys.stderr)
        return 1

    if args.limit > 0:
        endpoints = endpoints[: args.limit]

    if not endpoints:
        print("no endpoints to probe")
        return 0

    print(f"probing {len(endpoints)} endpoint(s) unauthenticated...", file=sys.stderr)
    WEBAPP.mkdir(parents=True, exist_ok=True)
    if RESULTS_FILE.exists():
        RESULTS_FILE.unlink()

    summary = {
        "total": len(endpoints),
        "by_bucket": {},
        "logged_findings": 0,
        "unauth_executes": [],
    }
    results = []

    for i, ep in enumerate(endpoints, 1):
        if args.rate and i > 1:
            time.sleep(args.rate)
        pr = probe(ep)
        cls = classify(pr, path=ep.get("path") or ep.get("example_path") or "/")
        rec = {"endpoint": ep, "probe": pr, "classification": cls}
        results.append(rec)
        with open(RESULTS_FILE, "a") as f:
            f.write(json.dumps(rec) + "\n")

        b = cls.get("bucket", "?")
        summary["by_bucket"][b] = summary["by_bucket"].get(b, 0) + 1

        if cls.get("log") and not args.no_log:
            host = ep.get("host", pr["url"])
            port = ep.get("port", 443)
            method = ep.get("method", "GET")
            path = ep.get("path", "/")
            title = {
                "UNAUTH_EXECUTES":
                    f"Unauthenticated access executes {method} {path}",
                "validation_only":
                    f"Endpoint reachable without auth: {method} {path}",
                "server_error":
                    f"Server error on unauth {method} {path}",
            }.get(b, f"unauth probe {method} {path}")
            log_finding(
                host, port,
                severity=cls["severity"],
                title=title,
                evidence=f"{pr['method']} {pr['url']} -> {pr['status']} "
                         f"(size={pr['body_size']}): {pr['body_snippet'][:200]}",
            )
            summary["logged_findings"] += 1

        if b == "UNAUTH_EXECUTES":
            summary["unauth_executes"].append({
                "url": pr["url"], "method": pr["method"], "status": pr["status"],
                "size": pr["body_size"], "snippet": pr["body_snippet"][:150],
            })

        # Live progress on important hits
        if cls.get("log"):
            sev = cls["severity"].upper()
            print(f"  [{sev}] {pr['method']} {pr['url']} → {pr['status']} ({cls.get('reason','')[:80]})",
                  file=sys.stderr)

    if args.json:
        print(json.dumps({"summary": summary, "results": results}, indent=2))
    else:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
