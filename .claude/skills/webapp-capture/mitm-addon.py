"""
slop-hack mitmproxy addon

- Logs every flow as a JSON line to $ENGAGEMENT_DIR/webapp/flows.jsonl
- Refuses out-of-scope hosts via scope-check (returns 403)
- Tags each flow with the auth method observed (cookie/bearer/basic/none)
"""
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from mitmproxy import http, ctx

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
WEBAPP = ENG_DIR / "webapp"
WEBAPP.mkdir(parents=True, exist_ok=True)
FLOWS = WEBAPP / "flows.jsonl"
SCOPE_CHECK = "/usr/local/bin/scope-check"

# In-process scope cache (host -> bool). Cleared per mitmdump run.
_scope_cache: dict[str, bool] = {}


def _in_scope(host: str) -> bool:
    if host in _scope_cache:
        return _scope_cache[host]
    try:
        rc = subprocess.run(
            [SCOPE_CHECK, host],
            capture_output=True, text=True, timeout=5,
        ).returncode
        result = rc == 0
    except Exception as e:
        ctx.log.error(f"scope-check failed for {host}: {e}")
        result = False
    _scope_cache[host] = result
    return result


def _detect_auth(req: http.Request) -> str:
    auth_header = (req.headers.get("authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return "bearer"
    if auth_header.lower().startswith("basic "):
        return "basic"
    if req.headers.get("cookie"):
        return "cookie"
    return "none"


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if not _in_scope(host):
        ctx.log.warn(f"OUT OF SCOPE — blocking: {host}")
        flow.response = http.Response.make(
            403,
            f"slop-hack: {host} blocked by scope-check\n".encode(),
            {"content-type": "text/plain"},
        )


def response(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if not _in_scope(host):
        return  # already blocked at request stage

    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": host,
        "port": flow.request.port,
        "path": flow.request.path,
        "url": flow.request.pretty_url,
        "request_headers": dict(flow.request.headers),
        "request_content_type": flow.request.headers.get("content-type", ""),
        "request_body_size": len(flow.request.content or b""),
        "request_body": (flow.request.get_text() or "")[:4096] if flow.request.content else "",
        "status": flow.response.status_code if flow.response else 0,
        "response_headers": dict(flow.response.headers) if flow.response else {},
        "response_content_type": flow.response.headers.get("content-type", "") if flow.response else "",
        "response_body_size": len(flow.response.content or b"") if flow.response else 0,
        "auth": _detect_auth(flow.request),
    }
    try:
        with open(FLOWS, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        ctx.log.error(f"failed to write flow: {e}")
