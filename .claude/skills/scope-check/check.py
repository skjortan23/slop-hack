#!/usr/bin/env python3
"""Scope check for pentest engagements.

Exit codes:
  0 — in scope, proceed
  1 — out of scope or expired, REFUSE
  2 — config error
"""
import sys
import os
import json
import fnmatch
import ipaddress
from datetime import date
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    print(json.dumps({"error": "PyYAML not installed"}), file=sys.stderr)
    sys.exit(2)


def find_scope_file():
    candidates = [
        os.environ.get("SCOPE_FILE"),
        os.path.join(os.environ["ENGAGEMENT_DIR"], "scope.yaml") if os.environ.get("ENGAGEMENT_DIR") else None,
        "/scope/scope.yaml",
        "./scope.yaml",
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return None


def normalize(target):
    if "://" in target:
        target = urlparse(target).hostname or target
    return target.strip().lower().rstrip("/")


def match_rule(target, rule):
    rule = rule.strip().lower()
    try:
        net = ipaddress.ip_network(rule, strict=False)
        try:
            return ipaddress.ip_address(target) in net
        except ValueError:
            return False
    except ValueError:
        pass
    return fnmatch.fnmatch(target, rule)


def main():
    if len(sys.argv) != 2:
        print("usage: check.py <target>", file=sys.stderr)
        sys.exit(2)

    target = normalize(sys.argv[1])
    scope_file = find_scope_file()
    if not scope_file:
        print(json.dumps({"error": "no scope.yaml found", "target": target}), file=sys.stderr)
        sys.exit(2)

    try:
        with open(scope_file) as f:
            scope = yaml.safe_load(f) or {}
    except Exception as e:
        print(json.dumps({"error": f"scope.yaml parse failed: {e}"}), file=sys.stderr)
        sys.exit(2)

    auth_until = scope.get("authorized_until")
    if isinstance(auth_until, str):
        try:
            auth_until = date.fromisoformat(auth_until)
        except ValueError:
            auth_until = None
    if isinstance(auth_until, date) and auth_until < date.today():
        print(json.dumps({
            "target": target, "in_scope": False,
            "reason": "engagement expired",
            "authorized_until": str(auth_until),
        }))
        sys.exit(1)

    for rule in scope.get("out_of_scope") or []:
        if match_rule(target, rule):
            print(json.dumps({
                "target": target, "in_scope": False,
                "reason": "out_of_scope", "matched_rule": rule,
            }))
            sys.exit(1)

    for rule in scope.get("in_scope") or []:
        if match_rule(target, rule):
            print(json.dumps({
                "target": target, "in_scope": True,
                "engagement_id": scope.get("engagement_id"),
                "matched_rule": rule,
                "authorized_until": str(auth_until) if auth_until else None,
            }))
            sys.exit(0)

    print(json.dumps({
        "target": target, "in_scope": False,
        "reason": "no in_scope rule matched",
    }))
    sys.exit(1)


if __name__ == "__main__":
    main()
