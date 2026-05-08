---
name: scope-check
description: Validate that a target (domain, IP, CIDR, or URL) is authorized in the engagement scope before any other recon, scan, or pentest action. MUST be called by every other pentest skill on every target before sending packets or making queries about that target. Reads scope.yaml from /scope/scope.yaml or $ENGAGEMENT_DIR/scope.yaml. Refuses on out-of-scope or expired engagements.
---

# Scope Check

Before any other pentest skill touches a target, validate it against the engagement scope. This is a hard gate — no skill may proceed without it.

## When to call

Every other skill MUST call this first per target. If you (the agent) are about to run any tool — passive or active — that takes a domain, IP, CIDR, URL, or org name as input, run scope-check first. If it returns out-of-scope, refuse the action and explain to the user.

## Input

A single target string: domain (`acme.com`), IP (`1.2.3.4`), CIDR (`1.2.3.0/24`), or URL (`https://acme.com/login`).

## How

```bash
python3 /root/.claude/skills/scope-check/check.py <target>
```

Exit codes:
- `0` — in scope, proceed
- `1` — out of scope or expired, REFUSE
- `2` — config error (no scope file, malformed yaml)

stdout is JSON:
```json
{
  "target": "acme.com",
  "in_scope": true,
  "engagement_id": "ENG-2026-001",
  "matched_rule": "*.acme.com",
  "authorized_until": "2026-06-01"
}
```

## Behavior on refusal

If `in_scope=false`:
1. Stop immediately.
2. Tell the user the exact target and the matched out-of-scope rule (or "no in-scope rule matched").
3. Do not retry against a different but related target without explicit user approval.

## Scope file format

`/scope/scope.yaml`:
```yaml
engagement_id: ENG-2026-001
authorized_until: 2026-06-01
in_scope:
  - "*.acme.com"
  - "203.0.113.0/24"
out_of_scope:
  - "vpn.acme.com"
  - "203.0.113.5"
```

`out_of_scope` always wins over `in_scope`.

## Resolution order

The script searches for scope.yaml in this order:
1. `$SCOPE_FILE` env var
2. `$ENGAGEMENT_DIR/scope.yaml`
3. `/scope/scope.yaml`
4. `./scope.yaml`

First match wins. If none exist, exit 2 — tell the user to create one.
