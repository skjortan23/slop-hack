---
name: slop-engage
description: Hybrid engagement — runs the deterministic chain (slop-engagement) for boilerplate coverage, then drops the agent in with a goal-directed prompt and the populated state. Agent spends every turn on interpretation, deep-dives, and attack chaining instead of remembering to call subfinder. Standard agentic+deterministic pattern (Cursor, GitHub Copilot Workspace, Claude Code itself all do this). Use this as the default front-door for engagements.
---

# slop-engage

Standard front-door for a pentest engagement. Combines:

```
phase 0  deterministic chain     ←  no LLM, fast, gets the coverage data
              ↓
phase 1  agent picks up          ←  every turn on interpretation/deep-dive
              ↓
         goal-directed pentester behavior
```

## Why not just run `slop-engagement` (chain only)?

Because the chain is a **checklist scanner**. It runs every tool against everything, doesn't prioritize, doesn't chain findings, doesn't decide which threads are interesting. That's the boring part of pentest work — a script can do it.

The interesting work — "this host has a wildcard cert covering an Azure tenant, that's a pivot opportunity" / "this webhook accepts arbitrary input AND triggers builds, that's RCE" / "config endpoint exposes DB hostname AND port 5432 is open, that's a chain" — needs a real reasoner.

## Why not just run `claude` straight (agent only)?

Because the agent then burns 20 turns running subfinder, dnsx, quickscan, openapi-import before it has data to reason about. By the time it gets to the interesting bit, it's near max-turns. We've watched this happen.

## The hybrid

`slop-engage` does phase 0 deterministically (5–10 min, populates findings store + service inventory + endpoint inventory + openapi imports), THEN invokes the agent with:
- the populated state already on disk
- an explicit instruction NOT to re-do recon
- a goal ("find high/critical findings")
- pentester-shaped expectations (chain findings, pivot to interesting threads, prioritize)

## Usage

```bash
# default goal: "find high/critical findings"
slop-engage codelight.ai

# with explicit goal
slop-engage codelight.ai --goal "find auth bypasses and RCE candidates"
slop-engage api.example.com --goal "find IDOR and access control gaps"
slop-engage internal.example.com --single-host --goal "lateral movement opportunities"

# skip the agent phase (chain only)
slop-engage codelight.ai --no-agent

# tune agent budget after the chain
slop-engage codelight.ai --max-turns 50
```

## What the agent receives

The post-chain prompt:
- State summary (host count, finding count, endpoint count)
- Engagement dir path
- The goal
- Explicit instruction: don't re-run mechanical recon — that's done
- Suggested starting moves: read findings list, inspect per-host YAMLs, prioritize
- Pentester voice: pivot to interesting threads, log via findings rubric

## Output

```
$ENGAGEMENT_DIR/
├── engagement.log              # phase 0 trace
├── agent-followup-trace.jsonl  # phase 1 trace
├── findings/                   # findings store (both phases append)
├── webapp/                     # endpoints, openapi, fuzz/authcheck results
└── report.md                   # final report (refreshed by agent at end)
```

## When to use chain-only (--no-agent)

- Periodic / scheduled scans where you want consistent output
- Targets you've already deep-dived; just want a coverage refresh
- CI/CD style integrations

## When to use agent-only

- Specific deep-dive on a known finding ("look at /api/foo, is it exploitable?")
- Custom approaches that don't fit the chain
- Interactive pentest work where you're driving via prompts

## Goal phrasing tips

Concrete > vague. The agent picks better tools when the goal is shaped:

- ❌ "do a pentest"
- ✅ "find auth bypasses on the API endpoints in endpoints.jsonl"
- ✅ "look for source / secret disclosure across all hosts"
- ✅ "identify which host has the largest unauth attack surface"
- ✅ "find RCE candidates in webhook + scan endpoints; confirm with webapp-confirm if any look promising"
