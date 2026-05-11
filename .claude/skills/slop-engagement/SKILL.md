---
name: slop-engagement
description: Deterministic end-to-end engagement chain — runs passive-recon → dnsx → quickscan → openapi-import → endpoint-authcheck → webapp-fuzz (nuclei DAST) → vuln-check → findings export-md in fixed order, bounded by timeouts at each step. Removes the LLM from the orchestration critical path; the playbook is bash, the LLM only reasons about individual findings afterward. Use when you want a reliable full engagement run that doesn't depend on the model remembering 7-phase prompts.
---

# slop-engagement

Single-command end-to-end engagement chain. **No LLM in the orchestration
loop** — the playbook is a deterministic bash script. The LLM is only
invoked for individual reasoning (interpreting a specific finding,
deciding follow-up). This matters because qwen36 (and most local models)
suffer plan-drift on 5+ phase prompts — even GPT-4 / Claude Opus do
occasionally.

## Usage

```bash
# Full engagement against a root domain (passive enum → all phases)
slop-engagement codelight.ai

# Single-host (skip passive subdomain enum)
slop-engagement dev.codelight.ai --single-host

# Skip the webapp fuzz/confirm chain
slop-engagement codelight.ai --no-webapp

# Depth control
slop-engagement codelight.ai --depth shallow   # quickscan 80/443/8080/8443 only
slop-engagement codelight.ai --depth normal    # default (~80 pentest ports)
slop-engagement codelight.ai --depth deep      # full port sweep + theHarvester
```

## Pipeline phases

```
scope-check
  ↓
[1] passive recon       — subfinder + amass passive + crt.sh
  ↓                       (skipped in --single-host mode)
[2] dnsx                — narrow to live hosts
  ↓                       writes findings host-set per host
[3] quickscan           — port + service inventory across all live hosts
  ↓                       writes findings service-set per (host, port, product, version)
[4] webapp pipeline     — for each web host:
                           - curl /openapi.json → openapi-import
                           - endpoint-authcheck (unauth probe)
                           - nuclei -dast (injection candidates)
  ↓
[5] vuln-check          — for every (host, port, product, version) from inventory
  ↓                       → matches nuclei CVE templates + searchsploit
[6] findings export-md  → $ENGAGEMENT_DIR/report.md
```

Every phase is bounded by `timeout` so a slow tool can't stall the whole
run. Failures in individual phases don't abort the chain — they're logged
and the next phase continues.

## Why deterministic?

Empirically, on a multi-phase prompt:
- Phase 1-2 (recon): qwen36 reliably runs these
- Phase 3-4 (orchestration): plan drift kicks in, model improvises
- Phase 5-6 (synthesis): often hits max-turns mid-summary, result=null

The same 5 minutes of bash:
- runs every phase deterministically
- writes findings.jsonl that's consumable for reporting
- doesn't depend on the model remembering "step 7: export-md"

The LLM's strengths (severity reasoning, false-positive detection, deciding
what to dig deeper on) are still used — just not for "remember to call
this tool next."

## Output layout

```
$ENGAGEMENT_DIR/
├── engagement.log              # full stdout from the chain
├── recon/
│   ├── passive/{subfinder,amass,crtsh,harvester}.txt
│   └── active/{dnsx.txt, live-hosts.txt, quickscan/, naabu.json, httpx.json}
├── webapp/
│   ├── <host>-openapi.json    # per host where exposed
│   ├── endpoints.jsonl
│   ├── authcheck-results.jsonl
│   ├── fuzz-urls.txt
│   └── dast.json
├── findings/
│   ├── hosts/<host>.yaml      # per-host service inventory + findings
│   └── findings.jsonl         # append-only audit log
└── report.md                  # findings export-md output
```

## When NOT to use this

- When you want LLM-driven exploration (specific deep-dives on one host)
- When you have an unusual target where the standard chain doesn't apply
- When you want to invoke specific skills only

For those, drive `claude` interactively or via `claude -p` with focused
single-skill prompts.

## Where the LLM still belongs

After this chain finishes, run claude on the result for interpretation:

```bash
slop-engagement codelight.ai
claude -p "Read $ENGAGEMENT_DIR/report.md and tell me:
1. Which findings are most likely real (vs noise)?
2. What's the most impactful one to pursue first?
3. Any combinations of findings that chain together?"
```

That's the LLM doing what it's actually good at — reasoning over structured
data — instead of trying to remember 7-phase playbooks across 30 turns.
