# slop-hack

Agentic pentest framework — Claude Code running inside a Kali container with
a fixed toolset, scope guard, and structured findings logger. Driven by an
external (local) LLM via vLLM + an Anthropic-format translator.

## Architecture

```
┌─────────────────┐         ┌────────────────────────────────┐
│  vLLM           │ Anthropic│  slop-hack container          │
│  (host)         │◀────────│  - claude (CLI)                │
│  :8000          │ /v1/    │  - skills: scope-check,        │
│  /v1/messages   │ messages│    findings, passive-recon,    │
└─────────────────┘         │    active-recon                │
                            │  - tools: nmap, subfinder, …   │
                            │  /scope (ro)  /work (rw)       │
                            └────────────────────────────────┘
```

Modern vLLM exposes `/v1/messages` natively, so Claude Code talks to it
without a translator in between.

## One-time setup

1. **Start vLLM on the host** with the model you want to drive the agent:

   ```bash
   vllm serve <model-id> --port 8000
   ```

   Note the model id you served — you'll pass it as `ANTHROPIC_MODEL`.

2. **Build the image.**

   ```bash
   colima start --cpu 4 --memory 8 --disk 40
   docker compose build
   ```

3. **Define an engagement scope.** Edit `scope/scope.yaml`:

   ```yaml
   engagement_id: ENG-2026-001
   authorized_until: 2026-06-01
   in_scope:
     - "*.acme.com"
     - "203.0.113.0/24"
   out_of_scope:
     - "vpn.acme.com"
   ```

4. **(Optional) Provide API keys** for richer passive recon. Put them in
   `pd-config/subfinder/provider-config.yaml` (see ProjectDiscovery docs) and
   set env vars in the shell before running compose:

   ```bash
   export SHODAN_API_KEY=...
   export CHAOS_KEY=...
   export GITHUB_TOKEN=...
   ```

## Run

```bash
ENGAGEMENT_ID=ENG-2026-001 \
VLLM_PORT=8000 \
ANTHROPIC_MODEL=<the-model-id-vllm-served> \
  docker compose run --rm slop-hack
```

Inside the container:

```bash
claude          # starts Claude Code against the local translator
```

Then drive the agent in natural language:

> Do passive recon on acme.com.
> Now find live web hosts and open ports.
> Generate the engagement report.

The agent picks up skills from `/root/.claude/skills/` automatically based on
their `description:` frontmatter.

## Skills

| Skill | Purpose |
|---|---|
| **scope-check** | Hard gate. Validates target against `scope.yaml`. Every other skill calls this first. |
| **findings** | Persists hosts/services/findings as per-host YAML + a JSONL audit log. Markdown export. |
| **passive-recon** | subfinder, amass, chaos, crt.sh, asnmap, whois, waybackurls, gau, theHarvester, shodan. No packets to target. |
| **active-recon** | dnsx, cdncheck, httpx, tlsx, naabu, nmap, katana. Sends packets. |

## Direct CLI usage (without the agent)

The skill helpers are on `$PATH` inside the container:

```bash
scope-check api.acme.com
# {"target":"api.acme.com","in_scope":true,"engagement_id":"ENG-2026-001",...}

findings host-set api.acme.com --hostname api.acme.com --asn AS13335
findings service-set api.acme.com 443/tcp --service https --product nginx --version 1.24.0
findings add api.acme.com --port 443/tcp --severity high \
  --title "Exposed .git directory" \
  --evidence "https://api.acme.com/.git/HEAD returns 200" \
  --source nuclei

findings list
findings export-md > /work/$ENGAGEMENT_ID/report.md
```

## Filesystem layout

```
/scope/                                       # ro — engagement authorization
└── scope.yaml

/work/$ENGAGEMENT_ID/                         # rw — per-engagement output
├── recon/
│   ├── passive/                              # raw tool output
│   └── active/
└── findings/
    ├── hosts/<host>.yaml                     # one yaml per host
    └── findings.jsonl                        # append-only audit log
```

## Adding tools or skills

- **A new tool**: append to the apt or `go install` list in `Dockerfile`.
- **A new skill**: drop `SKILL.md` (with `name` + `description` frontmatter)
  into `.claude/skills/<name>/`. Helpers go alongside it. Rebuild the image
  to bake them in.

## Safety notes

- The container runs as root with `NET_RAW` to allow SYN scans. Don't expose
  it to untrusted networks.
- Scope is enforced in skills, not at the kernel level. A misbehaving agent
  could still send packets to anything reachable. For hard isolation, run
  the container on a dedicated network namespace or VPN-scoped interface.
- `out_of_scope` rules always win over `in_scope`. Re-run `scope-check` on
  every host discovered via SAN/CNAME pivots before probing further.
