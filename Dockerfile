# slop-hack: agentic pentest container
# Base: Kali rolling (broad apt coverage, recent userspace).
# Strategy:
#   - apt for stable infra tools and Node.js
#   - go install for ProjectDiscovery (Kali apt lags)
#   - pipx for Python tools
#   - npm -g for Claude Code CLI

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/root/go \
    GOBIN=/root/go/bin \
    PATH=/root/go/bin:/root/.local/bin:/usr/local/go/bin:$PATH \
    PIPX_HOME=/root/.local/pipx \
    PIPX_BIN_DIR=/root/.local/bin

# --- system tools (apt) --------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq \
      python3 python3-pip python3-yaml pipx \
      golang \
      nodejs npm \
      libpcap-dev \
      nmap masscan whois dnsutils \
      hydra sqlmap gobuster ffuf nuclei amass \
      exploitdb \
      massdns \
      theharvester \
      seclists \
    && rm -rf /var/lib/apt/lists/* \
    && pipx ensurepath

# --- Claude Code CLI (npm) -----------------------------------------------
RUN npm install -g @anthropic-ai/claude-code

# --- ProjectDiscovery + other go tools -----------------------------------
RUN set -eux; \
    for t in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest \
      github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
      github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
      github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest \
      github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
      github.com/d3mondev/puredns/v2@latest \
      github.com/lc/gau/v2/cmd/gau@latest \
      github.com/tomnomnom/waybackurls@latest \
      github.com/projectdiscovery/cvemap/cmd/vulnx@latest \
    ; do go install -v "$t"; done

# --- Python tools (pipx) -------------------------------------------------
# theHarvester comes from apt (entrypoint registration broken on PyPI).
RUN pipx install shodan

# --- supporting data -----------------------------------------------------
RUN mkdir -p /opt/wordlists /opt/resolvers \
    && curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
       -o /opt/resolvers/resolvers.txt

RUN nuclei -update-templates -silent || true

# --- skills, agents, settings, standing instructions ---------------------
# Skills live globally so `claude` finds them no matter the working directory.
COPY .claude/skills /root/.claude/skills
COPY .claude/agents /root/.claude/agents
# Pre-approved tool allowlist so the agent isn't asking permission for every
# subfinder/dnsx/nmap call. scope-check is the real safety boundary.
COPY .claude/settings.json /root/.claude/settings.json
# Standing operator brief: mission, hard rules, tool inventory, severity rubric.
COPY .claude/CLAUDE.md /root/.claude/CLAUDE.md

# Wrapper so SKILL docs can say "findings ..." / "scope-check ..." instead of
# the full python path.
RUN printf '#!/bin/sh\nexec python3 /root/.claude/skills/findings/findings.py "$@"\n' \
        > /usr/local/bin/findings && chmod +x /usr/local/bin/findings \
 && printf '#!/bin/sh\nexec python3 /root/.claude/skills/scope-check/check.py "$@"\n' \
        > /usr/local/bin/scope-check && chmod +x /usr/local/bin/scope-check

# --- engagement layout ---------------------------------------------------
# /scope    — read-only mount: scope.yaml + API key configs
# /work     — read-write: per-engagement output, findings, evidence
RUN mkdir -p /scope /work
WORKDIR /work

# --- LLM endpoint --------------------------------------------------------
# Modern vLLM exposes the Anthropic Messages API directly at /v1/messages,
# so Claude Code can talk to it without a translator. Override the model id
# and base URL at runtime via compose env vars.
ENV ANTHROPIC_BASE_URL=http://host.docker.internal:8000 \
    ANTHROPIC_MODEL=local-model

CMD ["/bin/bash"]
