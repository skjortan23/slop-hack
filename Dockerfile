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
      python3 python3-pip python3-yaml python3-requests pipx \
      golang \
      nodejs npm \
      libpcap-dev \
      nmap masscan whois dnsutils \
      hydra sqlmap gobuster ffuf nuclei amass \
      exploitdb \
      massdns \
      theharvester \
      mitmproxy \
      seclists \
      smbclient enum4linux-ng \
      redis-tools \
      ldap-utils \
      openssl ncat \
      iproute2 procps \
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
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    ; do go install -v "$t"; done

# --- Python tools (pipx) -------------------------------------------------
# theHarvester comes from apt (entrypoint registration broken on PyPI).
RUN pipx install shodan \
    && pipx install arjun \
    && pipx install ssh-audit

# --- supporting data -----------------------------------------------------
RUN mkdir -p /opt/wordlists /opt/resolvers \
    && curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
       -o /opt/resolvers/resolvers.txt

RUN nuclei -update-templates -silent || true

# --- mitmproxy CA: pre-generate + install in system trust ----------------
# Without this, anything inside the container that talks HTTPS through
# mitmproxy (curl, wget, python, ...) gets cert-verification errors.
# Chromium-based tools (katana) still need --ignore-certificate-errors
# because they have their own NSS store.
RUN mkdir -p /root/.mitmproxy \
 && ( mitmdump --listen-port 19999 -q >/dev/null 2>&1 & MPID=$!; \
      sleep 4; kill $MPID 2>/dev/null; wait 2>/dev/null || true ) \
 && [ -f /root/.mitmproxy/mitmproxy-ca-cert.cer ] \
 && cp /root/.mitmproxy/mitmproxy-ca-cert.cer /usr/local/share/ca-certificates/mitmproxy-ca.crt \
 && update-ca-certificates

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
        > /usr/local/bin/scope-check && chmod +x /usr/local/bin/scope-check \
 && printf '#!/bin/sh\nexec python3 /root/.claude/skills/service-enum/service-enum.py "$@"\n' \
        > /usr/local/bin/service-enum && chmod +x /usr/local/bin/service-enum \
 && printf '#!/bin/sh\nexec python3 /root/.claude/skills/webapp-extract/openapi-import.py "$@"\n' \
        > /usr/local/bin/openapi-import && chmod +x /usr/local/bin/openapi-import \
 && chmod +x /root/.claude/skills/service-enum/playbooks/*.sh

# --- mitm-start / mitm-stop: pidfile-based wrappers -----------------------
# Avoids the "pkill -f matches its own parent shell" footgun by tracking
# the mitmdump pid in a file under $ENGAGEMENT_DIR/webapp/.
RUN cat > /usr/local/bin/mitm-start <<'SH' && chmod +x /usr/local/bin/mitm-start
#!/bin/bash
set -u
ENG="${ENGAGEMENT_DIR:-/work/default}"
HOST="${MITM_HOST:-127.0.0.1}"
PORT="${MITM_PORT:-8080}"
mkdir -p "$ENG/webapp"
PIDFILE="$ENG/webapp/mitm.pid"
LOGFILE="$ENG/webapp/mitmdump.log"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "mitmdump already running (pid=$(cat "$PIDFILE"))"
  exit 0
fi

# Truncate the log so we can detect immediate-exit (empty log = startup error)
: > "$LOGFILE"

nohup mitmdump \
  -s /root/.claude/skills/webapp-capture/mitm-addon.py \
  --listen-host "$HOST" --listen-port "$PORT" \
  --set confdir=/root/.mitmproxy \
  > "$LOGFILE" 2>&1 < /dev/null &
PID=$!
echo "$PID" > "$PIDFILE"
sleep 1

# If mitmdump died on startup, surface why.
if ! kill -0 "$PID" 2>/dev/null; then
  echo "mitmdump exited immediately. log:" >&2
  cat "$LOGFILE" >&2
  rm -f "$PIDFILE"
  exit 1
fi

# Wait for proxy to start listening on the port. Don't try to make a real
# request — out-of-scope targets get 403 from our addon, which would look
# like a failure even though the proxy is healthy.
for _ in 1 2 3 4 5 6 7 8; do
  if (exec 3<>/dev/tcp/${HOST}/${PORT}) 2>/dev/null; then
    exec 3<&- 3>&-
    echo "mitm started: pid=$PID  proxy=http://${HOST}:${PORT}"
    exit 0
  fi
  sleep 1
done

echo "mitm failed to come up; tail of $LOGFILE:" >&2
tail -20 "$LOGFILE" >&2
kill "$PID" 2>/dev/null || true
rm -f "$PIDFILE"
exit 1
SH

RUN cat > /usr/local/bin/mitm-stop <<'SH' && chmod +x /usr/local/bin/mitm-stop
#!/bin/bash
ENG="${ENGAGEMENT_DIR:-/work/default}"
PIDFILE="$ENG/webapp/mitm.pid"
if [ -f "$PIDFILE" ]; then
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  rm -f "$PIDFILE"
fi
echo "mitm stopped"
SH

# --- PreToolUse hook: auto-approve Bash, block destructive patterns -------
# Runs before each Bash tool call. Bypasses interactive permission prompts
# entirely (defense-in-depth alongside settings.json bypassPermissions mode).
RUN cat > /usr/local/bin/slop-auto-approve <<'SH' && chmod +x /usr/local/bin/slop-auto-approve
#!/bin/bash
input=$(cat)
cmd=$(echo "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)

# Block obviously destructive patterns
if echo "$cmd" | grep -qE 'rm -rf (/|/etc|/root|/scope|/usr|/var|/home|/opt)|dd if=/dev/(zero|random|urandom)|mkfs\.|^shutdown |^reboot |fork.*bomb|:\(\)\{ :\|:&\};:'; then
  cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"slop-hack: destructive pattern blocked"}}
EOF
  exit 0
fi

# Default: auto-approve
cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
EOF
SH

# --- entrypoint: seed project-level claude config into /work --------------
# Subagents discover settings via the project-tree walk from the engagement
# cwd, NOT via the home-dir path. We force-overwrite on every container start
# so stale local files from prior runs can't pollute permission resolution.
RUN cat > /usr/local/bin/slop-init <<'SH' && chmod +x /usr/local/bin/slop-init
#!/bin/bash
set -e
mkdir -p /work/.claude
cp -f /root/.claude/settings.json /work/.claude/settings.json
cp -f /root/.claude/CLAUDE.md /work/.claude/CLAUDE.md 2>/dev/null || true
# Clear any stale local override that previous interactive sessions may have
# accumulated (would otherwise override our bypass mode).
rm -f /work/.claude/settings.local.json 2>/dev/null || true

# Initialize /work as a git repo so Task subagents can create worktrees if
# they ask for isolation. Without this, dispatching subagents fails with
# "Cannot create agent worktree: not in a git repository".
if [ ! -d /work/.git ]; then
  git -C /work init -q -b main 2>/dev/null
  git -C /work config user.email "agent@slop-hack.local" 2>/dev/null
  git -C /work config user.name  "slop-hack-agent" 2>/dev/null
  # Ignore engagement output and persisted state — they bloat any worktree
  cat > /work/.gitignore <<GITIGN
ENG-*/
.claude/projects/
.claude/todos/
.claude/statsig/
GITIGN
  git -C /work add .gitignore .claude/CLAUDE.md .claude/settings.json 2>/dev/null
  git -C /work commit -q -m "slop-hack init" 2>/dev/null || true
fi

if [ -n "${ENGAGEMENT_DIR:-}" ]; then
  mkdir -p "$ENGAGEMENT_DIR"
  cd "$ENGAGEMENT_DIR"
fi
exec "$@"
SH

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

ENTRYPOINT ["/usr/local/bin/slop-init"]
CMD ["/bin/bash"]
