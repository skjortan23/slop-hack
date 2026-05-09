---
name: web-enum
description: Enumerate a live web target for exposed paths, misconfigurations, default logins, leaked secrets, takeover candidates, and admin panels. Runs nuclei (tags exposures/misconfiguration/default-logins/exposed-panels/takeover), then directory/file fuzzing with ffuf using SecLists. Use after active-recon when you have httpx-confirmed live web hosts. Logs every finding via the findings skill, raw output to $ENGAGEMENT_DIR/recon/web-enum/.
---

# web-enum

Surface web-app config issues and exposed paths against confirmed live hosts.
Pairs with `vuln-search` (which handles CVEs); this skill targets misconfigs,
exposures, default creds, takeover.

## Prerequisites

1. **scope-check** must pass for the target host.
2. `active-recon` should have run — `$ENGAGEMENT_DIR/recon/active/httpx.json`
   gives you the list of live web URLs.
3. Output dir: `mkdir -p $ENGAGEMENT_DIR/recon/web-enum`

## Inputs

- One or more URLs (typically from `httpx.json`'s `.url` field)
- Optional: `severity` floor (`info|low|medium|high|critical`) — default `low`

## Procedure

### 1. nuclei — config / exposure / panel / takeover

The four highest-signal tag sets, run in one command:

```bash
URL_LIST=$ENGAGEMENT_DIR/recon/web-enum/urls.txt
jq -r '.url' $ENGAGEMENT_DIR/recon/active/httpx.json | sort -u > $URL_LIST

nuclei -l $URL_LIST \
  -tags 'exposures,misconfiguration,default-login,exposed-panels,takeover,disclosure' \
  -severity info,low,medium,high,critical \
  -json -silent \
  -rate-limit 100 -bulk-size 25 \
  -o $ENGAGEMENT_DIR/recon/web-enum/nuclei.json
```

Persist each hit:

```bash
jq -c '.' $ENGAGEMENT_DIR/recon/web-enum/nuclei.json | while read line; do
  host=$(echo "$line"     | jq -r '.host // .input // empty' | sed 's|https\?://||;s|/.*||;s|:.*||')
  url=$(echo "$line"      | jq -r '.matched-at // .url // empty')
  port=$(echo "$line"     | jq -r '.port // (if (.url|test("https://")) then "443/tcp" else "80/tcp" end)')
  sev=$(echo "$line"      | jq -r '."info"."severity" // "info"')
  title=$(echo "$line"    | jq -r '."info"."name"     // .template-id // "nuclei finding"')
  templ=$(echo "$line"    | jq -r '.template-id       // empty')
  cve=$(echo "$line"      | jq -r '."info"."classification"."cve-id"[]? // empty' | head -1)

  findings add "$host" --port "$port" \
    --severity "$sev" \
    --title "$title" \
    --evidence "$url (template: $templ)" \
    ${cve:+--cve "$cve"} \
    --source nuclei
done
```

### 2. Targeted exposure checks (high-signal, manual)

These often catch what nuclei templates miss. For each URL:

```bash
TARGET=https://<host>

# Source disclosure
for path in .git/HEAD .git/config .svn/entries .hg/store/00manifest.i \
            .env .env.local .env.production .env.dev \
            .DS_Store \
            .vscode/settings.json .idea/workspace.xml \
            backup.sql backup.zip backup.tar.gz dump.sql \
            wp-config.php.bak config.php.bak \
            phpinfo.php info.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -L "$TARGET/$path" --max-time 5)
  if [ "$code" = "200" ]; then
    findings add "<host>" --port 443/tcp --severity high \
      --title "Source/secret file exposed: $path" \
      --evidence "GET $TARGET/$path -> 200" \
      --source curl
  fi
done

# API spec / introspection
for path in swagger.json swagger-ui.html api-docs openapi.json \
            graphql graphql/console __graphql /api/swagger; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path" --max-time 5)
  [ "$code" = "200" ] && findings add "<host>" --port 443/tcp --severity medium \
    --title "API spec/introspection exposed: $path" \
    --evidence "GET $TARGET/$path -> 200" \
    --source curl
done

# robots / sitemap (info only — useful for path harvesting)
curl -s "$TARGET/robots.txt" --max-time 5 \
  > $ENGAGEMENT_DIR/recon/web-enum/<host>-robots.txt
curl -s "$TARGET/sitemap.xml" --max-time 5 \
  > $ENGAGEMENT_DIR/recon/web-enum/<host>-sitemap.xml
```

### 3. Directory/file fuzzing with ffuf

Pick wordlist by depth wanted. Default to **quickhits** + a small content list:

```bash
WL_QUICK=/usr/share/seclists/Discovery/Web-Content/quickhits.txt
WL_DIRS=/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
WL_FILES=/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt

# Quickhits: ~2k high-signal paths, fast pass
ffuf -u "$TARGET/FUZZ" -w "$WL_QUICK" \
     -mc 200,301,302,401,403 -fs 0 \
     -t 40 -timeout 5 -rate 100 \
     -of json -o $ENGAGEMENT_DIR/recon/web-enum/<host>-quickhits.json -s

# Dirs (only if quickhits found stuff and target seems alive)
ffuf -u "$TARGET/FUZZ/" -w "$WL_DIRS" \
     -mc 200,301,302,401,403 -fs 0 \
     -t 40 -timeout 5 -rate 100 \
     -of json -o $ENGAGEMENT_DIR/recon/web-enum/<host>-dirs.json -s
```

Filter results — skip noise (status 404/403 with same length, common 200 catch-all). ffuf's `-fs <size>` after observing the index page size auto-filters wildcard responses.

For each interesting hit (status 200/401, novel content):

```bash
findings add "<host>" --port 443/tcp --severity low \
  --title "Discovered path: $path" \
  --evidence "GET $TARGET/$path -> $status (len=$length)" \
  --source ffuf
```

Bump severity if the path is a known-sensitive name (`admin`, `console`,
`backup`, `internal`, `debug`, `test`, `dev`, `staging`).

### 4. Default-login attempts (only with explicit user authorization)

Nuclei's `default-login` templates handle this safely — they test ONLY known
default credential pairs against ONLY identified products.

```bash
nuclei -l $URL_LIST \
  -tags default-login \
  -json -silent \
  -o $ENGAGEMENT_DIR/recon/web-enum/nuclei-default-logins.json
```

If a hit fires, log as **critical** and STOP — escalate to user. Don't try
your own credential combos.

```bash
findings add "<host>" --port 443/tcp --severity critical \
  --title "Default credentials accepted: <product>" \
  --evidence "<nuclei output>" \
  --source nuclei
```

### 5. Subdomain takeover candidates

Nuclei `takeover` tag covers most. Cross-check against any CNAME records
from `dnsx.json`:

```bash
nuclei -l $URL_LIST \
  -tags takeover \
  -json -silent \
  -o $ENGAGEMENT_DIR/recon/web-enum/takeover.json
```

Each hit = `high` severity finding (claimable subdomain → full host control
once registered with the upstream service).

## Constraints

- **Rate limits**: stay under 100 req/s per host. ffuf default `-rate 100` is
  fine. Don't go above unless user authorizes.
- **No payload-based attacks here**: no SQLi/XSS payloads, no command
  injection probes. Those live in a separate exploit skill (or run
  `nuclei -tags sqli,xss` only with explicit go-ahead).
- **WAF awareness**: if `cdncheck` flagged the IP as WAF/CDN, expect false
  negatives and rate-limit blocks. Note in findings if responses suddenly
  shift to 403/429.

## Output summary

After completion, report:
- `<n>` nuclei hits by severity bucket
- `<m>` directly-confirmed exposures (.git, .env, swagger)
- `<k>` interesting paths from ffuf (top 10 by status novelty)
- Any critical (default creds, exposed admin without auth, takeover)
- Suggested next move (deeper fuzz on a specific path? exploit search on a
  flagged product?)
