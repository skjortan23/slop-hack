---
name: origin-trace
description: Discover the real origin IP behind a CDN/WAF using free-only techniques — subfinder + crt.sh enumeration looking for non-CDN-IP subdomains, common-origin-subdomain probe (direct./origin./dev./staging./cpanel./mail./etc), MX lookup (mail servers rarely behind CDN), and host-header bypass confirmation. Returns candidate origin IPs with evidence. For higher-fidelity discovery (API-keyed sources like Shodan/Censys/SecurityTrails cert search), set those keys and use them separately — this skill stays in the free tier.
---

# origin-trace

When a target is behind Cloudflare/Akamai/etc, public DNS only returns CDN
edge IPs — the real origin is hidden. This skill tries to discover the
origin using techniques that don't require API keys.

## Usage

```bash
origin-trace dev.example.com
origin-trace dev.example.com --no-bruteforce     # skip common-sub probe
origin-trace dev.example.com --json              # structured output
```

## Techniques chained

1. **subfinder + crt.sh**: passive subdomain enumeration. Some forgotten
   staging / dev subdomain might bypass the CDN.
2. **Common-origin subdomain probe**: tries ~50 likely names
   (`direct.`, `origin.`, `dev.`, `staging.`, `cpanel.`, `vpn.`, `mail.`,
   `ftp.`, `monitor.`, `git.`, etc.).
3. **dnsx + cdncheck**: resolves every candidate, filters out IPs in known
   CDN/WAF ranges. Anything non-CDN goes to step 5.
4. **MX records**: dig for MX hosts, resolve them. Mail infrastructure
   rarely sits behind a CDN.
5. **Host-header bypass confirmation**: for each candidate IP, send
   `Host: target.example.com` and compare response hash/length to the
   target's CDN-fronted baseline. Match = confirmed origin.

## Output

When run without `--json`:
```
=== origin-trace: target.example.com ===
Public IPs: [104.21.55.66, 172.67.180.40]
CDN detected: cloudflare
Subdomains examined: 84 (crt.sh: 32, brute: 52)
Subdomains with non-CDN IPs: 1
  vpn.target.example.com → 195.201.42.66

MX records:
  10 mx1.target.example.com
  20 mx2.target.example.com

*** CANDIDATE ORIGIN IPs (Host-header bypass succeeded):
  ★ 195.201.42.66 via vpn.target.example.com — exact body match
```

## What it WON'T find

- Origins where every subdomain is also CDN-proxied
- Origins where mail is on a third party (Google Workspace / Office 365)
- Origins with TLS certificate filtering at the firewall (rejecting
  Host-header-without-SNI requests)
- Origins that require origin-pull authentication

For those, add Shodan/Censys/SecurityTrails API keys and search by
certificate hash or organization name. That's a separate red-team
workflow we haven't automated yet.

## Real-world example

Ran against `codelight.ai` / `dev.codelight.ai`:
- Subfinder + crt.sh: 12 subs found, **all** resolved to Cloudflare IPs
- Common-sub probe: every name caught by Cloudflare's wildcard
- MX: `smtp.google.com` — origin not at Google
- Host-header bypass: no candidate IPs to probe

Result: clean miss → operator's CF deployment is correctly hiding the
origin. (This is a positive security signal for the defender.)
