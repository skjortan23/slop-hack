#!/usr/bin/env python3
"""service-enum: dispatch a service-specific enumeration playbook.

Usage:
    service-enum <host> <port> [service]

Service detection order:
    1. Explicit `service` arg if provided
    2. The host's findings YAML (services.<port>/<proto>.service)
    3. Banner grab (SSH-/FTP/HTTP/SMTP fingerprints)
    4. /etc/services + /usr/share/nmap/nmap-services lookup
    5. Failure (exit 1)

Each playbook is playbooks/<service>.sh and is invoked as:
    <playbook> <host> <port>

Playbooks are responsible for their own finding logging via the
`findings` CLI.
"""
import os
import socket
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

ENG = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
PLAYBOOKS = Path("/root/.claude/skills/service-enum/playbooks")
SERVICES_FILES = [
    Path("/etc/services"),
    Path("/usr/share/nmap/nmap-services"),
]

# Translate /etc/services or nmap-services names into our playbook filenames
# when they don't match exactly. Anything not in this map is used as-is.
SERVICE_ALIASES = {
    "domain": "dns",
    "domain-s": "dns",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "submission": "smtp",
    "submissions": "smtps",
    "urd": "https",
    "http-alt": "http",
    "https-alt": "https",
    "https-mgmt": "https",
    "secure-mqtt": "mqtt",
    "mqtt-tls": "mqtt",
    "mongod": "mongodb",
    "openvpn": "vpn",
    "ipp": "http",          # Internet Printing — speaks HTTP
    "rfb": "vnc",
    "vnc-server": "vnc",
}

# Cache the parsed port map between calls within one process
_port_map_cache: dict | None = None


def load_port_map() -> dict[tuple[int, str], str]:
    """Parse /etc/services and nmap-services into {(port, proto): service-name}.

    First file wins to avoid overwriting POSIX names with nmap's more obscure
    entries.
    """
    global _port_map_cache
    if _port_map_cache is not None:
        return _port_map_cache

    out: dict[tuple[int, str], str] = {}
    for path in SERVICES_FILES:
        if not path.is_file():
            continue
        try:
            with path.open() as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2 or "/" not in parts[1]:
                        continue
                    name = parts[0].lower()
                    port_str, proto = parts[1].split("/", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue
                    proto = proto.lower()
                    if proto not in ("tcp", "udp"):
                        continue
                    out.setdefault((port, proto), name)
        except OSError:
            continue
    _port_map_cache = out
    return out


def normalize(name: str) -> str:
    """Map raw service names from nmap/etc-services into our playbook names."""
    if not name:
        return ""
    name = name.lower().strip()
    return SERVICE_ALIASES.get(name, name)


def from_findings(host: str, port: int) -> str:
    yaml_file = ENG / "findings" / "hosts" / f"{host}.yaml"
    if not yaml_file.exists() or yaml is None:
        return ""
    try:
        data = yaml.safe_load(yaml_file.read_text()) or {}
    except Exception:
        return ""
    services = data.get("services") or {}
    for key in (f"{port}/tcp", f"{port}/udp"):
        svc = (services.get(key) or {}).get("service")
        if svc:
            return normalize(svc)
    return ""


def from_banner(host: str, port: int) -> str:
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.settimeout(2)
        banner = s.recv(256).decode(errors="ignore")
        s.close()
    except Exception:
        return ""
    upper = banner.upper()
    if banner.startswith("SSH-"):
        return "ssh"
    if "FTP" in upper:
        return "ftp"
    if "HTTP/" in upper:
        return "http"
    if "SMTP" in upper:
        return "smtp"
    if "POP3" in upper:
        return "pop3"
    if "IMAP" in upper:
        return "imap"
    return ""


def from_port_map(port: int) -> str:
    pm = load_port_map()
    name = pm.get((port, "tcp")) or pm.get((port, "udp")) or ""
    return normalize(name)


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: service-enum <host> <port> [service]", file=sys.stderr)
        return 2
    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(f"port must be an integer, got: {sys.argv[2]}", file=sys.stderr)
        return 2

    if len(sys.argv) > 3:
        service = normalize(sys.argv[3])
    else:
        service = (
            from_findings(host, port)
            or from_banner(host, port)
            or from_port_map(port)
        )

    if not service:
        print(
            f"unknown service on {host}:{port} — pass service explicitly "
            f"(e.g. service-enum {host} {port} http)",
            file=sys.stderr,
        )
        return 1

    pb = PLAYBOOKS / f"{service}.sh"
    if not pb.is_file():
        # Fall back to the bare protocol if a TLS variant has no playbook
        # but the cleartext one does (e.g. unknown-tls → http when reflected
        # behaviour is HTTPish).
        print(
            f"no playbook for service: {service} (looked at {pb})\n"
            f"available: " +
            ", ".join(sorted(p.stem for p in PLAYBOOKS.glob("*.sh") if not p.stem.startswith("_"))),
            file=sys.stderr,
        )
        return 1

    os.execv(str(pb), [str(pb), host, str(port)])


if __name__ == "__main__":
    sys.exit(main())
