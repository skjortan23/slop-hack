#!/usr/bin/env python3
"""quickscan: rapid port sweep + service inventory population across one or
many hosts. naabu only — no nmap (too many timeouts and retry weirdness for
simple coverage scanning). HTTP/HTTPS ports enriched via httpx for banner
and tech detection.

Usage:
    quickscan <host>...                  # default top pentest port set
    quickscan -l hosts.txt
    quickscan -p 22,80,443 <host>...     # explicit ports
    quickscan --full <host>...           # 1-65535 (slow, masscan-style sweep)
    quickscan --no-log                   # skip findings calls (print only)
    quickscan --no-http                  # skip httpx enrichment

Pipeline:
    1. naabu --rate 1000 against all targets in parallel for the port set
    2. For HTTP/HTTPS ports: httpx fingerprint (status, title, tech, server)
    3. findings host-set + service-set per (host, port) with whatever info
       we collected (service name from port→name table, plus product/version
       from httpx where available)
    4. Print summary table (or JSON)

Designed for use after passive-recon to give one-shot coverage of common
service ports across all discovered subdomains in seconds-not-minutes.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ENG_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "/work/default"))
QS_DIR = ENG_DIR / "recon" / "quickscan"

# Curated pentest port list — common services worth a coverage sweep.
# Ordered roughly by frequency-of-presence across attack surfaces.
DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,"
    "465,514,587,623,636,993,995,1080,"
    # Databases (RDBMS, NoSQL, time-series, columnar)
    "1433,1521,1830,2483,2484,3306,5432,33060,"  # mssql, oracle (+alt+ssl), mysql (+x-proto)
    "5984,6379,6380,7474,7687,"                  # couchdb, redis (+tls), neo4j (+bolt)
    "8086,8123,9042,9160,11211,"                 # influxdb, clickhouse, cassandra (native+thrift), memcached
    "26257,27017,27018,27019,28015,28017,28018," # cockroachdb, mongodb (+http+rethinkdb)
    # Message brokers / queues
    "5672,9092,15672,"
    # Web / proxy / dev tools
    "1723,2049,2082,2083,2087,2096,2222,2375,2376,3000,3128,3268,"
    "3389,4443,4444,4500,4848,4949,5000,5060,5601,5900,5985,"
    "6443,7000,7001,7077,8000,8005,8009,8020,8022,8080,8081,"
    "8088,8090,8091,8161,8200,8443,8500,8530,8531,8649,8888,"
    "9000,9001,9043,9080,9090,9100,9200,9300,9418,9990,9999,"
    "10000,16379,26379,49152,50000,50070,50090"
)

# Fallback service-name mapping when no other info available.
PORT_TO_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "smb", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "smtp", 623: "ipmi", 636: "ldaps",
    993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1830: "oracle",
    2049: "nfs", 2222: "ssh", 2375: "docker", 2376: "docker",
    2483: "oracle", 2484: "oracle",
    3000: "http", 3128: "http-proxy", 3268: "ldap-gc", 3306: "mysql",
    3389: "rdp", 4443: "https", 4848: "glassfish", 4949: "munin",
    5000: "http", 5060: "sip", 5432: "postgres", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 5985: "winrm",
    6379: "redis", 6380: "redis", 6443: "k8s-api",
    7000: "http", 7001: "weblogic", 7077: "spark", 7474: "neo4j",
    7687: "neo4j-bolt",
    8000: "http", 8005: "tomcat", 8009: "ajp", 8020: "hadoop-hdfs",
    8022: "ssh", 8080: "http", 8081: "http", 8086: "influxdb",
    8088: "http", 8090: "http", 8091: "couchbase",
    8123: "clickhouse", 8161: "activemq",
    8200: "vault", 8443: "https", 8500: "consul", 8530: "wsus",
    8649: "ganglia", 8888: "http",
    9000: "http", 9001: "supervisor", 9042: "cassandra",
    9043: "websphere", 9080: "http", 9090: "http",
    9092: "kafka", 9100: "jetdirect", 9160: "cassandra-thrift",
    9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    9990: "wildfly", 9999: "http",
    10000: "webmin", 11211: "memcached",
    15672: "rabbitmq", 16379: "redis-cluster",
    26257: "cockroachdb", 26379: "redis-sentinel",
    27017: "mongodb", 27018: "mongodb", 27019: "mongodb",
    28015: "rethinkdb", 28017: "mongodb-http", 28018: "rethinkdb",
    33060: "mysql-x",
    49152: "wmi-rpc", 50000: "sap",
    50070: "hadoop-hdfs-web", 50090: "hadoop-hdfs-secondary",
}


def run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def naabu_scan(target_file, ports, rate=300):
    QS_DIR.mkdir(parents=True, exist_ok=True)
    out = QS_DIR / "naabu.json"
    out.unlink(missing_ok=True)

    args = [
        "naabu",
        "-l", str(target_file),
        "-p", ports,
        "-rate", str(rate),
        "-c", "25",
        "-silent", "-json",
        "-o", str(out),
    ]
    print(f"[naabu] -p <{len(ports.split(','))} ports> -rate {rate}", file=sys.stderr)
    rc, _, err = run(args, timeout=600)
    if rc != 0:
        print(f"naabu rc={rc}: {err.strip()[:200]}", file=sys.stderr)

    hits = []
    if out.exists():
        with open(out) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    hits.append({
                        "host": r.get("host") or r.get("ip"),
                        "ip": r.get("ip"),
                        "port": int(r["port"]),
                        "proto": r.get("protocol", "tcp"),
                        "tls": r.get("tls", False),
                    })
                except Exception:
                    continue
    return hits


def httpx_enrich(http_hits):
    """For HTTP/HTTPS ports, fingerprint via httpx for product+banner info."""
    if not http_hits:
        return {}

    QS_DIR.mkdir(parents=True, exist_ok=True)
    in_file = QS_DIR / "httpx-input.txt"
    out_file = QS_DIR / "httpx.json"
    out_file.unlink(missing_ok=True)

    with open(in_file, "w") as f:
        for h in http_hits:
            scheme = "https" if h["tls"] or h["port"] in (443, 8443, 4443) else "http"
            f.write(f"{scheme}://{h['host']}:{h['port']}\n")

    args = [
        "httpx",
        "-l", str(in_file),
        "-title", "-tech-detect", "-server", "-status-code",
        "-no-color", "-silent", "-json",
        "-timeout", "15",
        "-o", str(out_file),
    ]
    print(f"[httpx] {len(http_hits)} HTTP endpoints", file=sys.stderr)
    rc, _, _ = run(args, timeout=300)

    by_target = {}
    if out_file.exists():
        with open(out_file) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    # Key by (host, port) since httpx normalizes URLs
                    # (drops :443 from https, :80 from http)
                    host = r.get("host") or r.get("input", "")
                    port = r.get("port", "")
                    try:
                        port = int(port)
                    except (ValueError, TypeError):
                        continue
                    by_target[(host, port)] = {
                        "title": r.get("title", ""),
                        "tech": r.get("tech") or [],
                        "server": r.get("webserver", "") or r.get("server", ""),
                        "status": r.get("status_code"),
                    }
                except Exception:
                    continue
    return by_target


def log_to_findings(host, port, proto, *, service=None, product=None, version=None, banner=None):
    subprocess.run(
        ["findings", "host-set", host, "--hostname", host],
        check=False, capture_output=True, timeout=10,
    )
    args = ["findings", "service-set", host, f"{port}/{proto}"]
    if service: args += ["--service", service]
    if product: args += ["--product", product]
    if version: args += ["--version", version]
    if banner:  args += ["--banner", banner[:200]]
    subprocess.run(args, check=False, capture_output=True, timeout=10)


def main() -> int:
    ap = argparse.ArgumentParser(prog="quickscan")
    ap.add_argument("targets", nargs="*")
    ap.add_argument("-l", "--list")
    ap.add_argument("-p", "--ports", help="explicit port list (overrides default)")
    ap.add_argument("--full", action="store_true", help="full 1-65535 sweep (slow)")
    ap.add_argument("--rate", type=int, default=300,
                    help="packets per second (default 300; higher rates may trip upstream WAF/firewall rate limits)")
    ap.add_argument("--no-log", action="store_true")
    ap.add_argument("--no-http", action="store_true", help="skip httpx enrichment")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.list:
        with open(args.list) as f:
            targets += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    targets = sorted(set(targets))
    if not targets:
        ap.error("no targets — pass hostnames or -l <file>")

    QS_DIR.mkdir(parents=True, exist_ok=True)
    target_file = QS_DIR / "targets.txt"
    target_file.write_text("\n".join(targets) + "\n")

    if args.full:
        ports = "1-65535"
    elif args.ports:
        ports = args.ports
    else:
        ports = DEFAULT_PORTS

    hits = naabu_scan(target_file, ports, rate=args.rate)

    # Group HTTP/HTTPS-likely ports for httpx enrichment
    http_ports = {80, 443, 8000, 8080, 8081, 8088, 8443, 8888, 9000, 9080, 9090, 9200, 5000, 5601, 7474, 8500}
    http_hits = [h for h in hits if h["port"] in http_ports or h["tls"]]

    # Cloudflare/WAF fronted hosts often drop naabu's CONNECT scan but still
    # respond to HTTP probes. So always run httpx independently on common
    # web ports for every target, and merge those into the hits set.
    if not args.no_http:
        web_probe_ports = [80, 443, 8080, 8443, 8000, 8888]
        for target in targets:
            for port in web_probe_ports:
                tls = port in (443, 8443)
                stub = {"host": target, "ip": target, "port": port, "proto": "tcp", "tls": tls}
                if any(h["host"] == target and h["port"] == port for h in http_hits):
                    continue
                http_hits.append(stub)

    enrich = {} if args.no_http else httpx_enrich(http_hits)

    # Merge httpx-confirmed ports back into hits if naabu missed them but
    # httpx got a response — those are real reachable services.
    seen = {(h["host"], h["port"]) for h in hits}
    for h in http_hits:
        key = (h["host"], h["port"])
        if key in enrich and key not in seen:
            hits.append(h)
            seen.add(key)

    services_logged = []
    for h in hits:
        host, port, proto = h["host"], h["port"], h["proto"]
        service = PORT_TO_SERVICE.get(port, "")
        product = ""
        version = ""
        banner = ""

        # Match this hit to its httpx enrichment
        if (host, port) in enrich:
            e = enrich[(host, port)]
            if e.get("server"):
                # "nginx/1.24.0" → product=nginx, version=1.24.0
                srv = e["server"]
                if "/" in srv:
                    p, _, v = srv.partition("/")
                    product = p
                    version = v.split(" ")[0]
                else:
                    product = srv
            if e.get("tech") and not product:
                product = e["tech"][0]
            banner_bits = []
            if e.get("server"): banner_bits.append(e["server"])
            if e.get("title"): banner_bits.append(f'title="{e["title"][:60]}"')
            if e.get("status"): banner_bits.append(f'status={e["status"]}')
            if banner_bits:
                banner = " ".join(banner_bits)

        services_logged.append({
            "host": host, "port": port, "proto": proto,
            "service": service, "product": product, "version": version,
            "banner": banner,
        })

        if not args.no_log:
            log_to_findings(host, port, proto,
                            service=service or None,
                            product=product or None,
                            version=version or None,
                            banner=banner or None)

    summary = {
        "targets": len(targets),
        "open_ports": len(hits),
        "http_enriched": len(enrich),
        "logged_to_findings": (not args.no_log),
        "services": services_logged,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print()
        print(f"{'host':<32} {'port':<8} {'service':<10} {'product':<22} {'version':<14}")
        print("-" * 90)
        for s in services_logged:
            print(f"{s['host'][:32]:<32} {(str(s['port'])+'/'+s['proto'][:3]):<8} "
                  f"{s['service'][:10]:<10} {s['product'][:22]:<22} {s['version'][:14]:<14}")
        print("-" * 90)
        print(f"{summary['open_ports']} open ports across {summary['targets']} target(s), "
              f"http_enriched={summary['http_enriched']}, "
              f"logged={summary['logged_to_findings']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
