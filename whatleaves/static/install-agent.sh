#!/bin/sh
# Install the What Leaves Home agent as a system service on this server.
# What Leaves Home's Services page shows the line to run, with your address and token filled in.
# It fetches this script, and then the agent, over HTTPS: from GitHub, pinned to a release, or
# from your What Leaves Home when you open its page over HTTPS. The agent is run only if its
# SHA-256 matches the one below, so a changed copy is refused.
# It needs python3. It reads only: the connection table and which process owns each connection.
set -eu
AGENT_VERSION=0.8.0
AGENT_SHA256=3d4be6f65da51ac372721d1746b69a4916cd0ce755b7f5fdbf839217c8732dc1
AGENT_FROM="${WL_AGENT_FROM:-https://raw.githubusercontent.com/swapanshridhar/what-leaves-home/v$AGENT_VERSION/whatleaves/static}"
: "${WL_URL:?Set WL_URL to What Leaves Home's address}"
: "${WL_TOKEN:?Set WL_TOKEN to the token on What Leaves Home's Services page}"
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
command -v python3 >/dev/null || { echo "This needs python3. Or use the Docker line instead." >&2; exit 1; }

case "$AGENT_FROM" in https://*) ;; *) echo "WL_AGENT_FROM must be an https:// address." >&2; exit 1 ;; esac
command -v sha256sum >/dev/null || { echo "This needs sha256sum (coreutils)." >&2; exit 1; }

install -d -m 0755 /opt/whatleaves-agent
tmp=$(mktemp)
curl -fsSL --proto '=https' "$AGENT_FROM/whatleaves-agent.py" -o "$tmp"
if [ "$(sha256sum "$tmp" | cut -d' ' -f1)" != "$AGENT_SHA256" ]; then
  rm -f "$tmp"
  echo "The agent downloaded from $AGENT_FROM doesn't match version $AGENT_VERSION's checksum. Not installing." >&2
  exit 1
fi
install -m 0644 "$tmp" /opt/whatleaves-agent/whatleaves-agent.py
rm -f "$tmp"
( umask 077; printf 'WL_URL=%s\nWL_TOKEN=%s\n' "$WL_URL" "$WL_TOKEN" > /etc/whatleaves-agent.env )

# The connection table, and the kernel counting bytes per connection (for "data sent").
modprobe nf_conntrack 2>/dev/null || true
if [ ! -e /proc/net/nf_conntrack ] && ! command -v conntrack >/dev/null; then
  # Some kernels (Raspberry Pi OS, for one) don't offer /proc/net/nf_conntrack; the conntrack tool reads the same table.
  if command -v apt-get >/dev/null; then
    echo "This kernel has no /proc/net/nf_conntrack; installing the conntrack tool to read the connection table"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq conntrack >/dev/null
  elif command -v apk >/dev/null; then
    apk add -q conntrack-tools
  else
    echo "Install the conntrack tool (it reads the connection table on this kernel), then run this again." >&2; exit 1
  fi
fi
if [ "$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null || echo 0)" != 1 ]; then
  echo "Turning on per-connection byte counts (net.netfilter.nf_conntrack_acct=1; undo: delete /etc/sysctl.d/90-whatleaves-agent.conf)"
  echo net.netfilter.nf_conntrack_acct=1 > /etc/sysctl.d/90-whatleaves-agent.conf
  sysctl -q -w net.netfilter.nf_conntrack_acct=1 || true
fi

cat > /etc/systemd/system/whatleaves-agent.service <<UNIT
[Unit]
Description=What Leaves Home agent (which service opened each connection)
After=network-online.target docker.service
Wants=network-online.target

[Service]
EnvironmentFile=/etc/whatleaves-agent.env
ExecStart=/usr/bin/env python3 /opt/whatleaves-agent/whatleaves-agent.py
Restart=always
RestartSec=30
ProtectHome=yes
ProtectSystem=strict
NoNewPrivileges=yes
PrivateTmp=yes
# Root, but only what it needs: the connection table (NET_ADMIN), which process owns
# each socket (SYS_PTRACE, DAC_READ_SEARCH). Nothing to change files, users or the network.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
( set -a; . /etc/whatleaves-agent.env; set +a; python3 /opt/whatleaves-agent/whatleaves-agent.py --once )
systemctl enable --now whatleaves-agent >/dev/null
echo "Installed. It reports every 5 minutes. Remove: systemctl disable --now whatleaves-agent; rm -r /opt/whatleaves-agent /etc/whatleaves-agent.env /etc/systemd/system/whatleaves-agent.service"
