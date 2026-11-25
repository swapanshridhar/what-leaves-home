#!/bin/sh
# Install the What Leaves Home agent as a system service on this server.
# What Leaves Home's Services page shows this line with your address and token filled in:
#   curl -fsSL <WL_URL>/install-agent.sh | sudo WL_URL=<WL_URL> WL_TOKEN=<token> sh
# It needs python3. It reads only: the connection table and which process owns each connection.
set -eu
: "${WL_URL:?Set WL_URL to What Leaves Home's address}"
: "${WL_TOKEN:?Set WL_TOKEN to the token on What Leaves Home's Services page}"
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
command -v python3 >/dev/null || { echo "This needs python3. Or use the Docker line instead." >&2; exit 1; }

install -d -m 0755 /opt/whatleaves-agent
curl -fsSL "$WL_URL/whatleaves-agent.py" -o /opt/whatleaves-agent/whatleaves-agent.py
( umask 077; printf 'WL_URL=%s\nWL_TOKEN=%s\n' "$WL_URL" "$WL_TOKEN" > /etc/whatleaves-agent.env )

# The connection table, and the kernel counting bytes per connection (for "data sent").
modprobe nf_conntrack 2>/dev/null || true
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

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
env $(cat /etc/whatleaves-agent.env) python3 /opt/whatleaves-agent/whatleaves-agent.py --once
systemctl enable --now whatleaves-agent >/dev/null
echo "Installed. It reports every 5 minutes. Remove: systemctl disable --now whatleaves-agent; rm -r /opt/whatleaves-agent /etc/whatleaves-agent.env /etc/systemd/system/whatleaves-agent.service"
