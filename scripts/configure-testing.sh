#!/bin/bash
#
# BlockHost testing-mode configuration.
# Runs in-target (chroot into the installed system).
#
# Build-time values (SSH_PUBKEY, APT_PROXY) live in /tmp/late-testing.env,
# copied in by late-testing.sh.
#

LOG=/var/log/blockhost-install.log

if [ -f /tmp/late-testing.env ]; then
    . /tmp/late-testing.env
fi

# Enable SSH root login with password
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    if [ -d /etc/ssh/sshd_config.d ]; then
        echo "PermitRootLogin yes" > /etc/ssh/sshd_config.d/99-testing.conf
    fi
fi

# Add SSH public key for passwordless access
if [ -n "$SSH_PUBKEY" ]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo "SSH public key added to /root/.ssh/authorized_keys" >> "$LOG"
fi

# Set apt proxy for post-install (only if provided at build time)
if [ -n "$APT_PROXY" ]; then
    mkdir -p /etc/apt/apt.conf.d
    echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/00proxy
fi

# Ensure SSH is always accessible in testing mode (bypass pve-firewall).
# Persist across reboots via iptables-persistent rules file.
mkdir -p /etc/iptables
iptables -I INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "blockhost-testing" 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# Create testing mode marker for validation script
mkdir -p /etc/blockhost
touch /etc/blockhost/.testing-mode
chmod 0644 /etc/blockhost/.testing-mode

echo "Testing mode configured" >> "$LOG"
