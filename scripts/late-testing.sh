#!/bin/sh
#
# BlockHost preseed late_command — testing-mode additions.
# Invoked by late-install.sh when this file is present on the CDROM
# (i.e. the ISO was built with --testing).
#
# Argument: $1 = path to the CDROM mount.
#

CDROM="$1"

echo "late-testing.sh: starting"

# In-target configure-testing.sh: enable SSH root login, add SSH pubkey,
# set apt proxy, open SSH in iptables, drop the testing-mode marker.
# Build-time values (SSH_PUBKEY, APT_PROXY) live in late-testing.env.
cp "$CDROM/blockhost/scripts/configure-testing.sh" /target/tmp/
cp "$CDROM/blockhost/scripts/late-testing.env" /target/tmp/
in-target /bin/bash /tmp/configure-testing.sh

# In-target btrfs snapshot directory setup (no-op on non-btrfs roots).
cp "$CDROM/blockhost/scripts/setup-btrfs-snapshots.sh" /target/tmp/
in-target /bin/bash /tmp/setup-btrfs-snapshots.sh

# revert/resume CLIs land in the target's /usr/local/bin (not in-target —
# the source files are on the live ISO mount, accessible from the
# installer environment but not from the chroot).
if [ -f "$CDROM/blockhost/scripts/blockhost-revert" ]; then
    cp "$CDROM/blockhost/scripts/blockhost-revert" /target/usr/local/bin/revert
    chmod +x /target/usr/local/bin/revert
fi
if [ -f "$CDROM/blockhost/scripts/blockhost-resume" ]; then
    cp "$CDROM/blockhost/scripts/blockhost-resume" /target/usr/local/bin/resume
    chmod +x /target/usr/local/bin/resume
fi

echo "late-testing.sh: done"
