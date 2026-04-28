#!/bin/sh
#
# BlockHost preseed late_command body — production install.
#
# Runs from the Debian installer environment with stdout/stderr already
# redirected to /target/var/log/blockhost-install.log by the preseed
# late_command.
#
# Argument: $1 = path to the CDROM mount (containing blockhost/ subdir).
#

CDROM="$1"
TARGET=/target/opt/blockhost

echo "late-install.sh: CDROM=$CDROM"

mkdir -p "$TARGET" /target/var/lib/blockhost \
    /target/etc/systemd/system/multi-user.target.wants

# Copy BlockHost payload. Errors are logged via the preseed's redirect but
# never fatal — the build only ships some directories on some configs.
for d in installer admin packages scripts; do
    if [ -d "$CDROM/blockhost/$d" ]; then
        cp -r "$CDROM/blockhost/$d" "$TARGET/"
    else
        echo "Note: $d not present on CDROM, skipping"
    fi
done

# First-boot script
cp "$CDROM/blockhost/first-boot.sh" "$TARGET/"
chmod +x "$TARGET/first-boot.sh"

# Systemd services
cp "$CDROM/blockhost/blockhost-firstboot.service" /target/lib/systemd/system/
cp "$CDROM/blockhost/blockhost-admin.service" /target/lib/systemd/system/

# Enable firstboot via symlink (systemctl enable doesn't work without
# entering the chroot).
ln -sf /lib/systemd/system/blockhost-firstboot.service \
    /target/etc/systemd/system/multi-user.target.wants/blockhost-firstboot.service

echo "Files copied successfully"
ls -la "$TARGET/"

# Testing-mode hook (only present on --testing builds).
if [ -f "$CDROM/blockhost/scripts/late-testing.sh" ]; then
    echo "late-testing.sh found, running..."
    sh "$CDROM/blockhost/scripts/late-testing.sh" "$CDROM"
fi
