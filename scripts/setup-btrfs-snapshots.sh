#!/bin/bash
# Btrfs snapshot directory setup — runs via in-target (chroot into installed system)

LOG="/var/log/blockhost-install.log"

# Detect the root device (strip btrfs [/subvol] suffix)
ROOT_DEV=$(findmnt -no SOURCE / | sed 's/\[.*$//')
FSTYPE=$(stat -f -c %T /)

if [ -z "$ROOT_DEV" ] || [ "$FSTYPE" != "btrfs" ]; then
    echo "btrfs-setup: root is ${FSTYPE:-unknown}, not btrfs — skipping" >> "$LOG"
    exit 0
fi

# Mount the top-level subvolume (subvolid=5)
mkdir -p /mnt/btrfs-top
mount -o subvolid=5 "$ROOT_DEV" /mnt/btrfs-top

# Create @snapshots directory on the top-level (sibling of @rootfs)
mkdir -p /mnt/btrfs-top/@snapshots
echo "btrfs-setup: created @snapshots on top-level (dev=$ROOT_DEV)" >> "$LOG"

umount /mnt/btrfs-top
