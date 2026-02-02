"""
Boot medium detection for BlockHost installer.

Determines whether the system is booting from:
- ISO (live environment)
- USB live
- Fresh HDD installation (first boot)
- Existing HDD installation
"""

import os
import subprocess
from enum import Enum
from pathlib import Path
from typing import Optional


class BootMedium(Enum):
    """Detected boot medium type."""
    ISO = "iso"
    USB_LIVE = "usb-live"
    HDD_FRESH = "hdd-fresh"
    HDD_INSTALLED = "hdd-installed"
    UNKNOWN = "unknown"


def _check_cmdline() -> dict:
    """Parse /proc/cmdline for boot indicators."""
    result = {
        'is_live': False,
        'boot_medium': None,
    }

    try:
        cmdline = Path('/proc/cmdline').read_text()

        # Proxmox live ISO indicators
        if 'boot=live' in cmdline or 'proxinstall' in cmdline:
            result['is_live'] = True

        # Check for root device hints
        if 'root=/dev/sr' in cmdline or 'root=/dev/loop' in cmdline:
            result['boot_medium'] = 'optical'
        elif 'root=/dev/sd' in cmdline or 'root=/dev/nvme' in cmdline:
            result['boot_medium'] = 'disk'

    except Exception:
        pass

    return result


def _check_mounts() -> dict:
    """Check /proc/mounts for filesystem indicators."""
    result = {
        'has_squashfs': False,
        'has_overlay': False,
        'root_fstype': None,
    }

    try:
        mounts = Path('/proc/mounts').read_text()

        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                mountpoint, fstype = parts[1], parts[2]

                if fstype == 'squashfs':
                    result['has_squashfs'] = True
                if fstype == 'overlay' and mountpoint == '/':
                    result['has_overlay'] = True
                if mountpoint == '/':
                    result['root_fstype'] = fstype

    except Exception:
        pass

    return result


def _check_proxmox_markers() -> dict:
    """Check for Proxmox-specific files and markers."""
    result = {
        'is_proxmox': False,
        'pve_version': None,
        'is_installed': False,
    }

    # Check if Proxmox is present
    pve_release = Path('/etc/pve-release')
    if pve_release.exists():
        result['is_proxmox'] = True
        try:
            result['pve_version'] = pve_release.read_text().strip()
        except Exception:
            pass

    # Alternative check
    if Path('/usr/bin/pvesh').exists():
        result['is_proxmox'] = True

    # Check for completed installation markers
    # These are created after successful Proxmox installation
    install_markers = [
        '/var/lib/pve-cluster/.members',
        '/etc/pve/corosync.conf',
    ]

    for marker in install_markers:
        if Path(marker).exists():
            result['is_installed'] = True
            break

    return result


def _check_blockhost_state() -> dict:
    """Check BlockHost-specific state files."""
    result = {
        'setup_complete': False,
        'first_boot_pending': False,
    }

    setup_marker = Path('/var/lib/blockhost/.setup-complete')
    result['setup_complete'] = setup_marker.exists()

    # If marker doesn't exist and we're on a disk install, it's first boot
    result['first_boot_pending'] = not result['setup_complete']

    return result


def _get_root_device() -> Optional[str]:
    """Get the root device path."""
    try:
        result = subprocess.run(
            ['findmnt', '-n', '-o', 'SOURCE', '/'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def detect_boot_medium() -> tuple[BootMedium, dict]:
    """
    Detect the current boot medium.

    Returns:
        Tuple of (BootMedium enum, dict of detection details)
    """
    details = {
        'cmdline': _check_cmdline(),
        'mounts': _check_mounts(),
        'proxmox': _check_proxmox_markers(),
        'blockhost': _check_blockhost_state(),
        'root_device': _get_root_device(),
    }

    cmdline = details['cmdline']
    mounts = details['mounts']
    proxmox = details['proxmox']
    blockhost = details['blockhost']

    # Decision tree

    # 1. If we have squashfs + overlay, we're in a live environment
    if mounts['has_squashfs'] or mounts['has_overlay']:
        if cmdline.get('boot_medium') == 'optical':
            return BootMedium.ISO, details
        return BootMedium.USB_LIVE, details

    # 2. If cmdline says live boot
    if cmdline['is_live']:
        return BootMedium.ISO, details

    # 3. If root is on a real disk
    root_fstype = mounts['root_fstype']
    if root_fstype in ('ext4', 'xfs', 'btrfs', 'zfs'):
        # On a real filesystem
        if blockhost['setup_complete']:
            return BootMedium.HDD_INSTALLED, details
        elif proxmox['is_installed']:
            # Proxmox installed but BlockHost setup not complete
            return BootMedium.HDD_FRESH, details
        else:
            # Very fresh install, PVE not fully configured yet
            return BootMedium.HDD_FRESH, details

    return BootMedium.UNKNOWN, details


def is_first_boot() -> bool:
    """Quick check if this is a first boot requiring setup."""
    medium, details = detect_boot_medium()

    # First boot if:
    # 1. Booted from ISO/USB (installer mode)
    # 2. Fresh HDD install without setup complete
    if medium in (BootMedium.ISO, BootMedium.USB_LIVE):
        return True
    if medium == BootMedium.HDD_FRESH:
        return not details['blockhost']['setup_complete']

    return False


if __name__ == '__main__':
    # CLI for testing
    import json
    medium, details = detect_boot_medium()
    print(f"Boot Medium: {medium.value}")
    print(f"First Boot: {is_first_boot()}")
    print(f"\nDetails:\n{json.dumps(details, indent=2)}")
