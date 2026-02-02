# BlockHost Build Guide

**Version**: 0.1.0
**Last Updated**: 2026-02-02
**Base**: Proxmox VE 8.4

---

## Overview

BlockHost adds a first-boot web installer to Proxmox VE. On first boot after installation:
1. Network is configured (DHCP or console wizard)
2. OTP code is displayed on the console
3. Web installer starts for final configuration

---

## Project Structure

```
blockhost/
├── installer/
│   ├── common/           # Shared utilities
│   │   ├── detection.py  # Boot medium detection
│   │   ├── network.py    # Network configuration
│   │   └── otp.py        # OTP authentication
│   ├── console/          # Console (whiptail) fallback
│   │   ├── main.py
│   │   ├── whiptail.py
│   │   └── screens/
│   │       └── network.py
│   └── web/              # Flask web installer
│       ├── app.py
│       └── templates/
├── scripts/
│   ├── first-boot.sh     # Main first-boot script
│   └── build-iso.sh      # ISO builder
├── systemd/
│   └── blockhost-firstboot.service
└── docs/
    └── BUILD_GUIDE.md
```

---

## Prerequisites

```bash
sudo apt install -y \
    xorriso \
    squashfs-tools \
    python3 \
    python3-flask \
    whiptail
```

---

## How It Works

### First-Boot Flow

```
┌─────────────────────────────────────────────────────────┐
│                    first-boot.sh                        │
├─────────────────────────────────────────────────────────┤
│  1. Try DHCP on default interface                       │
│         ↓                                               │
│  2. If DHCP fails → launch console wizard (whiptail)    │
│         ↓                                               │
│  3. Generate OTP → display on TTY1                      │
│         ↓                                               │
│  4. Start Flask web server                              │
│         ↓                                               │
│  5. User completes wizard → creates marker file         │
│         ↓                                               │
│  6. Service won't run on next boot                      │
└─────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/first-boot.sh` | Main orchestrator - runs everything |
| `systemd/blockhost-firstboot.service` | Runs first-boot.sh on boot |
| `installer/common/otp.py` | OTP generation (6-char, 4hr timeout) |
| `installer/common/network.py` | DHCP and static IP config |
| `installer/console/main.py` | Whiptail network wizard |
| `installer/web/app.py` | Flask web installer |

---

## Building the ISO

### 1. Download Proxmox VE ISO

```bash
mkdir -p build
cd build
wget https://enterprise.proxmox.com/iso/proxmox-ve_8.4-1.iso
```

### 2. Build Custom ISO

```bash
./scripts/build-iso.sh
```

This:
1. Extracts the Proxmox ISO
2. Copies BlockHost files to `/blockhost/` on the ISO
3. Creates `install-blockhost.sh` hook
4. Rebuilds the ISO

Output: `build/blockhost-pve_0.1.0.iso`

---

## Components

### OTP System

- 6 characters, alphanumeric (no confusing chars like 0/O, 1/I)
- 4-hour timeout
- 10 attempts max before lockout
- Stored in `/run/blockhost/otp.json`

```python
from installer.common.otp import OTPManager
otp = OTPManager()
code = otp.generate()      # "X7KM3P"
otp.verify("X7KM3P")       # (True, "OTP verified")
```

### Network Manager

```python
from installer.common.network import NetworkManager
net = NetworkManager()
net.detect_interfaces()     # List all interfaces
net.run_dhcp("eth0")        # Try DHCP
net.configure_static(...)   # Static IP
net.is_private_ip("10.0.0.1")  # True (determines HTTP vs HTTPS)
```

### Console Wizard

Whiptail-based fallback when DHCP fails:
- Interface selection
- DHCP retry or manual IP entry
- DNS configuration

### Web Installer

Flask app with:
- OTP login
- Network config
- Disk selection
- Package selection
- Installation summary

HTTP for private IPs, HTTPS (self-signed) for public IPs.

---

## Testing

### Test Modules Locally

```bash
# OTP
python3 -c "
from installer.common.otp import OTPManager
import tempfile
from pathlib import Path
otp = OTPManager(state_dir=Path(tempfile.mkdtemp()))
code = otp.generate()
print(f'Code: {code}')
print(otp.verify(code))
"

# Network (list interfaces)
python3 -m installer.common.network interfaces

# Web app (dev server)
python3 -m installer.web.app --port 8080
```

### Test in VM

```bash
sudo virt-install \
    --name blockhost-test \
    --ram 4096 \
    --vcpus 2 \
    --disk size=32 \
    --cdrom build/blockhost-pve_0.1.0.iso \
    --network network=default \
    --graphics vnc
```

---

## Troubleshooting

### No OTP on Console
Check: `journalctl -u blockhost-firstboot`

### Web Installer Unreachable
1. Verify IP: `ip addr`
2. Check service: `systemctl status blockhost-firstboot`
3. Check logs: `/var/log/blockhost-firstboot.log`

### DHCP Failed, No Console Wizard
The script needs TTY access. Check the systemd service has `TTYPath=/dev/tty1`.

---

## Architecture Notes

**Why a single first-boot.sh instead of multiple services?**
- Runs once, never again
- Simpler to debug
- No complex service dependencies
- Everything in one place

**Why HTTP for private IPs?**
- Self-signed certs cause browser warnings
- Private networks are trusted
- Reduces friction for home/lab use
