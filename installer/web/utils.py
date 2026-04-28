"""
BlockHost Web Installer - Utility Functions

Pure utility functions with no Flask dependency:
- Disk detection
- Address validation
- Broker registry lookups
- YAML helpers
- Certificate generation
"""

import grp
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional, Union

import yaml


def set_blockhost_ownership(path, mode=0o640):
    """Set file to root:blockhost with given mode."""
    os.chmod(str(path), mode)
    gid = grp.getgrnam('blockhost').gr_gid
    os.chown(str(path), 0, gid)


def write_blockhost_file(path: Union[str, Path], content: str, mode: int = 0o640):
    """Write content with restrictive mode at create time, then set root:blockhost ownership.

    O_CREAT mode applies only when the file is new — chmod after handles existing
    files. The point is to avoid the brief default-perm window between
    Path.write_text() and chmod for sensitive keyfiles (deployer.key, server.key,
    admin-signature.key, OTP).
    """
    path_str = str(path)
    fd = os.open(path_str, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    set_blockhost_ownership(path_str, mode)


def detect_disks() -> list[dict]:
    """Detect available disks."""
    disks = []
    try:
        result = subprocess.run(
            ['lsblk', '-J', '-b', '-o', 'NAME,SIZE,TYPE,MODEL,MOUNTPOINT'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for device in data.get('blockdevices', []):
                if device.get('type') == 'disk':
                    size_gb = int(device.get('size', 0)) / (1024**3)
                    disks.append({
                        'name': device['name'],
                        'path': f"/dev/{device['name']}",
                        'size': f"{size_gb:.1f} GB",
                        'size_bytes': device.get('size', 0),
                        'model': device.get('model', 'Unknown'),
                        'mountpoint': device.get('mountpoint'),
                    })
    except Exception:
        pass
    return disks


def is_valid_ipv6_prefix(prefix: str) -> bool:
    """Validate IPv6 prefix format."""
    match = re.match(r'^([0-9a-fA-F:]+)/(\d{1,3})$', prefix)
    if not match:
        return False
    prefix_len = int(match.group(2))
    return 32 <= prefix_len <= 128


def write_yaml(path: Path, data: dict):
    """Write data to YAML file."""
    path.write_text(yaml.safe_dump(data, default_flow_style=False))


def parse_pam_ciphertext(output: str) -> Optional[str]:
    """Parse ciphertext hex from bhcrypt output."""
    for line in output.split('\n'):
        if 'Ciphertext' in line and '0x' in line:
            return line[line.index('0x'):].strip()
    return None


def generate_self_signed_cert(
    cert_path: Union[str, Path],
    key_path: Union[str, Path],
    cn: str = 'blockhost-installer',
    set_owner: bool = False,
) -> bool:
    """Generate a self-signed certificate. Returns True on success.

    set_owner=True chmods the key to 0o640 and sets root:blockhost ownership
    (used by finalization for HTTPS fallback so nginx-as-blockhost can read it).
    """
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', str(key_path), '-out', str(cert_path),
            '-days', '365', '-nodes', '-subj', f'/CN={cn}',
        ], check=True, capture_output=True, timeout=60)
    except Exception:
        return False
    if set_owner:
        set_blockhost_ownership(key_path, 0o640)
    return True


def generate_self_signed_cert_for_finalization(hostname: str, ssl_dir: Path):
    """Generate a self-signed certificate for fallback HTTPS (used by finalization)."""
    generate_self_signed_cert(
        ssl_dir / 'cert.pem',
        ssl_dir / 'key.pem',
        cn=hostname,
        set_owner=True,
    )
