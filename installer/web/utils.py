"""
BlockHost Web Installer - Utility Functions

Pure utility functions with no Flask dependency:
- Disk detection
- Ethereum key generation and validation
- Broker registry lookups
- YAML helpers
- Certificate generation
"""

import grp
import json
import os
import secrets
import subprocess
from pathlib import Path
from typing import Optional


def set_blockhost_ownership(path, mode=0o640):
    """Set file to root:blockhost with given mode."""
    os.chmod(str(path), mode)
    gid = grp.getgrnam('blockhost').gr_gid
    os.chown(str(path), 0, gid)


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


def _cast_wallet_address(private_hex: str) -> Optional[str]:
    """Derive Ethereum address from private key using Foundry's cast."""
    try:
        result = subprocess.run(
            ['cast', 'wallet', 'address', '--private-key', private_hex],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def generate_secp256k1_keypair() -> tuple[str, str]:
    """Generate a secp256k1 keypair for Ethereum."""
    try:
        # Try using eth-keys library if available
        from eth_keys import keys
        private_key = keys.PrivateKey(secrets.token_bytes(32))
        return private_key.to_hex(), private_key.public_key.to_checksum_address()
    except ImportError:
        pass

    # Fallback: generate random key and use cast for address derivation
    private_bytes = secrets.token_bytes(32)
    private_hex = '0x' + private_bytes.hex()

    address = _cast_wallet_address(private_hex)
    if address:
        return private_hex, address

    raise RuntimeError("Failed to generate keypair: cast wallet address failed")


def generate_secp256k1_keypair_with_pubkey() -> tuple[str, str, str]:
    """Generate a secp256k1 keypair and return (private_key, address, public_key).

    The public key is the uncompressed format (0x04 + x + y, 65 bytes hex)
    needed for ECIES encryption.
    """
    try:
        # Try using eth-keys library if available
        from eth_keys import keys
        private_key = keys.PrivateKey(secrets.token_bytes(32))
        # public_key.to_bytes() gives 64 bytes (x + y), need to prepend 0x04 for uncompressed
        public_key_bytes = b'\x04' + private_key.public_key.to_bytes()
        public_key_hex = '0x' + public_key_bytes.hex()
        return (
            private_key.to_hex(),
            private_key.public_key.to_checksum_address(),
            public_key_hex
        )
    except ImportError:
        pass

    # Fallback: generate random key and use cast
    private_bytes = secrets.token_bytes(32)
    private_hex = '0x' + private_bytes.hex()

    address = _cast_wallet_address(private_hex)
    if not address:
        raise RuntimeError("Failed to generate keypair: cast wallet address failed")

    # Get public key — use python ecdsa as backup
    try:
        from ecdsa import SigningKey, SECP256k1
        sk = SigningKey.from_string(private_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        # to_string() gives 64 bytes (x + y)
        public_key_hex = '0x04' + vk.to_string().hex()
    except ImportError:
        # Last resort: store empty and generate later
        public_key_hex = ''

    return private_hex, address, public_key_hex


def get_address_from_key(private_key: str) -> Optional[str]:
    """Derive Ethereum address from private key."""
    if not private_key:
        return None

    # Clean up key format
    key = private_key.strip()
    if key.startswith('0x'):
        key = key[2:]

    if len(key) != 64:
        return None

    try:
        # Try using eth-keys library if available
        from eth_keys import keys
        pk = keys.PrivateKey(bytes.fromhex(key))
        return pk.public_key.to_checksum_address()
    except ImportError:
        pass

    # Fallback: use Foundry's cast if available
    return _cast_wallet_address('0x' + key)


def is_valid_address(address: str) -> bool:
    """Check if string is a valid Ethereum address."""
    if not address:
        return False
    address = address.strip()
    if not address.startswith('0x'):
        return False
    if len(address) != 42:
        return False
    try:
        int(address, 16)
        return True
    except ValueError:
        return False


def is_valid_ipv6_prefix(prefix: str) -> bool:
    """Validate IPv6 prefix format."""
    import re
    pattern = r'^([0-9a-fA-F:]+)/(\d{1,3})$'
    match = re.match(pattern, prefix)
    if not match:
        return False

    prefix_len = int(match.group(2))
    if prefix_len < 32 or prefix_len > 128:
        return False

    return True


def get_broker_registry(chain_id: str) -> Optional[str]:
    """Get broker registry contract address for chain."""
    # Placeholder - in production, these would be the actual deployed addresses
    registries = {
        '11155111': '0x0E5b567E0000000000000000000000000000dead',  # Sepolia
        '1': None,  # Mainnet - not deployed
        '137': None,  # Polygon - not deployed
    }
    return registries.get(chain_id)


def get_wallet_balance(address: str, rpc_url: str) -> Optional[int]:
    """Get wallet balance via JSON-RPC."""
    import urllib.request
    import urllib.error

    try:
        # Prepare JSON-RPC request
        payload = json.dumps({
            'jsonrpc': '2.0',
            'method': 'eth_getBalance',
            'params': [address, 'latest'],
            'id': 1,
        }).encode('utf-8')

        req = urllib.request.Request(
            rpc_url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'BlockHost-Installer/1.0',
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

            if 'result' in data:
                # Result is hex string, convert to int
                return int(data['result'], 16)

        return None
    except (urllib.error.URLError, json.JSONDecodeError, ValueError, KeyError) as e:
        print(f"Balance check error: {e}")
        return None


def fetch_broker_registry_from_github(chain_id: str) -> Optional[str]:
    """Fetch broker registry contract address from GitHub."""
    import urllib.request
    import urllib.error

    # Use testnet registry when running from a testing ISO
    testing_marker = Path('/etc/blockhost/.testing-mode')
    registry_file = 'registry-testnet.json' if testing_marker.exists() else 'registry.json'
    url = f'https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/{registry_file}'

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'BlockHost-Installer'})

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

            # Handle flat format: {"registry_contract": "0x...", "chain_id": 11155111}
            if 'registry_contract' in data:
                # Check if chain_id matches (if specified in the JSON)
                json_chain_id = data.get('chain_id')
                if json_chain_id is None or str(json_chain_id) == str(chain_id):
                    return data['registry_contract']

            # Handle keyed format: {"11155111": {"registry": "0x..."}}
            if chain_id in data:
                return data[chain_id].get('registry') or data[chain_id].get('address')
            elif str(chain_id) in data:
                return data[str(chain_id)].get('registry') or data[str(chain_id)].get('address')

        return None
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        print(f"GitHub fetch error: {e}")
        return None


def request_broker_allocation(registry: str) -> dict:
    """Request IPv6 allocation from broker network."""
    try:
        # Call blockhost-broker-client
        result = subprocess.run(
            ['blockhost-broker-client', 'request', '--registry', registry, '--json'],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            data = json.loads(result.stdout)
            return {
                'success': True,
                'prefix': data.get('prefix'),
                'broker_node': data.get('broker_node'),
                'tunnel_active': data.get('tunnel_active', False),
                'wg_config': data.get('wg_config'),
            }
        else:
            return {
                'success': False,
                'error': result.stderr or 'Broker request failed',
            }
    except FileNotFoundError:
        return {
            'success': False,
            'error': 'blockhost-broker-client not installed',
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': 'Broker request timed out',
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
        }


def write_yaml(path: Path, data: dict):
    """Write data to YAML file."""
    try:
        import yaml
        path.write_text(yaml.safe_dump(data, default_flow_style=False))
    except ImportError:
        # Fallback: simple YAML output
        lines = []
        dict_to_yaml(data, lines, 0)
        path.write_text('\n'.join(lines))


def dict_to_yaml(data: dict, lines: list, indent: int):
    """Simple dict to YAML converter."""
    prefix = '  ' * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            dict_to_yaml(value, lines, indent + 1)
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                lines.append(f"{prefix}  - {item}")
        elif value is None:
            lines.append(f"{prefix}{key}: null")
        elif isinstance(value, bool):
            lines.append(f"{prefix}{key}: {str(value).lower()}")
        elif isinstance(value, (int, float)):
            lines.append(f"{prefix}{key}: {value}")
        else:
            lines.append(f"{prefix}{key}: \"{value}\"")


def parse_pam_ciphertext(output: str) -> Optional[str]:
    """Parse ciphertext hex from pam_web3_tool output."""
    for line in output.split('\n'):
        if 'Ciphertext' in line and '0x' in line:
            return line[line.index('0x'):].strip()
    return None


def _run_openssl_selfsigned(cert_path: str, key_path: str, cn: str) -> bool:
    """Run openssl to generate a self-signed certificate. Returns True on success."""
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path, '-out', cert_path,
            '-days', '365', '-nodes', '-subj', f'/CN={cn}',
        ], check=True, capture_output=True, timeout=60)
        return True
    except Exception:
        return False


def generate_self_signed_cert_for_finalization(hostname: str, ssl_dir: Path):
    """Generate a self-signed certificate for fallback HTTPS (used by finalization)."""
    cert_path = ssl_dir / 'cert.pem'
    key_path = ssl_dir / 'key.pem'
    _run_openssl_selfsigned(str(cert_path), str(key_path), hostname)
    set_blockhost_ownership(key_path, 0o640)


def generate_self_signed_cert(cert_path: str, key_path: str) -> bool:
    """Generate self-signed SSL certificate (used by run_server)."""
    return _run_openssl_selfsigned(cert_path, key_path, 'blockhost-installer')
