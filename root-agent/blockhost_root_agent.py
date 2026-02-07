#!/usr/bin/env python3
"""
BlockHost Root Agent — Privileged Operations Daemon

Runs as root, listens on a Unix domain socket, accepts validated JSON
commands for operations that genuinely require root privileges:
  - qm (Proxmox VM management)
  - ip -6 route (kernel networking)
  - iptables (firewall)
  - virt-customize (disk images)
  - Key/addressbook writes to /etc/blockhost/

Protocol: 4-byte big-endian length prefix + JSON payload (both directions).
"""

import asyncio
import json
import logging
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

SOCKET_PATH = '/run/blockhost/root-agent.sock'
CONFIG_DIR = Path('/etc/blockhost')
STATE_DIR = Path('/var/lib/blockhost')

# Logging to systemd journal (stderr)
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s %(message)s',
    stream=sys.stderr,
)
log = logging.getLogger('root-agent')

# --- Validation helpers ---

VMID_MIN = 100
VMID_MAX = 999999

NAME_RE = re.compile(r'^[a-z0-9-]{1,64}$')
SHORT_NAME_RE = re.compile(r'^[a-z0-9-]{1,32}$')
STORAGE_RE = re.compile(r'^[a-z0-9-]+$')
ADDRESS_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')
COMMENT_RE = re.compile(r'^[a-zA-Z0-9-]+$')
IPV6_CIDR128_RE = re.compile(
    r'^([0-9a-fA-F:]+)/128$'
)

QM_SET_ALLOWED_KEYS = frozenset({
    'scsi0', 'boot', 'ide2', 'agent', 'serial0', 'vga',
    'net0', 'memory', 'cores', 'name', 'ostype', 'scsihw',
})

QM_CREATE_ALLOWED_ARGS = frozenset({
    '--scsi0', '--boot', '--ide2', '--agent', '--serial0', '--vga',
    '--net0', '--memory', '--cores', '--name', '--ostype', '--scsihw',
    '--sockets', '--cpu', '--numa', '--machine', '--bios',
})

ALLOWED_ROUTE_DEVS = frozenset({'vmbr0'})

WALLET_DENY_NAMES = frozenset({'admin', 'server', 'dev', 'broker'})

VIRT_CUSTOMIZE_ALLOWED_OPS = frozenset({
    '--install', '--run-command', '--copy-in', '--upload',
    '--chmod', '--mkdir', '--write', '--append-line',
    '--firstboot-command', '--run', '--delete',
})


def _validate_vmid(vmid):
    if not isinstance(vmid, int) or vmid < VMID_MIN or vmid > VMID_MAX:
        raise ValueError(f'vmid must be int {VMID_MIN}-{VMID_MAX}')
    return vmid


def _validate_ipv6_128(address):
    if not IPV6_CIDR128_RE.match(address):
        raise ValueError(f'Invalid IPv6/128: {address}')
    return address


def _validate_dev(dev):
    if dev not in ALLOWED_ROUTE_DEVS:
        raise ValueError(f'Device not allowed: {dev}')
    return dev


def _run(cmd, timeout=120):
    """Run a subprocess, return (returncode, stdout, stderr)."""
    log.info('exec: %s', ' '.join(str(c) for c in cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


# --- Action handlers ---

def handle_qm_start(params):
    vmid = _validate_vmid(params['vmid'])
    rc, out, err = _run(['qm', 'start', str(vmid)])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_stop(params):
    vmid = _validate_vmid(params['vmid'])
    rc, out, err = _run(['qm', 'stop', str(vmid)])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_shutdown(params):
    vmid = _validate_vmid(params['vmid'])
    rc, out, err = _run(['qm', 'shutdown', str(vmid)], timeout=300)
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_destroy(params):
    vmid = _validate_vmid(params['vmid'])
    rc, out, err = _run(['qm', 'destroy', str(vmid), '--purge'])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_create(params):
    vmid = _validate_vmid(params['vmid'])
    name = params.get('name', '')
    if not NAME_RE.match(name):
        return {'ok': False, 'error': f'Invalid VM name: {name}'}

    args = params.get('args', [])
    if not isinstance(args, list):
        return {'ok': False, 'error': 'args must be a list'}

    # Validate each flag is in allowlist
    i = 0
    while i < len(args):
        arg = str(args[i])
        if arg.startswith('--'):
            if arg not in QM_CREATE_ALLOWED_ARGS:
                return {'ok': False, 'error': f'Disallowed arg: {arg}'}
            i += 2  # skip flag + value
        else:
            i += 1

    cmd = ['qm', 'create', str(vmid), '--name', name] + [str(a) for a in args]
    rc, out, err = _run(cmd, timeout=300)
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_importdisk(params):
    vmid = _validate_vmid(params['vmid'])
    disk_path = params.get('disk_path', '')
    storage = params.get('storage', '')

    if not disk_path.startswith('/var/lib/'):
        return {'ok': False, 'error': 'disk_path must be under /var/lib/'}
    if not os.path.isfile(disk_path):
        return {'ok': False, 'error': f'Disk file not found: {disk_path}'}
    if not STORAGE_RE.match(storage):
        return {'ok': False, 'error': f'Invalid storage name: {storage}'}

    rc, out, err = _run(['qm', 'importdisk', str(vmid), disk_path, storage], timeout=600)
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_set(params):
    vmid = _validate_vmid(params['vmid'])
    options = params.get('options', {})
    if not isinstance(options, dict):
        return {'ok': False, 'error': 'options must be a dict'}

    cmd = ['qm', 'set', str(vmid)]
    for key, value in options.items():
        if key not in QM_SET_ALLOWED_KEYS:
            return {'ok': False, 'error': f'Disallowed option: {key}'}
        cmd.extend([f'--{key}', str(value)])

    rc, out, err = _run(cmd, timeout=120)
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_qm_template(params):
    vmid = _validate_vmid(params['vmid'])
    rc, out, err = _run(['qm', 'template', str(vmid)])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_ip6_route_add(params):
    address = _validate_ipv6_128(params['address'])
    dev = _validate_dev(params['dev'])
    rc, out, err = _run(['ip', '-6', 'route', 'replace', address, 'dev', dev])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_ip6_route_del(params):
    address = _validate_ipv6_128(params['address'])
    dev = _validate_dev(params['dev'])
    rc, out, err = _run(['ip', '-6', 'route', 'del', address, 'dev', dev])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_iptables_open(params):
    port = params.get('port')
    if not isinstance(port, int) or port < 1 or port > 65535:
        return {'ok': False, 'error': 'port must be 1-65535'}
    proto = params.get('proto', 'tcp')
    if proto not in ('tcp', 'udp'):
        return {'ok': False, 'error': 'proto must be tcp or udp'}
    comment = params.get('comment', '')
    if not COMMENT_RE.match(comment):
        return {'ok': False, 'error': 'Invalid comment (alphanumeric/dash only)'}

    rc, out, err = _run([
        'iptables', '-A', 'INPUT', '-p', proto,
        '--dport', str(port), '-j', 'ACCEPT',
        '-m', 'comment', '--comment', comment,
    ])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_iptables_close(params):
    port = params.get('port')
    if not isinstance(port, int) or port < 1 or port > 65535:
        return {'ok': False, 'error': 'port must be 1-65535'}
    proto = params.get('proto', 'tcp')
    if proto not in ('tcp', 'udp'):
        return {'ok': False, 'error': 'proto must be tcp or udp'}
    comment = params.get('comment', '')
    if not COMMENT_RE.match(comment):
        return {'ok': False, 'error': 'Invalid comment (alphanumeric/dash only)'}

    rc, out, err = _run([
        'iptables', '-D', 'INPUT', '-p', proto,
        '--dport', str(port), '-j', 'ACCEPT',
        '-m', 'comment', '--comment', comment,
    ])
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_virt_customize(params):
    image_path = params.get('image_path', '')
    commands = params.get('commands', [])

    # Validate path
    if not (image_path.startswith('/var/lib/blockhost/') or image_path.startswith('/tmp/')):
        return {'ok': False, 'error': 'image_path must be under /var/lib/blockhost/ or /tmp/'}
    if not os.path.isfile(image_path):
        return {'ok': False, 'error': f'Image not found: {image_path}'}

    if not isinstance(commands, list) or not commands:
        return {'ok': False, 'error': 'commands must be a non-empty list'}

    cmd = ['virt-customize', '-a', image_path]
    for entry in commands:
        if not isinstance(entry, list) or len(entry) < 2:
            return {'ok': False, 'error': f'Each command must be [op, arg, ...]: {entry}'}
        op = entry[0]
        if op not in VIRT_CUSTOMIZE_ALLOWED_OPS:
            return {'ok': False, 'error': f'Disallowed virt-customize op: {op}'}
        cmd.extend(entry)

    rc, out, err = _run(cmd, timeout=600)
    if rc != 0:
        return {'ok': False, 'error': err or out}
    return {'ok': True, 'output': out}


def handle_generate_wallet(params):
    import grp

    name = params.get('name', '')
    if not SHORT_NAME_RE.match(name):
        return {'ok': False, 'error': f'Invalid wallet name: {name}'}
    if name in WALLET_DENY_NAMES:
        return {'ok': False, 'error': f'Reserved name: {name}'}

    keyfile = CONFIG_DIR / f'{name}.key'
    if keyfile.exists():
        return {'ok': False, 'error': f'Key file already exists: {keyfile}'}

    # Generate secp256k1 keypair using ecdsa library (installed with proxmox-ve)
    try:
        import ecdsa
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        private_hex = sk.to_string().hex()
        vk = sk.get_verifying_key()
        pub_bytes = vk.to_string()

        # Derive Ethereum address: keccak256(pub_bytes)[-20:]
        import hashlib
        keccak = hashlib.new('sha3_256')  # Python's sha3_256 is Keccak-256
        # Actually need keccak256 not SHA3-256; use pysha3 or pycryptodome if available
        # Fallback: use cast wallet to derive address
    except ImportError:
        pass

    # Reliable approach: use cast wallet new
    rc, out, err = _run(['cast', 'wallet', 'new'], timeout=30)
    if rc != 0:
        return {'ok': False, 'error': f'cast wallet new failed: {err}'}

    # Parse output: "Successfully created new keypair.\nAddress: 0x...\nPrivate key: 0x..."
    address = None
    private_key = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Address:'):
            address = line.split(':', 1)[1].strip()
        elif line.lower().startswith('private key:'):
            private_key = line.split(':', 1)[1].strip()

    if not address or not private_key:
        return {'ok': False, 'error': f'Failed to parse cast wallet output: {out}'}

    # Write private key (raw hex, no 0x prefix)
    raw_key = private_key[2:] if private_key.startswith('0x') else private_key
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    keyfile.write_text(raw_key)

    # Set ownership: root:blockhost 0640
    gid = grp.getgrnam('blockhost').gr_gid
    os.chown(str(keyfile), 0, gid)
    os.chmod(str(keyfile), 0o640)

    # Update addressbook.json
    ab_file = CONFIG_DIR / 'addressbook.json'
    addressbook = {}
    if ab_file.exists():
        try:
            addressbook = json.loads(ab_file.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    addressbook[name] = {
        'address': address,
        'keyfile': str(keyfile),
    }

    ab_file.write_text(json.dumps(addressbook, indent=2))
    os.chown(str(ab_file), 0, gid)
    os.chmod(str(ab_file), 0o640)

    log.info('Generated wallet %s: %s', name, address)
    return {'ok': True, 'address': address}


def handle_addressbook_save(params):
    import grp

    entries = params.get('entries', {})
    if not isinstance(entries, dict):
        return {'ok': False, 'error': 'entries must be a dict'}

    # Validate each entry
    for name, entry in entries.items():
        if not SHORT_NAME_RE.match(name) and not NAME_RE.match(name):
            return {'ok': False, 'error': f'Invalid entry name: {name}'}
        if not isinstance(entry, dict):
            return {'ok': False, 'error': f'Entry {name} must be a dict'}
        addr = entry.get('address', '')
        if not ADDRESS_RE.match(addr):
            return {'ok': False, 'error': f'Invalid address for {name}: {addr}'}
        keyfile = entry.get('keyfile')
        if keyfile and not keyfile.startswith('/etc/blockhost/'):
            return {'ok': False, 'error': f'keyfile for {name} must be under /etc/blockhost/'}

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ab_file = CONFIG_DIR / 'addressbook.json'
    ab_file.write_text(json.dumps(entries, indent=2))

    gid = grp.getgrnam('blockhost').gr_gid
    os.chown(str(ab_file), 0, gid)
    os.chmod(str(ab_file), 0o640)

    log.info('Saved addressbook with %d entries', len(entries))
    return {'ok': True}


# --- Action dispatch ---

ACTIONS = {
    'qm-start': handle_qm_start,
    'qm-stop': handle_qm_stop,
    'qm-shutdown': handle_qm_shutdown,
    'qm-destroy': handle_qm_destroy,
    'qm-create': handle_qm_create,
    'qm-importdisk': handle_qm_importdisk,
    'qm-set': handle_qm_set,
    'qm-template': handle_qm_template,
    'ip6-route-add': handle_ip6_route_add,
    'ip6-route-del': handle_ip6_route_del,
    'iptables-open': handle_iptables_open,
    'iptables-close': handle_iptables_close,
    'virt-customize': handle_virt_customize,
    'generate-wallet': handle_generate_wallet,
    'addressbook-save': handle_addressbook_save,
}


# --- Protocol ---

async def read_message(reader):
    """Read a length-prefixed JSON message."""
    header = await reader.readexactly(4)
    length = struct.unpack('>I', header)[0]
    if length > 10 * 1024 * 1024:  # 10 MB limit
        raise ValueError(f'Message too large: {length}')
    data = await reader.readexactly(length)
    return json.loads(data.decode('utf-8'))


async def write_message(writer, msg):
    """Write a length-prefixed JSON message."""
    data = json.dumps(msg).encode('utf-8')
    writer.write(struct.pack('>I', len(data)) + data)
    await writer.drain()


async def handle_connection(reader, writer):
    """Handle a single client connection."""
    peer = 'unknown'
    try:
        msg = await asyncio.wait_for(read_message(reader), timeout=10)
        action = msg.get('action', '')
        params = msg.get('params', {})

        log.info('Request: action=%s', action)

        handler = ACTIONS.get(action)
        if not handler:
            response = {'ok': False, 'error': f'Unknown action: {action}'}
        else:
            try:
                response = handler(params)
            except Exception as e:
                log.exception('Handler error for %s', action)
                response = {'ok': False, 'error': str(e)}

        await write_message(writer, response)

    except asyncio.IncompleteReadError:
        log.warning('Client disconnected mid-message')
    except asyncio.TimeoutError:
        log.warning('Client read timeout')
    except Exception as e:
        log.exception('Connection error')
        try:
            await write_message(writer, {'ok': False, 'error': str(e)})
        except Exception:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    """Start the root agent daemon."""
    if os.getuid() != 0:
        log.error('Root agent must run as root')
        sys.exit(1)

    # Ensure runtime directory exists
    run_dir = Path(SOCKET_PATH).parent
    run_dir.mkdir(parents=True, exist_ok=True)

    # Remove stale socket
    socket_path = Path(SOCKET_PATH)
    if socket_path.exists():
        socket_path.unlink()

    server = await asyncio.start_unix_server(handle_connection, path=SOCKET_PATH)

    # Set socket permissions: root:blockhost 0660
    try:
        import grp
        gid = grp.getgrnam('blockhost').gr_gid
        os.chown(SOCKET_PATH, 0, gid)
    except (KeyError, OSError) as e:
        log.warning('Could not set socket group to blockhost: %s', e)

    os.chmod(SOCKET_PATH, 0o660)

    log.info('Root agent listening on %s', SOCKET_PATH)

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
