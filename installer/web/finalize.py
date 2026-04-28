"""
BlockHost Web Installer - Finalization Pipeline

The finalization pipeline: step functions, orchestration, and helpers.
All step functions are private to this module. The public API is:
- get_finalization_steps(provisioner, engine) — returns step tuples
- run_finalization_with_state(setup_state, config, provisioner, engine) — orchestration loop

Chain-specific steps (wallet, contracts, config, mint_nft, plan,
revenue_share) are provided by the engine wizard plugin. This module
contains chain-agnostic infrastructure steps (keypair, ipv6, https, etc.).
"""

import grp
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

from blockhost.config import CONFIG_DIR, DATA_DIR, BROKER_ALLOCATION_FILE
from installer.web.utils import (
    set_blockhost_ownership,
    write_blockhost_file,
    write_yaml,
    generate_self_signed_cert_for_finalization,
)


def get_finalization_steps(provisioner, engine=None) -> list[tuple]:
    """Canonical finalization step list — single source of truth.

    Each tuple is (id, label, func) or (id, label, func, hint). Plugins may
    return either form. Order:
    1. Infrastructure (keypair — chain-agnostic, needed before engine)
    2. Engine pre-steps (from plugin: wallet, contracts, chain_config)
    3. Provisioner steps (from plugin: token, terraform, bridge, template)
    4. Post steps (ipv6, https, signup, nginx)
    5. Engine post-steps (from plugin: mint_nft, plan, revenue_share)
    6. Final (finalize, validate)
    """
    def plugin_steps(plugin, attr):
        if plugin and plugin.get('module') and hasattr(plugin['module'], attr):
            return getattr(plugin['module'], attr)()
        return []

    return [
        ('keypair', 'Generating server keypair', _finalize_keypair),
        *plugin_steps(engine, 'get_finalization_steps'),
        *plugin_steps(provisioner, 'get_finalization_steps'),
        ('ipv6', 'Configuring IPv6', _finalize_ipv6),
        ('https', 'Configuring HTTPS', _finalize_https),
        ('signup', 'Generating signup page', _finalize_signup),
        ('nginx', 'Setting up nginx reverse proxy', _finalize_nginx),
        *plugin_steps(engine, 'get_post_finalization_steps'),
        ('finalize', 'Finalizing setup', _finalize_complete),
        ('validate', 'Validating system', _finalize_validate, 'testing only'),
    ]


def get_step_metadata(provisioner, engine=None, network_mode: str = 'none') -> list[dict]:
    """Return UI-friendly step metadata.

    network_mode='onion' filters ipv6/https from display — those steps still
    run during finalization but short-circuit, so they shouldn't appear in
    the progress UI.
    """
    meta = []
    for step in get_finalization_steps(provisioner, engine):
        sid = step[0]
        if network_mode == 'onion' and sid in ('ipv6', 'https'):
            continue
        m = {'id': sid, 'label': step[1]}
        if len(step) > 3:
            m['hint'] = step[3]
        meta.append(m)
    return meta


def run_finalization_with_state(setup_state, config: dict, provisioner, engine=None):
    """Run the full finalization process with persistent state tracking."""
    # Make engine available to step functions via config
    if engine:
        config['_engine'] = engine
    steps = get_finalization_steps(provisioner, engine)

    try:
        for step in steps:
            step_id, step_name, step_func = step[0], step[1], step[2]
            step_state = setup_state.state['steps'][step_id]

            # Skip already completed steps
            if step_state['status'] == 'completed':
                continue

            # Mark step as running
            setup_state.mark_step_running(step_id)

            try:
                # Run step
                success, error = step_func(config)

                if success:
                    # Step data convention: step functions set
                    # config['_step_result_<step_id>'] for UI display data
                    step_data = config.pop(f'_step_result_{step_id}', None)

                    # Installer step data (stays here — these steps are ours)
                    if not step_data:
                        if step_id == 'ipv6':
                            ipv6_cfg = config.get('ipv6', {})
                            prefix = ipv6_cfg.get('prefix', '')
                            if not prefix:
                                alloc_file = CONFIG_DIR / BROKER_ALLOCATION_FILE
                                if alloc_file.exists():
                                    try:
                                        alloc = json.loads(alloc_file.read_text())
                                        prefix = alloc.get('prefix', '')
                                    except (json.JSONDecodeError, IOError):
                                        pass
                            if prefix:
                                step_data = {'prefix': prefix, 'mode': ipv6_cfg.get('mode', '')}
                        elif step_id == 'https':
                            https_cfg = config.get('https', {})
                            if https_cfg.get('hostname'):
                                step_data = {'hostname': https_cfg['hostname']}

                    setup_state.mark_step_completed(step_id, data=step_data)
                else:
                    setup_state.mark_step_failed(step_id, error or f'{step_name} failed')
                    return  # Stop on failure

            except Exception as e:
                setup_state.mark_step_failed(step_id, str(e))
                return  # Stop on failure

        # All steps completed
        setup_state.complete()

    except Exception as e:
        # Unexpected error
        current = setup_state.state['current_step']
        if current:
            setup_state.mark_step_failed(current, f'Unexpected error: {str(e)}')
        else:
            setup_state.state['status'] = 'failed'
            setup_state.save()


# ---------------------------------------------------------------------------
# Shared helpers (private to this module)
# ---------------------------------------------------------------------------

def _discover_bridge() -> Optional[str]:
    """Read bridge name from first-boot marker or scan /sys/class/net."""
    bridge_file = Path('/run/blockhost/bridge')
    if bridge_file.exists():
        name = bridge_file.read_text().strip()
        if name:
            return name
    for p in Path('/sys/class/net').iterdir():
        if (p / 'bridge').is_dir():
            return p.name
    return None


def _chown_recursive(path: str, user: str, group: str):
    """Recursively chown path. Uses os.walk + os.chown — no subprocess fork per file."""
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for entry in dirs + files:
            try:
                os.chown(os.path.join(root, entry), uid, gid, follow_symlinks=False)
            except OSError:
                pass


def _systemctl(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run `systemctl <args>` with a uniform timeout policy. Never raises on non-zero."""
    return subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=timeout)


def _ip(*args: str, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run `ip <args>` and capture output. Never raises on non-zero."""
    return subprocess.run(['ip', *args], capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# Step functions (private to this module — chain-agnostic infrastructure)
# ---------------------------------------------------------------------------

def _finalize_keypair(config: dict) -> tuple[bool, Optional[str]]:
    """Generate secp256k1 ECIES server keypair.

    Writes server.key (private, hex, 0640) and server.pubkey (uncompressed
    public point, hex, 0640). Idempotent — skips if both already exist.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        key_file = CONFIG_DIR / 'server.key'
        pub_file = CONFIG_DIR / 'server.pubkey'

        if key_file.exists() and pub_file.exists():
            return True, None

        if key_file.exists():
            priv_hex = key_file.read_text().strip()
        else:
            priv_hex = secrets.token_hex(32)
            write_blockhost_file(key_file, priv_hex + '\n')

        priv_int = int(priv_hex, 16)
        priv_key = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
        pub_hex = priv_key.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint
        ).hex()

        write_blockhost_file(pub_file, pub_hex + '\n')

        return True, None
    except Exception as e:
        return False, f'Failed to generate server keypair: {e}'


def _setup_onion_host_service():
    """Configure tor hidden service for host (admin/signup over .onion)."""
    host_onion_dir = Path('/var/lib/tor/blockhost-host')
    host_onion_dir.mkdir(parents=True, exist_ok=True)
    _chown_recursive(str(host_onion_dir), 'debian-tor', 'debian-tor')
    with open('/etc/tor/torrc', 'a') as f:
        f.write('\n# BlockHost — host hidden service (admin/signup)\n')
        f.write(f'HiddenServiceDir {host_onion_dir}\n')
        f.write('HiddenServicePort 80 127.0.0.1:80\n')
    _systemctl('enable', '--now', 'tor')


def _enable_ipv6_forwarding():
    """Enable net.ipv6.conf.all.forwarding now and persistently."""
    subprocess.run(
        ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'],
        capture_output=True, timeout=10,
    )
    sysctl_dir = Path('/etc/sysctl.d')
    sysctl_dir.mkdir(parents=True, exist_ok=True)
    (sysctl_dir / '99-blockhost-ipv6.conf').write_text(
        'net.ipv6.conf.all.forwarding=1\n'
    )


def _extract_prefix_from_broker_stdout(stdout: str) -> str:
    """Best-effort: pull a prefix from broker-client stdout when allocation file is missing."""
    for line in (stdout or '').strip().split('\n'):
        if line.strip().startswith('{'):
            try:
                data = json.loads(line)
                prefix = data.get('prefix', data.get('ipv6_prefix', ''))
                if prefix:
                    return prefix
            except json.JSONDecodeError:
                pass
    m = re.search(r'prefix[:\s]+([0-9a-fA-F:]+/\d+)', stdout or '')
    return m.group(1) if m else ''


def _request_broker_allocation_step(config: dict, ipv6: dict) -> tuple[Optional[str], Optional[str]]:
    """Run broker-client request + install. Returns (prefix, error)."""
    registry = ipv6.get('broker_registry')

    # Engine declares its session key in the manifest; fall back to 'blockchain'
    # for engines that don't declare one (legacy).
    session_key = 'blockchain'
    engine = config.get('_engine')
    if engine and engine.get('manifest'):
        declared = engine['manifest'].get('config_keys', {}).get('session_key')
        if declared:
            session_key = declared
    nft_contract = config.get(session_key, {}).get('nft_contract', '')

    if not nft_contract:
        return None, 'NFT contract address not available for broker request'
    if not registry:
        return None, 'Broker registry address not configured'

    # Step 1: Request allocation (no --configure-wg — broker-client writes its own
    # broker-allocation.json via save_allocation_config())
    result = subprocess.run(
        ['broker-client', '--registry-contract', registry, 'request',
         '--nft-contract', nft_contract,
         '--wallet-key', str(CONFIG_DIR / 'deployer.key')],
        capture_output=True, text=True, timeout=3600,
    )

    allocation_file = CONFIG_DIR / BROKER_ALLOCATION_FILE
    prefix = ''
    if allocation_file.exists():
        set_blockhost_ownership(allocation_file, 0o640)
        try:
            alloc_data = json.loads(allocation_file.read_text())
            prefix = alloc_data.get('prefix', alloc_data.get('ipv6_prefix', ''))
        except (json.JSONDecodeError, IOError):
            pass

    if not prefix:
        prefix = _extract_prefix_from_broker_stdout(result.stdout)

    if not prefix:
        return None, f'Broker allocation failed: {result.stderr or result.stdout or "no prefix in broker response"}'

    # Step 2: Install persistent WireGuard config (non-fatal on failure)
    install_result = subprocess.run(
        ['broker-client', '--registry-contract', registry, 'install'],
        capture_output=True, text=True, timeout=60,
    )
    if install_result.returncode != 0:
        print(f"Warning: broker-client install failed: {install_result.stderr}")

    # Step 3: Verify WireGuard tunnel is up; bring it up if not
    wg_check = subprocess.run(['wg', 'show'], capture_output=True, text=True, timeout=10)
    if wg_check.returncode != 0 or not wg_check.stdout.strip():
        subprocess.run(['wg-quick', 'up', 'wg-broker'], capture_output=True, timeout=30)

    return prefix, None


def _save_manual_allocation(ipv6: dict) -> str:
    """Manual mode: write broker-allocation.json from user-provided prefix."""
    prefix = ipv6.get('prefix', '')
    write_blockhost_file(
        CONFIG_DIR / 'broker-allocation.json',
        json.dumps({
            'prefix': prefix,
            'broker_node': '',
            'registry': '',
            'mode': 'manual',
        }, indent=2),
        mode=0o640,
    )
    return prefix


def _create_host_dummy_iface(network: ipaddress.IPv6Network):
    """Give the host its own routable /128 on dummy0; persist via systemd oneshot.

    The host's wg-broker address (::201) has routing issues from the WG topology;
    a dummy interface with ::202 sidesteps this with a separate routable /128.
    Proxmox bypasses ifupdown, so interfaces.d/ isn't reliable — use systemd.
    """
    try:
        host_addr = str(network.network_address + 2)

        # ip link add type dummy auto-loads the kernel module; explicit modprobe
        # only needed to ensure /etc/modules-load.d/dummy.conf is present.
        Path('/etc/modules-load.d/dummy.conf').write_text('dummy\n')
        _ip('link', 'add', 'dummy0', 'type', 'dummy')
        _ip('link', 'set', 'dummy0', 'up')
        _ip('-6', 'addr', 'add', f'{host_addr}/128', 'dev', 'dummy0')
        _ip('-6', 'route', 'add', f'{host_addr}/128', 'dev', 'wg-broker')

        service_file = Path('/etc/systemd/system/blockhost-dummy-ipv6.service')
        service_file.write_text(f"""[Unit]
Description=BlockHost host routable IPv6 (dummy interface)
After=wg-quick@wg-broker.service
Wants=wg-quick@wg-broker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip link add dummy0 type dummy
ExecStart=/sbin/ip link set dummy0 up
ExecStart=/sbin/ip -6 addr add {host_addr}/128 dev dummy0
ExecStart=/sbin/ip -6 route add {host_addr}/128 dev wg-broker
ExecStop=/sbin/ip link del dummy0

[Install]
WantedBy=multi-user.target
""")
        _systemctl('daemon-reload', timeout=10)
        _systemctl('enable', 'blockhost-dummy-ipv6', timeout=10)
    except (ValueError, subprocess.TimeoutExpired) as e:
        print(f"Warning: Could not create dummy interface: {e}")


def _add_bridge_gateway(network: ipaddress.IPv6Network):
    """Add the VM-facing IPv6 gateway address to the host bridge and persist it."""
    try:
        bridge_dev = _discover_bridge()
        if not bridge_dev:
            print("Warning: No bridge found for IPv6 gateway — skipping")
            return
        gw_addr = str(network.network_address + 1)

        # /128 to avoid conflicting with the /120 on wg-broker
        _ip('-6', 'addr', 'add', f'{gw_addr}/128', 'dev', bridge_dev)

        # interfaces.d/ confuses ifupdown on boot — must live in the same file
        # as the bridge's inet stanza.
        with open('/etc/network/interfaces', 'a') as f:
            f.write(
                f'\n# BlockHost IPv6 gateway address on bridge for VM connectivity\n'
                f'iface {bridge_dev} inet6 static\n'
                f'    address {gw_addr}/128\n'
            )
    except (ValueError, subprocess.TimeoutExpired) as e:
        print(f"Warning: Could not add IPv6 gateway to bridge: {e}")


def _persist_db_yaml_and_reserve_ipv6(network: ipaddress.IPv6Network, prefix: str):
    """Single pass: read db.yaml once, reserve host IPv6 addrs in vm-db, write ipv6_pool."""
    try:
        reserved = [
            str(network.network_address + 1),  # bridge gateway
            str(network.network_address + 2),  # dummy0 host address
        ]

        db_yaml = CONFIG_DIR / 'db.yaml'
        db_config = {}
        if db_yaml.exists():
            db_config = yaml.safe_load(db_yaml.read_text()) or {}
        db_file = Path(db_config.get('db_file') or DATA_DIR / 'vm-db.json')

        # Update vm-db.json (or create it)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        if db_file.exists():
            db = json.loads(db_file.read_text())
        else:
            db = {"vms": {}, "next_vmid": 100, "allocated_ips": [],
                  "allocated_ipv6": [], "reserved_nft_tokens": {}}
        allocated = db.setdefault("allocated_ipv6", [])
        for addr in reserved:
            if addr not in allocated:
                allocated.append(addr)
        db_file.write_text(json.dumps(db, indent=2))

        # Update db.yaml's ipv6_pool (only if db.yaml already existed — provisioner owns it)
        if db_yaml.exists():
            db_config['ipv6_pool'] = {'prefix': prefix}
            write_yaml(db_yaml, db_config)
    except Exception as e:
        print(f"Warning: Could not persist IPv6 reservations: {e}")


def _finalize_ipv6(config: dict) -> tuple[bool, Optional[str]]:
    """Configure IPv6: onion service, broker-tunnel allocation, or manual prefix.

    Sequences focused helpers; each step short-circuits or warns on failure
    rather than failing the whole step. The broker request itself is the only
    hard-fail.
    """
    ipv6 = config.get('ipv6', {})
    network_mode_file = CONFIG_DIR / 'network-mode'

    if ipv6.get('mode') == 'onion':
        network_mode_file.write_text('onion\n')
        try:
            _setup_onion_host_service()
        except Exception as e:
            return False, f'Failed to set up onion host service: {e}'
        return True, None  # Tor handles connectivity, no IPv6 needed

    try:
        _enable_ipv6_forwarding()

        if ipv6.get('mode') == 'broker':
            prefix, err = _request_broker_allocation_step(config, ipv6)
            if err:
                return False, err
            config['ipv6']['prefix'] = prefix
        elif ipv6.get('mode') == 'manual':
            config['ipv6']['prefix'] = _save_manual_allocation(ipv6)

        prefix = config.get('ipv6', {}).get('prefix', '')
        if prefix:
            try:
                network = ipaddress.IPv6Network(prefix, strict=False)
            except ValueError as e:
                print(f"Warning: Invalid IPv6 prefix '{prefix}': {e}")
            else:
                _create_host_dummy_iface(network)
                _add_bridge_gateway(network)
                _persist_db_yaml_and_reserve_ipv6(network, prefix)

        network_mode_file.write_text(f'{ipv6.get("mode", "none")}\n')
        return True, None
    except subprocess.TimeoutExpired:
        return False, 'Broker request timed out (180s)'
    except Exception as e:
        return False, str(e)


def _finalize_https(config: dict) -> tuple[bool, Optional[str]]:
    """Configure HTTPS using dns_zone (preferred) or sslip.io fallback, with Let's Encrypt."""
    ipv6 = config.get('ipv6', {})
    if ipv6.get('mode') == 'onion':
        return True, None  # Tor provides end-to-end encryption, no TLS needed
    try:
        ssl_dir = CONFIG_DIR / 'ssl'
        ssl_dir.mkdir(parents=True, exist_ok=True)

        # Try to get IPv6 address and dns_zone from broker allocation
        ipv6_address = None
        dns_zone = None
        ipv6_network = None
        broker_file = CONFIG_DIR / BROKER_ALLOCATION_FILE
        if broker_file.exists():
            broker_data = json.loads(broker_file.read_text())
            prefix = broker_data.get('prefix', '')
            dns_zone = broker_data.get('dns_zone', '')
            if prefix:
                ipv6_network = ipaddress.IPv6Network(prefix, strict=False)
                # Host's routable address is +2 in prefix (e.g., ::702 for ::700/120)
                # +1 is the VM gateway on the bridge, +2 is on dummy0 (publicly routable)
                ipv6_address = str(ipv6_network.network_address + 2)

        hostname = None
        use_dns_zone = False
        use_sslip = False

        if ipv6_address and dns_zone:
            # Preferred: derive hostname from dns_zone
            # offset = host IPv6 address - prefix base (part before :: in prefix notation)
            # e.g., prefix 2a11:6c7:f04:276::200/120, host ::201 → offset 0x201
            prefix_addr = broker_data['prefix'].split('/')[0]
            if '::' in prefix_addr:
                prefix_base = int(ipaddress.IPv6Address(prefix_addr.split('::')[0] + '::'))
            else:
                prefix_base = int(ipv6_network.network_address)
            offset = int(ipaddress.IPv6Address(ipv6_address)) - prefix_base
            hostname = f"{offset:x}.{dns_zone}"
            use_dns_zone = True
        elif ipv6_address:
            # Fallback: sslip.io (no dns_zone available)
            ipv6_dashed = ipv6_address.replace(':', '-')
            hostname = f"signup.{ipv6_dashed}.sslip.io"
            use_sslip = True
        else:
            # No IPv6 - check if user configured a custom domain
            ipv6_config = config.get('ipv6', {})
            custom_domain = ipv6_config.get('custom_domain')
            if custom_domain:
                hostname = custom_domain
            else:
                # Fall back to self-signed certificate
                hostname = socket.gethostname()

        # Store hostname in config for services to use
        https_config = {
            'hostname': hostname,
            'use_dns_zone': use_dns_zone,
            'use_sslip': use_sslip,
            'ipv6_address': ipv6_address,
            'cert_file': str(ssl_dir / 'cert.pem'),
            'key_file': str(ssl_dir / 'key.pem'),
        }

        if use_dns_zone or use_sslip or (hostname and '.' in hostname and not hostname.endswith('.local')):
            # Try to get Let's Encrypt certificate
            try:
                # Install certbot if missing (wizard binds :443; port 80 is free)
                if not shutil.which('certbot'):
                    subprocess.run(
                        ['apt-get', 'install', '-y', 'certbot'],
                        capture_output=True, timeout=300,
                    )

                # Bind certbot directly to port 80 — the wizard is on 443 during
                # finalization, and nginx hasn't been started yet.
                result = subprocess.run(
                    [
                        'certbot', 'certonly',
                        '--standalone',
                        '--http-01-port', '80',
                        '--non-interactive',
                        '--agree-tos',
                        '--register-unsafely-without-email',
                        '--domain', hostname,
                        '--cert-path', str(ssl_dir / 'cert.pem'),
                        '--key-path', str(ssl_dir / 'key.pem'),
                        '--fullchain-path', str(ssl_dir / 'fullchain.pem'),
                    ],
                    capture_output=True, text=True, timeout=120,
                )

                if result.returncode == 0:
                    https_config['tls_mode'] = 'letsencrypt'
                    # Update paths to Let's Encrypt's actual locations
                    le_path = Path(f'/etc/letsencrypt/live/{hostname}')
                    if le_path.exists():
                        https_config['cert_file'] = str(le_path / 'fullchain.pem')
                        https_config['key_file'] = str(le_path / 'privkey.pem')

                    # Switch renewal to webroot so certbot renews through nginx
                    # without needing to stop anything (standalone won't work
                    # post-reboot since nginx owns port 80)
                    certbot_webroot = Path('/var/www/certbot')
                    certbot_webroot.mkdir(parents=True, exist_ok=True)
                    renewal_conf = Path(f'/etc/letsencrypt/renewal/{hostname}.conf')
                    if renewal_conf.exists():
                        txt = renewal_conf.read_text()
                        txt = txt.replace(
                            'authenticator = standalone',
                            'authenticator = webroot',
                        )
                        if 'webroot_path' not in txt:
                            # certbot needs webroot_path in [renewalparams] AND
                            # the [[webroot]] domain mapping section
                            txt = txt.replace(
                                'authenticator = webroot',
                                'authenticator = webroot\nwebroot_path = /var/www/certbot,',
                            )
                            txt += f'\n[[webroot]]\n{hostname} = /var/www/certbot\n'
                        renewal_conf.write_text(txt)

                    # Deploy hook: reload nginx after renewal to pick up new cert
                    deploy_dir = Path('/etc/letsencrypt/renewal-hooks/deploy')
                    deploy_dir.mkdir(parents=True, exist_ok=True)
                    hook = deploy_dir / 'reload-nginx.sh'
                    hook.write_text('#!/bin/sh\nsystemctl reload nginx\n')
                    hook.chmod(0o755)
                else:
                    cause = (result.stderr or result.stdout or '').strip().splitlines()[-1:] or ['no detail']
                    print(f"certbot failed (rc={result.returncode}): {cause[0]}", file=sys.stderr)
                    generate_self_signed_cert_for_finalization(hostname, ssl_dir)
                    https_config['tls_mode'] = 'self-signed'
                    https_config['fallback_reason'] = cause[0]

            except Exception as e:
                print(f"certbot stage raised: {e!r}", file=sys.stderr)
                generate_self_signed_cert_for_finalization(hostname, ssl_dir)
                https_config['tls_mode'] = 'self-signed'
                https_config['fallback_reason'] = repr(e)
        else:
            # No valid domain, use self-signed
            generate_self_signed_cert_for_finalization(hostname, ssl_dir)
            https_config['tls_mode'] = 'self-signed'

        # Write HTTPS configuration
        https_config_file = CONFIG_DIR / 'https.json'
        https_config_file.write_text(json.dumps(https_config, indent=2))

        # Store in running config for other steps
        config['https'] = https_config

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_signup(config: dict) -> tuple[bool, Optional[str]]:
    """Generate signup page as a static file (served by nginx)."""
    try:
        signup_dir = Path('/var/www/blockhost')
        signup_dir.mkdir(parents=True, exist_ok=True)

        signup_file = signup_dir / 'signup.html'

        # Generate the signup page
        result = subprocess.run(
            ['blockhost-generate-signup', '--output', str(signup_file)],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            return False, f"Failed to generate signup page: {result.stderr}"

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_nginx(config: dict) -> tuple[bool, Optional[str]]:
    """Install and configure nginx as TLS reverse proxy for signup + admin panel."""
    try:
        # Install nginx
        result = subprocess.run(
            ['apt-get', 'install', '-y', 'nginx'],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode != 0:
            return False, f"Failed to install nginx: {result.stderr}"

        # Read HTTPS config for cert paths and hostname
        https_config = config.get('https', {})
        if not https_config:
            https_file = CONFIG_DIR / 'https.json'
            if https_file.exists():
                https_config = json.loads(https_file.read_text())

        hostname = https_config.get('hostname', socket.gethostname())
        cert_file = https_config.get('cert_file', str(CONFIG_DIR / 'ssl/cert.pem'))
        key_file = https_config.get('key_file', str(CONFIG_DIR / 'ssl/key.pem'))

        # Read admin panel path prefix
        admin_config_file = CONFIG_DIR / 'admin.json'
        admin_prefix = '/admin'
        if admin_config_file.exists():
            try:
                admin_cfg = json.loads(admin_config_file.read_text())
                p = admin_cfg.get('path_prefix', '/admin')
                admin_prefix = '/' + p.strip('/')
            except (json.JSONDecodeError, OSError):
                pass
        else:
            write_blockhost_file(
                admin_config_file,
                json.dumps({'path_prefix': '/admin'}, indent=2),
                mode=0o644,
            )

        # Engine-specific nginx locations (e.g. chain API reverse proxy)
        engine_locations = ""
        _engine = config.get('_engine')
        if _engine and _engine.get('module'):
            get_locs = getattr(_engine['module'], 'get_nginx_extra_locations', None)
            if get_locs:
                extra = get_locs(config)
                if extra:
                    # Indent each line for nginx block nesting
                    engine_locations = '\n' + extra.rstrip('\n') + '\n'

        # Write nginx config
        nginx_config = f"""server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {hostname};

    ssl_certificate {cert_file};
    ssl_certificate_key {key_file};

    # Signup page (static)
    root /var/www/blockhost;
    index signup.html;

    location / {{
        try_files $uri $uri/ /signup.html;
    }}

    # Admin panel — prefix strip proxies to Flask
    location {admin_prefix} {{
        proxy_pass http://127.0.0.1:8443/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
{engine_locations}
}}

server {{
    listen 80;
    listen [::]:80;
    server_name {hostname};

    # Let's Encrypt ACME challenge (webroot renewal)
    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}
"""
        sites_available = Path('/etc/nginx/sites-available/blockhost')
        sites_available.write_text(nginx_config)

        sites_enabled = Path('/etc/nginx/sites-enabled/blockhost')
        default_enabled = Path('/etc/nginx/sites-enabled/default')

        # Symlink to sites-enabled
        if sites_enabled.exists() or sites_enabled.is_symlink():
            sites_enabled.unlink()
        sites_enabled.symlink_to(sites_available)

        # Remove default site
        if default_enabled.exists() or default_enabled.is_symlink():
            default_enabled.unlink()

        # Verify config
        result = subprocess.run(
            ['nginx', '-t'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return False, f"nginx config validation failed: {result.stderr}"

        # Enable but do NOT start — nginx starts on reboot
        _systemctl('enable', 'nginx')
        # apt-get install often auto-starts nginx; stop it
        _systemctl('stop', 'nginx')

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_complete(config: dict) -> tuple[bool, Optional[str]]:
    """Finalize setup: write admin config, enable services, mark complete.

    Chain-specific operations (plan creation, revenue sharing, monitor service)
    are handled by engine post-finalization steps. This step only handles
    chain-agnostic admin config and system housekeeping.
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        admin_commands = config.get('admin_commands', {})
        admin_signature = config.get('admin_signature', '')

        # Write admin-commands.json if admin commands are enabled
        if admin_commands.get('enabled') and admin_commands.get('knock_command'):
            commands_db = {
                'commands': {
                    admin_commands['knock_command']: {
                        'action': 'knock',
                        'description': 'Open configured ports temporarily',
                        'params': {
                            'allowed_ports': admin_commands.get('knock_ports', [22]),
                            'default_duration': admin_commands.get('knock_timeout', 300),
                        }
                    }
                }
            }
            (CONFIG_DIR / 'admin-commands.json').write_text(
                json.dumps(commands_db, indent=2) + '\n'
            )

        # Write admin signature for NFT #0 minting (used by engine mint step)
        if admin_signature:
            write_blockhost_file(CONFIG_DIR / 'admin-signature.key', admin_signature)

        # Enable chain-agnostic blockhost services (will start on reboot)
        # Note: blockhost-monitor is engine-specific — enabled by engine post-step
        _systemctl('enable', 'blockhost-admin')
        _systemctl('enable', 'blockhost-gc.timer')

        # State dir owned by blockhost; libvirt-qemu needs traverse access for VM disks/cloud-init ISOs
        _chown_recursive(str(DATA_DIR), 'blockhost', 'blockhost')
        os.chmod(DATA_DIR, 0o755)

        # Config dir: root:blockhost with group-readable contents
        _chown_recursive(str(CONFIG_DIR), 'root', 'blockhost')
        os.chmod(CONFIG_DIR, 0o750)

        # Write setup complete marker
        (DATA_DIR / '.setup-complete').touch()

        # Disable and stop first-boot service
        _systemctl('disable', 'blockhost-firstboot')
        _systemctl('stop', 'blockhost-firstboot')

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_validate(config: dict) -> tuple[bool, Optional[str]]:
    """Run comprehensive system validation (testing mode only).

    This step only runs on ISOs built with --testing flag.
    It validates all configuration files, services, and system state.
    """
    try:
        from installer.web.validate_system import validate_system, is_testing_mode

        if not is_testing_mode():
            # Skip validation on production builds
            return True, None

        # Run full validation
        success, message = validate_system()

        if success:
            return True, None
        else:
            # Return detailed error message
            return False, f"Validation failed:\n{message}"

    except ImportError as e:
        # If module can't be imported, skip (don't fail the install)
        return True, None
    except Exception as e:
        return False, f"Validation error: {str(e)}"
