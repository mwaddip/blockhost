"""
BlockHost Web Installer - Finalization Pipeline

The finalization pipeline: step functions, orchestration, and helpers.
All step functions are private to this module. The public API is:
- get_finalization_steps(provisioner, engine) — returns step tuples
- run_finalization_with_state(setup_state, config, provisioner, engine) — orchestration loop
- run_finalization(job_id, config, jobs, provisioner, engine) — legacy wrapper

Chain-specific steps (wallet, contracts, config, mint_nft, plan,
revenue_share) are provided by the engine wizard plugin. This module
contains chain-agnostic infrastructure steps (keypair, ipv6, https, etc.).
"""

import ipaddress
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

from installer.web.utils import (
    set_blockhost_ownership,
    parse_pam_ciphertext,
    write_yaml,
    generate_self_signed_cert_for_finalization,
)


def get_finalization_steps(provisioner, engine=None) -> list[tuple]:
    """Build the finalization step list, injecting engine and provisioner steps.

    Step order:
    1. Infrastructure steps (keypair — chain-agnostic, needed before engine)
    2. Engine pre-steps (from plugin: wallet, contracts, chain_config)
    3. Provisioner steps (from plugin: token, terraform, bridge, template)
    4. Post steps (ipv6, https, signup, nginx)
    5. Engine post-steps (from plugin: mint_nft, plan, revenue_share)
    6. Final steps (finalize, validate)
    """
    # Infrastructure steps (chain-agnostic, run before engine)
    infra_steps = [
        ('keypair', 'Generating server keypair', _finalize_keypair),
    ]

    # Engine pre-steps (chain-specific)
    engine_steps = []
    if engine and engine.get('module'):
        eng_mod = engine['module']
        if hasattr(eng_mod, 'get_finalization_steps'):
            engine_steps = eng_mod.get_finalization_steps()

    # Provisioner steps (from plugin)
    provisioner_steps = []
    if provisioner and provisioner.get('module'):
        prov_mod = provisioner['module']
        if hasattr(prov_mod, 'get_finalization_steps'):
            provisioner_steps = prov_mod.get_finalization_steps()

    post_steps = [
        ('ipv6', 'Configuring IPv6', _finalize_ipv6),
        ('https', 'Configuring HTTPS', _finalize_https),
        ('signup', 'Generating signup page', _finalize_signup),
        ('nginx', 'Setting up nginx reverse proxy', _finalize_nginx),
    ]

    # Engine post-steps (need hostname from https step)
    engine_post_steps = []
    if engine and engine.get('module'):
        eng_mod = engine['module']
        if hasattr(eng_mod, 'get_post_finalization_steps'):
            engine_post_steps = eng_mod.get_post_finalization_steps()

    final_steps = [
        ('finalize', 'Finalizing setup', _finalize_complete),
        ('validate', 'Validating system (testing only)', _finalize_validate),
    ]

    return infra_steps + engine_steps + provisioner_steps + post_steps + engine_post_steps + final_steps


def run_finalization_with_state(setup_state, config: dict, provisioner, engine=None):
    """Run the full finalization process with persistent state tracking."""
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
                                alloc_file = Path('/etc/blockhost/broker-allocation.json')
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


def run_finalization(job_id: str, config: dict, jobs: dict, provisioner, engine=None):
    """Legacy wrapper - run finalization with job-based tracking."""
    # Import SetupState here to avoid circular import at module level
    from installer.web.app import SetupState

    setup_state = SetupState()
    setup_state.start(config)
    run_finalization_with_state(setup_state, config, provisioner, engine)

    # Update job status from setup state
    if job_id in jobs:
        state_response = setup_state.to_api_response()
        jobs[job_id].update(state_response)


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


# ---------------------------------------------------------------------------
# Step functions (private to this module — chain-agnostic infrastructure)
# ---------------------------------------------------------------------------

CONFIG_DIR = Path('/etc/blockhost')


def _finalize_keypair(config: dict) -> tuple[bool, Optional[str]]:
    """Generate server ECIES keypair (server.key + server.pubkey).

    Uses pam_web3_tool (secp256k1) — not chain-specific, every engine
    needs this for PAM authentication infrastructure.

    Idempotent: skips if both files already exist.
    No step result data — summary shows just "Completed".
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        server_key = CONFIG_DIR / 'server.key'
        server_pubkey = CONFIG_DIR / 'server.pubkey'

        if server_key.exists() and server_pubkey.exists():
            return True, None

        # Generate keypair
        result = subprocess.run(
            ['pam_web3_tool', 'generate-keypair'],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return False, f'Keypair generation failed: {result.stderr}'

        # Parse private key from output (bare hex, 64 chars, no 0x prefix)
        # pam_web3_tool outputs lines like:
        #   Private key (hex): abcdef1234...
        #   Public key (hex): 04abcdef...
        private_key = ''
        public_key = ''
        for line in result.stdout.strip().split('\n'):
            lower = line.lower()
            if 'private' in lower and ':' in line:
                val = line.split(':', 1)[1].strip().replace('0x', '')
                if len(val) == 64 and all(c in '0123456789abcdefABCDEF' for c in val):
                    private_key = val
            elif 'public' in lower and ':' in line:
                val = line.split(':', 1)[1].strip()
                val_clean = val.replace('0x', '')
                if len(val_clean) >= 128 and all(c in '0123456789abcdefABCDEF' for c in val_clean):
                    public_key = f'0x{val_clean}'

        # Fallback: try bare hex lines (two lines: private, public)
        if not private_key:
            for line in result.stdout.strip().split('\n'):
                stripped = line.strip().replace('0x', '')
                if len(stripped) == 64 and all(c in '0123456789abcdefABCDEF' for c in stripped):
                    private_key = stripped
                    break

        if not private_key:
            return False, 'Could not parse private key from keypair output'

        # Write server.key (hex, 64 chars, no 0x prefix)
        server_key.write_text(private_key)
        set_blockhost_ownership(server_key, 0o640)

        # Derive public key if not parsed from generate-keypair output
        if not public_key:
            result2 = subprocess.run(
                ['pam_web3_tool', 'derive-pubkey', '--private-key', private_key],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result2.returncode == 0:
                for line in result2.stdout.strip().split('\n'):
                    if ':' in line:
                        val = line.split(':', 1)[1].strip()
                    else:
                        val = line.strip()
                    val_clean = val.replace('0x', '')
                    if len(val_clean) >= 128 and all(c in '0123456789abcdefABCDEF' for c in val_clean):
                        public_key = f'0x{val_clean}'
                        break
            if not public_key:
                return False, 'Could not derive public key from private key'

        # Write server.pubkey (hex with 0x prefix)
        server_pubkey.write_text(public_key)
        set_blockhost_ownership(server_pubkey, 0o644)

        return True, None
    except FileNotFoundError:
        return False, 'pam_web3_tool not installed'
    except subprocess.TimeoutExpired:
        return False, 'Keypair generation timed out'
    except Exception as e:
        return False, str(e)


def _finalize_ipv6(config: dict) -> tuple[bool, Optional[str]]:
    """Configure IPv6 tunnel if using broker, or save manual prefix.

    For broker mode:
    1. Request allocation (broker-client saves its own config)
    2. Install persistent WireGuard config
    3. Enable IPv6 forwarding
    """
    try:
        ipv6 = config.get('ipv6', {})

        # Enable IPv6 forwarding (needed for VM traffic regardless of mode)
        subprocess.run(
            ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1'],
            capture_output=True,
            timeout=10
        )
        sysctl_dir = Path('/etc/sysctl.d')
        sysctl_dir.mkdir(parents=True, exist_ok=True)
        (sysctl_dir / '99-blockhost-ipv6.conf').write_text(
            'net.ipv6.conf.all.forwarding=1\n'
        )

        if ipv6.get('mode') == 'broker':
            registry = ipv6.get('broker_registry')
            blockchain = config.get('blockchain', {})
            nft_contract = blockchain.get('nft_contract', '')

            if not nft_contract:
                return False, 'NFT contract address not available for broker request'

            if not registry:
                return False, 'Broker registry address not configured'

            # Step 1: Request allocation (no --configure-wg — let broker-client
            # save its own broker-allocation.json via save_allocation_config())
            cmd = [
                'broker-client',
                '--registry-contract', registry,
                'request',
                '--nft-contract', nft_contract,
                '--wallet-key', '/etc/blockhost/deployer.key',
                '--timeout', '120',
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )

            # Don't bail on non-zero if stdout contains allocation data
            allocation_file = Path('/etc/blockhost/broker-allocation.json')
            prefix = ''

            if allocation_file.exists():
                # broker-client wrote it — fix permissions and read prefix
                set_blockhost_ownership(allocation_file, 0o640)
                try:
                    alloc_data = json.loads(allocation_file.read_text())
                    prefix = alloc_data.get('prefix', alloc_data.get('ipv6_prefix', ''))
                except (json.JSONDecodeError, IOError):
                    pass

            if not prefix:
                # Fallback: parse from stdout
                import re
                for line in (result.stdout or '').strip().split('\n'):
                    if line.strip().startswith('{'):
                        try:
                            data = json.loads(line)
                            prefix = data.get('prefix', data.get('ipv6_prefix', ''))
                            if prefix:
                                break
                        except json.JSONDecodeError:
                            pass
                if not prefix:
                    prefix_match = re.search(r'prefix[:\s]+([0-9a-fA-F:]+/\d+)', result.stdout or '')
                    if prefix_match:
                        prefix = prefix_match.group(1)

            if not prefix:
                error_msg = result.stderr or result.stdout or 'No prefix in broker response'
                return False, f'Broker allocation failed: {error_msg}'

            # Store prefix in config for later steps (https, step data)
            config['ipv6']['prefix'] = prefix

            # Step 2: Install persistent WireGuard config
            install_result = subprocess.run(
                [
                    'broker-client',
                    '--registry-contract', registry,
                    'install',
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            if install_result.returncode != 0:
                # Non-fatal warning — tunnel may work ephemerally
                print(f"Warning: broker-client install failed: {install_result.stderr}")

            # Step 3: Verify WireGuard tunnel is up
            wg_check = subprocess.run(
                ['wg', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if wg_check.returncode != 0 or not wg_check.stdout.strip():
                # Try to bring up the tunnel manually
                subprocess.run(
                    ['wg-quick', 'up', 'wg-broker'],
                    capture_output=True,
                    timeout=30
                )

        elif ipv6.get('mode') == 'manual':
            # Manual mode - just save the provided prefix
            allocation_file = Path('/etc/blockhost/broker-allocation.json')
            allocation_file.write_text(json.dumps({
                'prefix': ipv6.get('prefix', ''),
                'broker_node': '',
                'registry': '',
                'mode': 'manual',
            }, indent=2))
            set_blockhost_ownership(allocation_file, 0o640)
            config['ipv6']['prefix'] = ipv6.get('prefix', '')

        # Step 4: Create dummy interface with host's own routable IPv6 address
        # The host's wg-broker address (::201) has routing issues due to the
        # WireGuard tunnel topology. A dummy interface with ::202 sidesteps
        # this by giving the host a separate routable /128 address.
        prefix = config.get('ipv6', {}).get('prefix', '')
        if prefix:
            try:
                network = ipaddress.IPv6Network(prefix, strict=False)
                host_addr = str(network.network_address + 2)

                # Load dummy module
                subprocess.run(
                    ['modprobe', 'dummy'],
                    capture_output=True, timeout=10
                )
                Path('/etc/modules-load.d/dummy.conf').write_text('dummy\n')

                # Create and configure dummy0
                subprocess.run(
                    ['ip', 'link', 'add', 'dummy0', 'type', 'dummy'],
                    capture_output=True, timeout=10
                )
                subprocess.run(
                    ['ip', 'link', 'set', 'dummy0', 'up'],
                    capture_output=True, timeout=10
                )
                subprocess.run(
                    ['ip', '-6', 'addr', 'add', f'{host_addr}/128', 'dev', 'dummy0'],
                    capture_output=True, timeout=10
                )
                subprocess.run(
                    ['ip', '-6', 'route', 'add', f'{host_addr}/128', 'dev', 'wg-broker'],
                    capture_output=True, timeout=10
                )

                # Persist via systemd oneshot (works on both Proxmox and standard Debian
                # — Proxmox bypasses ifupdown, so interfaces.d/ is not reliable)
                service_content = f"""[Unit]
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
"""
                service_file = Path('/etc/systemd/system/blockhost-dummy-ipv6.service')
                service_file.write_text(service_content)
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=10)
                subprocess.run(['systemctl', 'enable', 'blockhost-dummy-ipv6'], capture_output=True, timeout=10)
            except (ValueError, subprocess.TimeoutExpired) as e:
                print(f"Warning: Could not create dummy interface: {e}")

        # Step 5: Add gateway address to bridge for VM connectivity
        # VMs use the first host address in the prefix as their IPv6 gateway.
        # This address must exist on the bridge VMs are connected to.
        prefix = config.get('ipv6', {}).get('prefix', '')
        if prefix:
            try:
                bridge_dev = _discover_bridge()
                if not bridge_dev:
                    print("Warning: No bridge found for IPv6 gateway — skipping")
                else:
                    network = ipaddress.IPv6Network(prefix, strict=False)
                    gw_addr = str(network.network_address + 1)

                    # Add to bridge as /128 to avoid conflicting with the /120 on wg-broker
                    subprocess.run(
                        ['ip', '-6', 'addr', 'add', f'{gw_addr}/128', 'dev', bridge_dev],
                        capture_output=True,
                        timeout=10
                    )

                    # Persist: append inet6 stanza to /etc/network/interfaces
                    # Must be in the same file as the bridge's inet stanza —
                    # a separate interfaces.d/ file confuses ifupdown on boot.
                    with open('/etc/network/interfaces', 'a') as f:
                        f.write(
                            f'\n# BlockHost IPv6 gateway address on bridge for VM connectivity\n'
                            f'iface {bridge_dev} inet6 static\n'
                            f'    address {gw_addr}/128\n'
                        )
            except (ValueError, subprocess.TimeoutExpired) as e:
                print(f"Warning: Could not add IPv6 gateway to bridge: {e}")

        # Reserve host infrastructure IPv6 addresses in VM database so the
        # allocator never hands them out to VMs.
        if prefix:
            try:
                network = ipaddress.IPv6Network(prefix, strict=False)
                reserved = [
                    str(network.network_address + 1),  # bridge gateway
                    str(network.network_address + 2),  # dummy0 host address
                ]
                # Read db_file path from db.yaml (written by provisioner)
                db_yaml = CONFIG_DIR / 'db.yaml'
                db_file = Path('/var/lib/blockhost/vm-db.json')  # fallback
                if db_yaml.exists():
                    import yaml
                    db_conf = yaml.safe_load(db_yaml.read_text()) or {}
                    if db_conf.get('db_file'):
                        db_file = Path(db_conf['db_file'])
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
            except Exception as e:
                print(f"Warning: Could not reserve host IPv6 in VM database: {e}")

        # Append ipv6_pool to db.yaml (written by provisioner in an earlier step)
        if prefix:
            db_yaml = CONFIG_DIR / 'db.yaml'
            if db_yaml.exists():
                try:
                    import yaml
                    db_config = yaml.safe_load(db_yaml.read_text()) or {}
                    db_config['ipv6_pool'] = {'prefix': prefix}
                    write_yaml(db_yaml, db_config)
                except Exception as e:
                    print(f"Warning: Could not add ipv6_pool to db.yaml: {e}")

        return True, None
    except subprocess.TimeoutExpired:
        return False, 'Broker request timed out (180s)'
    except Exception as e:
        return False, str(e)


def _finalize_https(config: dict) -> tuple[bool, Optional[str]]:
    """Configure HTTPS using dns_zone (preferred) or sslip.io fallback, with Let's Encrypt."""
    try:
        config_dir = Path('/etc/blockhost')
        ssl_dir = config_dir / 'ssl'
        ssl_dir.mkdir(parents=True, exist_ok=True)

        # Try to get IPv6 address and dns_zone from broker allocation
        ipv6_address = None
        dns_zone = None
        ipv6_network = None
        broker_file = config_dir / 'broker-allocation.json'
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
                # Check if certbot is available
                certbot_check = subprocess.run(['which', 'certbot'], capture_output=True)
                if certbot_check.returncode != 0:
                    # Install certbot if not present
                    subprocess.run(
                        ['apt-get', 'install', '-y', 'certbot'],
                        capture_output=True,
                        timeout=300
                    )

                # Run certbot for HTTP-01 challenge
                # Use --http-01-port on a free port, redirect :80 via iptables
                # (the wizard is already listening on :80 IPv4)
                # Both iptables (IPv4) and ip6tables (IPv6) needed — Let's Encrypt
                # may connect over either protocol depending on DNS resolution.
                _redirect_rule = ['-t', 'nat', '-p', 'tcp',
                                  '--dport', '80', '-j', 'REDIRECT', '--to-port', '8088']
                for cmd in ['iptables', 'ip6tables']:
                    subprocess.run(
                        [cmd, '-A', 'PREROUTING'] + _redirect_rule,
                        capture_output=True, timeout=10
                    )
                try:
                    result = subprocess.run(
                        [
                            'certbot', 'certonly',
                            '--standalone',
                            '--http-01-port', '8088',
                            '--non-interactive',
                            '--agree-tos',
                            '--register-unsafely-without-email',
                            '--domain', hostname,
                            '--cert-path', str(ssl_dir / 'cert.pem'),
                            '--key-path', str(ssl_dir / 'key.pem'),
                            '--fullchain-path', str(ssl_dir / 'fullchain.pem'),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                finally:
                    for cmd in ['iptables', 'ip6tables']:
                        subprocess.run(
                            [cmd, '-D', 'PREROUTING'] + _redirect_rule,
                            capture_output=True, timeout=10
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
                    # Let's Encrypt failed, fall back to self-signed
                    generate_self_signed_cert_for_finalization(hostname, ssl_dir)
                    https_config['tls_mode'] = 'self-signed'

            except Exception as e:
                # Certbot failed, use self-signed
                generate_self_signed_cert_for_finalization(hostname, ssl_dir)
                https_config['tls_mode'] = 'self-signed'
        else:
            # No valid domain, use self-signed
            generate_self_signed_cert_for_finalization(hostname, ssl_dir)
            https_config['tls_mode'] = 'self-signed'

        # Write HTTPS configuration
        https_config_file = config_dir / 'https.json'
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
            https_file = Path('/etc/blockhost/https.json')
            if https_file.exists():
                https_config = json.loads(https_file.read_text())

        hostname = https_config.get('hostname', socket.gethostname())
        cert_file = https_config.get('cert_file', '/etc/blockhost/ssl/cert.pem')
        key_file = https_config.get('key_file', '/etc/blockhost/ssl/key.pem')

        # Read admin panel path prefix
        admin_config_file = Path('/etc/blockhost/admin.json')
        admin_prefix = '/admin'
        if admin_config_file.exists():
            try:
                admin_cfg = json.loads(admin_config_file.read_text())
                p = admin_cfg.get('path_prefix', '/admin')
                admin_prefix = '/' + p.strip('/')
            except (json.JSONDecodeError, OSError):
                pass
        else:
            # Write default config
            admin_config_file.write_text(json.dumps(
                {'path_prefix': '/admin'}, indent=2))
            set_blockhost_ownership(admin_config_file, 0o644)

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
        subprocess.run(
            ['systemctl', 'enable', 'nginx'],
            capture_output=True,
            timeout=30
        )

        # Stop nginx if apt started it (apt-get install often auto-starts it)
        subprocess.run(
            ['systemctl', 'stop', 'nginx'],
            capture_output=True,
            timeout=30
        )

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
        config_dir = Path('/etc/blockhost')
        config_dir.mkdir(parents=True, exist_ok=True)
        marker_dir = Path('/var/lib/blockhost')
        marker_dir.mkdir(parents=True, exist_ok=True)

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
            (config_dir / 'admin-commands.json').write_text(
                json.dumps(commands_db, indent=2) + '\n'
            )

        # Write admin signature for NFT #0 minting (used by engine mint step)
        if admin_signature:
            sig_file = config_dir / 'admin-signature.key'
            sig_file.write_text(admin_signature)
            set_blockhost_ownership(sig_file, 0o640)

        # Enable chain-agnostic blockhost services (will start on reboot)
        # Note: blockhost-monitor is engine-specific — enabled by engine post-step
        subprocess.run(
            ['systemctl', 'enable', 'blockhost-admin'],
            capture_output=True,
            timeout=30
        )
        subprocess.run(
            ['systemctl', 'enable', 'blockhost-gc.timer'],
            capture_output=True,
            timeout=30
        )

        # Ensure state dir is owned by blockhost user
        subprocess.run(
            ['chown', '-R', 'blockhost:blockhost', '/var/lib/blockhost'],
            capture_output=True, timeout=30
        )
        # libvirt-qemu needs to traverse to access VM disk images and cloud-init ISOs
        subprocess.run(
            ['chmod', '755', '/var/lib/blockhost'],
            capture_output=True, timeout=30
        )

        # Ensure config dir has correct group ownership
        subprocess.run(
            ['chown', '-R', 'root:blockhost', '/etc/blockhost'],
            capture_output=True, timeout=30
        )
        subprocess.run(
            ['chmod', '750', '/etc/blockhost'],
            capture_output=True, timeout=30
        )

        # Write setup complete marker
        (marker_dir / '.setup-complete').touch()

        # Disable and stop first-boot service
        subprocess.run(
            ['systemctl', 'disable', 'blockhost-firstboot'],
            capture_output=True,
            timeout=30
        )
        subprocess.run(
            ['systemctl', 'stop', 'blockhost-firstboot'],
            capture_output=True,
            timeout=30
        )

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
