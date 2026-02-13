"""
BlockHost Web Installer - Finalization Pipeline

The finalization pipeline: step functions, orchestration, and helpers.
All step functions are private to this module. The public API is:
- get_finalization_steps(provisioner) — returns step tuples
- run_finalization_with_state(setup_state, config, provisioner) — orchestration loop
- run_finalization(job_id, config, jobs, provisioner) — legacy wrapper
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
    generate_secp256k1_keypair_with_pubkey,
    get_address_from_key,
    is_valid_address,
    parse_pam_ciphertext,
    write_yaml,
    generate_self_signed_cert_for_finalization,
)

# USDC contract addresses by chain ID
USDC_BY_CHAIN = {
    11155111: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',  # Sepolia
    1: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',         # Mainnet
    137: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',       # Polygon
    42161: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',     # Arbitrum
}


def get_finalization_steps(provisioner) -> list[tuple]:
    """Build the finalization step list, injecting provisioner steps dynamically.

    Step order:
    1. Core steps (keypair, wallet, contracts, config)
    2. Provisioner steps (from plugin: token, terraform, bridge, template)
    3. Post steps (ipv6, https, signup, mint_nft, finalize, validate)
    """
    core_steps = [
        ('keypair', 'Generating server keypair', _finalize_keypair),
        ('wallet', 'Configuring deployer wallet', _finalize_wallet),
        ('contracts', 'Handling contracts', _finalize_contracts),
        ('config', 'Writing configuration files', _finalize_config),
    ]

    # Get provisioner finalization steps from plugin
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
        ('mint_nft', 'Minting admin NFT', _finalize_mint_nft),
        ('finalize', 'Finalizing setup', _finalize_complete),
        ('validate', 'Validating system (testing only)', _finalize_validate),
    ]

    return core_steps + provisioner_steps + post_steps


def run_finalization_with_state(setup_state, config: dict, provisioner):
    """Run the full finalization process with persistent state tracking."""
    steps = get_finalization_steps(provisioner)

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
                    # Attach step data for UI display
                    step_data = None
                    if step_id == 'wallet':
                        deployer_key = config.get('blockchain', {}).get('deployer_key')
                        addr = get_address_from_key(deployer_key) if deployer_key else None
                        if addr:
                            step_data = {'deployer_address': addr}
                    elif step_id == 'contracts' and config.get('contracts'):
                        step_data = {'contracts': config['contracts']}
                    elif step_id == 'ipv6':
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
                    elif step_id == 'mint_nft' and config.get('mint_nft_result'):
                        step_data = config['mint_nft_result']
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


def run_finalization(job_id: str, config: dict, jobs: dict, provisioner):
    """Legacy wrapper - run finalization with job-based tracking."""
    # Import SetupState here to avoid circular import at module level
    from installer.web.app import SetupState

    setup_state = SetupState()
    setup_state.start(config)
    run_finalization_with_state(setup_state, config, provisioner)

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


def _parse_cast_int(raw: str) -> int:
    """Parse integer from cast call/send output (handles both hex and decimal)."""
    raw = raw.strip()
    return int(raw, 16) if raw.startswith('0x') else int(raw)


# ---------------------------------------------------------------------------
# Step functions (private to this module)
# ---------------------------------------------------------------------------

def _finalize_keypair(config: dict) -> tuple[bool, Optional[str]]:
    """Generate server keypair for ECIES encryption."""
    try:
        config_dir = Path('/etc/blockhost')
        config_dir.mkdir(parents=True, exist_ok=True)

        key_file = config_dir / 'server.key'

        private_key, address, public_key = generate_secp256k1_keypair_with_pubkey()

        # Write private key without 0x prefix (pam_web3_tool expects raw hex)
        private_key_raw = private_key[2:] if private_key.startswith('0x') else private_key
        key_file.write_text(private_key_raw)
        set_blockhost_ownership(key_file, 0o640)

        # Write public key separately (for signup page ECIES encryption)
        pubkey_file = config_dir / 'server.pubkey'
        pubkey_file.write_text(public_key)
        pubkey_file.chmod(0o644)

        # Store in running config for later steps
        config['server_address'] = address
        config['server_public_key'] = public_key

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_wallet(config: dict) -> tuple[bool, Optional[str]]:
    """Configure deployer wallet."""
    try:
        blockchain = config.get('blockchain', {})
        deployer_key = blockchain.get('deployer_key')

        if not deployer_key:
            return False, 'No deployer key configured'

        key_file = Path('/etc/blockhost/deployer.key')
        key_file.parent.mkdir(parents=True, exist_ok=True)

        key_file.write_text(deployer_key)
        set_blockhost_ownership(key_file, 0o640)

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_contracts(config: dict) -> tuple[bool, Optional[str]]:
    """Deploy or verify contracts."""
    try:
        blockchain = config.get('blockchain', {})

        if blockchain.get('contract_mode') == 'existing':
            # Verify existing contracts are accessible
            # For now, just check format
            nft = blockchain.get('nft_contract')
            sub = blockchain.get('subscription_contract')

            if not is_valid_address(nft) or not is_valid_address(sub):
                return False, 'Invalid contract addresses'

            config['contracts'] = {
                'nft': nft,
                'subscription': sub,
            }
        else:
            # Deploy new contracts using Foundry
            rpc_url = blockchain.get('rpc_url')
            deployer_key = blockchain.get('deployer_key')

            if not rpc_url or not deployer_key:
                return False, 'Missing RPC URL or deployer key'

            # Ensure deployer key has 0x prefix
            if not deployer_key.startswith('0x'):
                deployer_key = '0x' + deployer_key

            contracts_dir = Path('/usr/share/blockhost/contracts')

            # Deploy NFT contract (AccessCredentialNFT)
            # Constructor: (string name, string symbol, string defaultImageUri)
            nft_address, err = _deploy_contract_with_forge(
                contracts_dir / 'AccessCredentialNFT.json',
                rpc_url,
                deployer_key,
                constructor_args=['BlockHost Access', 'BHAC', '']
            )
            if err:
                return False, f'NFT contract deployment failed: {err}'

            # Deploy Subscription/PoS contract (no constructor args)
            sub_address, err = _deploy_contract_with_forge(
                contracts_dir / 'BlockhostSubscriptions.json',
                rpc_url,
                deployer_key,
                constructor_args=[]
            )
            if err:
                return False, f'Subscription contract deployment failed: {err}'

            config['contracts'] = {
                'nft': nft_address,
                'subscription': sub_address,
            }

        return True, None
    except Exception as e:
        return False, str(e)


def _deploy_contract_with_forge(
    artifact_path: Path,
    rpc_url: str,
    private_key: str,
    constructor_args: list = None
) -> tuple[Optional[str], Optional[str]]:
    """Deploy a contract using cast send --create."""
    import json as json_module

    if not artifact_path.exists():
        return None, f'Contract artifact not found: {artifact_path}'

    try:
        # Load contract artifact
        with open(artifact_path) as f:
            artifact = json_module.load(f)

        # Get contract name from artifact
        contract_name = artifact.get('contractName', artifact_path.stem)

        # Check if we have bytecode - handle different artifact formats
        bytecode = artifact.get('bytecode', artifact.get('bin', ''))
        if isinstance(bytecode, dict):
            bytecode = bytecode.get('object', '')
        if not bytecode:
            # Try Foundry output format
            bytecode = artifact.get('bytecode', {}).get('object', '')

        # Ensure 0x prefix
        if bytecode and not bytecode.startswith('0x'):
            bytecode = '0x' + bytecode

        if not bytecode or bytecode == '0x':
            return None, f'No bytecode found in artifact: {artifact_path}'

        # If there are constructor args, we need to ABI-encode them and append to bytecode
        if constructor_args:
            abi = artifact.get('abi', [])
            constructor = next((x for x in abi if x.get('type') == 'constructor'), None)
            if constructor and constructor.get('inputs'):
                # Build constructor signature for encoding
                input_types = [inp['type'] for inp in constructor['inputs']]
                sig = f"constructor({','.join(input_types)})"

                # Use cast to encode constructor args
                encode_cmd = ['cast', 'abi-encode', sig] + [str(a) for a in constructor_args]
                encode_result = subprocess.run(encode_cmd, capture_output=True, text=True)

                if encode_result.returncode == 0:
                    encoded_args = encode_result.stdout.strip()
                    # Remove 0x prefix from encoded args and append to bytecode
                    if encoded_args.startswith('0x'):
                        encoded_args = encoded_args[2:]
                    bytecode = bytecode + encoded_args

        # Use cast to deploy with raw bytecode
        cmd = [
            'cast', 'send',
            '--rpc-url', rpc_url,
            '--private-key', private_key,
            '--create', bytecode,
            '--json'
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180  # 3 minutes for slow networks
        )

        if result.returncode != 0:
            return None, f'Deployment failed: {result.stderr}'

        # Parse the deployed address from JSON output
        try:
            output = json_module.loads(result.stdout)
            contract_address = output.get('contractAddress')
            if contract_address:
                return contract_address, None
        except json_module.JSONDecodeError:
            pass

        # Try to parse from non-JSON output
        # Look for "Deployed to: 0x..." pattern
        import re
        match = re.search(r'(?:contractAddress|Deployed to)[:\s]+([0-9a-fA-Fx]+)', result.stdout)
        if match:
            return match.group(1), None

        return None, f'Could not parse deployed address from output: {result.stdout}'

    except subprocess.TimeoutExpired:
        return None, 'Contract deployment timed out (120s)'
    except Exception as e:
        return None, str(e)


def _finalize_config(config: dict) -> tuple[bool, Optional[str]]:
    """Write configuration files."""
    try:
        config_dir = Path('/etc/blockhost')
        config_dir.mkdir(parents=True, exist_ok=True)

        blockchain = config.get('blockchain', {})
        provisioner = config.get('provisioner', {})
        ipv6 = config.get('ipv6', {})
        contracts = config.get('contracts', {})
        admin_commands = config.get('admin_commands', {})
        admin_wallet = config.get('admin_wallet', '')

        # Write db.yaml — shared keys always, provisioner-specific keys conditionally
        db_config = {
            'db_file': '/var/lib/blockhost/vms.json',
            'ipv6_pool': {
                'start': 1,  # First usable offset after network address
                'end': 254,
            },
            'default_expiry_days': 30,
            'gc_grace_days': provisioner.get('gc_grace_days', 7),
        }

        # IP pool (both provisioners provide these, possibly auto-detected)
        ip_network = provisioner.get('ip_network')
        if ip_network:
            ip_start = provisioner.get('ip_start', '200')
            ip_end = provisioner.get('ip_end', '250')
            # Convert full IP strings to last-octet integers
            if isinstance(ip_start, str) and '.' in ip_start:
                ip_start = int(ip_start.split('.')[-1])
            if isinstance(ip_end, str) and '.' in ip_end:
                ip_end = int(ip_end.split('.')[-1])
            db_config['ip_pool'] = {
                'network': ip_network,
                'start': ip_start,
                'end': ip_end,
                'gateway': provisioner.get('gateway', ''),
            }

        # Provisioner-specific keys (only written if present in session data)
        if provisioner.get('vmid_start'):
            db_config['vmid_range'] = {
                'start': provisioner.get('vmid_start', 100),
                'end': provisioner.get('vmid_end', 999),
            }
        if provisioner.get('terraform_dir'):
            db_config['terraform_dir'] = provisioner['terraform_dir']

        # Bridge name — discovered from first-boot or system scan
        bridge_name = _discover_bridge()
        if bridge_name:
            db_config['bridge'] = bridge_name
        write_yaml(config_dir / 'db.yaml', db_config)
        set_blockhost_ownership(config_dir / 'db.yaml', 0o640)

        chain_id = int(blockchain.get('chain_id', 11155111))

        # Write web3-defaults.yaml (nested structure expected by provisioner)
        web3_config = {
            'blockchain': {
                'chain_id': chain_id,
                'rpc_url': blockchain.get('rpc_url'),
                'nft_contract': contracts.get('nft'),
                'subscription_contract': contracts.get('subscription'),
                'usdc_address': USDC_BY_CHAIN.get(chain_id, ''),
            },
            'auth': {
                'otp_length': 6,
                'otp_ttl_seconds': 300,
                'public_secret': config.get('admin_public_secret', 'blockhost-access'),
            },
            'signing_page': {
                'html_path': '/usr/share/libpam-web3-tools/signing-page/index.html',
            },
            'deployer': {
                'private_key_file': '/etc/blockhost/deployer.key',
            },
            'server': {
                'public_key': config.get('server_public_key', ''),
            },
        }
        write_yaml(config_dir / 'web3-defaults.yaml', web3_config)
        set_blockhost_ownership(config_dir / 'web3-defaults.yaml', 0o640)

        # Write blockhost.yaml (includes fields needed by generate-signup-page.py)
        blockhost_config = {
            'server': {
                'address': config.get('server_address'),
                'key_file': '/etc/blockhost/server.key',
            },
            'deployer': {
                'key_file': '/etc/blockhost/deployer.key',
            },
            # Top-level fields for generate-signup-page.py
            'server_public_key': config.get('server_public_key', ''),
            'public_secret': config.get('admin_public_secret', 'blockhost-access'),
        }

        # Add admin section if admin commands are enabled
        if admin_wallet:
            admin_section = {
                'wallet_address': admin_wallet,
            }
            if admin_commands.get('enabled'):
                admin_section.update({
                    'max_command_age': 300,
                    'destination_mode': admin_commands.get('destination_mode', 'self'),
                })
            blockhost_config['admin'] = admin_section

        write_yaml(config_dir / 'blockhost.yaml', blockhost_config)
        set_blockhost_ownership(config_dir / 'blockhost.yaml', 0o640)

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

        # Write admin signature for NFT #0 minting
        admin_signature = config.get('admin_signature', '')
        if admin_signature:
            sig_file = config_dir / 'admin-signature.key'
            sig_file.write_text(admin_signature)
            set_blockhost_ownership(sig_file, 0o640)

        # Write .env file for blockhost-monitor service
        env_file = Path('/opt/blockhost/.env')
        env_file.parent.mkdir(parents=True, exist_ok=True)

        env_lines = [
            f"RPC_URL={blockchain.get('rpc_url', '')}",
            f"BLOCKHOST_CONTRACT={contracts.get('subscription', '')}",
            f"NFT_CONTRACT={contracts.get('nft', '')}",
            f"DEPLOYER_KEY_FILE=/etc/blockhost/deployer.key",
        ]
        env_file.write_text('\n'.join(env_lines) + '\n')
        set_blockhost_ownership(env_file, 0o640)

        return True, None
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
            contracts = config.get('contracts', {})
            nft_contract = contracts.get('nft')

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
                # — Proxmox bypasses ifupdown, so interfaces.d is not reliable)
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
                vms_json = Path('/var/lib/blockhost/vms.json')
                if vms_json.exists():
                    db = json.loads(vms_json.read_text())
                else:
                    db = {"vms": {}, "next_vmid": 100, "allocated_ips": [],
                          "allocated_ipv6": [], "reserved_nft_tokens": {}}
                allocated = db.setdefault("allocated_ipv6", [])
                for addr in reserved:
                    if addr not in allocated:
                        allocated.append(addr)
                vms_json.write_text(json.dumps(db, indent=2))
            except Exception as e:
                print(f"Warning: Could not reserve host IPv6 in VM database: {e}")

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


def _finalize_mint_nft(config: dict) -> tuple[bool, Optional[str]]:
    """Mint NFT #0 (admin access credential) to the admin wallet.

    This encrypts the connection details with the admin's signature-derived
    key and mints an NFT containing the encrypted data.
    """
    try:
        admin_wallet = config.get('admin_wallet')
        admin_signature = config.get('admin_signature')
        admin_public_secret = config.get('admin_public_secret', '')
        https_config = config.get('https', {})
        hostname = https_config.get('hostname', '')

        if not admin_wallet:
            return False, 'Admin wallet not configured'
        if not admin_signature:
            return False, 'Admin signature not available'

        # Step 1: Encrypt connection details using pam_web3_tool
        plaintext = json.dumps({
            'hostname': hostname,
            'port': 443,
            'type': 'admin',
        })

        encrypt_result = subprocess.run(
            [
                'pam_web3_tool', 'encrypt-symmetric',
                '--signature', admin_signature,
                '--plaintext', plaintext,
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if encrypt_result.returncode != 0:
            return False, f'Encryption failed: {encrypt_result.stderr}'

        ciphertext_hex = parse_pam_ciphertext(encrypt_result.stdout)
        if not ciphertext_hex:
            return False, f'Could not parse ciphertext from output: {encrypt_result.stdout}'

        # Step 2: Mint or update NFT
        try:
            sys.path.insert(0, '/usr/lib/python3/dist-packages')
            from blockhost.mint_nft import mint_nft
            from blockhost.config import load_web3_config
        except ImportError as e:
            return False, f'Cannot import minting module: {e}'

        web3_config = load_web3_config()
        nft_contract = web3_config['blockchain']['nft_contract']
        rpc_url = web3_config['blockchain']['rpc_url']

        # Check if admin already owns an NFT
        check_cmd = ['cast', 'call', nft_contract,
                     'balanceOf(address)', admin_wallet,
                     '--rpc-url', rpc_url]
        check_result = subprocess.run(check_cmd, capture_output=True,
                                      text=True, timeout=30)
        if check_result.returncode == 0:
            raw = check_result.stdout.strip()
            balance = _parse_cast_int(raw)
        else:
            balance = 0

        if balance > 0:
            # UPDATE path: admin already has an NFT, update instead of re-minting
            token_cmd = ['cast', 'call', nft_contract,
                         'tokenOfOwnerByIndex(address,uint256)',
                         admin_wallet, '0',
                         '--rpc-url', rpc_url]
            token_result = subprocess.run(token_cmd, capture_output=True,
                                          text=True, timeout=30)
            if token_result.returncode != 0:
                return False, f'Cannot find admin token: {token_result.stderr}'

            raw = token_result.stdout.strip()
            token_id = str(_parse_cast_int(raw))

            deployer_key = Path('/etc/blockhost/deployer.key').read_text().strip()

            # Update userEncrypted on-chain
            update_cmd = ['cast', 'send', nft_contract,
                          'updateUserEncrypted(uint256,bytes)',
                          token_id, ciphertext_hex,
                          '--private-key', deployer_key,
                          '--rpc-url', rpc_url, '--json']
            update_result = subprocess.run(update_cmd, capture_output=True,
                                           text=True, timeout=120)
            if update_result.returncode != 0:
                return False, f'updateUserEncrypted failed: {update_result.stderr}'

            print(f"Updated existing NFT #{token_id} instead of minting")

            config['mint_nft_result'] = {
                'token_id': token_id,
                'tx_hash': 'updated (existing NFT)',
                'message': f'Existing NFT #{token_id} found, updated metadata',
            }
        else:
            # MINT path: fresh install, no existing NFT
            result = mint_nft(
                owner_wallet=admin_wallet,
                machine_id='blockhost-admin',
                user_encrypted=ciphertext_hex,
                public_secret=admin_public_secret,
                config=web3_config,
            )

            config['mint_nft_result'] = {
                'token_id': '0',
                'tx_hash': result or '',
            }

        # Write credential_nft_id to blockhost.yaml so `bw who admin` can resolve it
        token_id = int(config['mint_nft_result']['token_id'])
        blockhost_yaml = Path('/etc/blockhost/blockhost.yaml')
        try:
            import yaml
            bh_config = yaml.safe_load(blockhost_yaml.read_text()) or {}
        except ImportError:
            bh_config = {}
        bh_config.setdefault('admin', {})['credential_nft_id'] = token_id
        write_yaml(blockhost_yaml, bh_config)
        set_blockhost_ownership(blockhost_yaml, 0o640)

        return True, None
    except Exception as e:
        return False, str(e)


def _write_revenue_share_config(config: dict):
    """Write addressbook.json and revenue-share.json based on wizard settings."""
    config_dir = Path('/etc/blockhost')
    config_dir.mkdir(parents=True, exist_ok=True)
    blockchain = config.get('blockchain', {})
    share_dev = blockchain.get('revenue_share_dev', False) and blockchain.get('revenue_share_enabled', False)
    share_broker = blockchain.get('revenue_share_broker', False) and blockchain.get('revenue_share_enabled', False)

    # Build addressbook — always written, used beyond just revenue sharing
    # Each entry is {address, keyfile?}. No "hot" entry — engine auto-generates it.
    addressbook = {}

    admin_wallet = config.get('admin_wallet', '')
    if admin_wallet:
        addressbook['admin'] = {'address': admin_wallet}

    deployer_key = blockchain.get('deployer_key', '')
    if deployer_key:
        deployer_addr = get_address_from_key(deployer_key)
        if deployer_addr:
            addressbook['server'] = {
                'address': deployer_addr,
                'keyfile': '/etc/blockhost/deployer.key',
            }

    # dev and broker only included when their revenue sharing role is enabled
    if share_dev:
        addressbook['dev'] = {'address': '0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9'}

    broker_wallet = None
    if share_broker:
        broker_wallet = _resolve_broker_wallet(config)
        if broker_wallet:
            addressbook['broker'] = {'address': broker_wallet}
        else:
            print("Warning: Could not resolve broker wallet, skipping broker from revenue share")

    (config_dir / 'addressbook.json').write_text(json.dumps(addressbook, indent=2))
    set_blockhost_ownership(config_dir / 'addressbook.json', 0o640)

    # Revenue share config
    if not blockchain.get('revenue_share_enabled'):
        (config_dir / 'revenue-share.json').write_text(json.dumps({
            'enabled': False,
            'total_percent': 0,
            'recipients': [],
        }, indent=2))
        os.chmod(config_dir / 'revenue-share.json', 0o644)
        return

    total_percent = blockchain.get('revenue_share_percent', 1)

    recipients = []
    if share_dev:
        recipients.append('dev')
    if share_broker and broker_wallet:
        recipients.append('broker')

    per_recipient = round(total_percent / len(recipients), 4) if recipients else 0
    (config_dir / 'revenue-share.json').write_text(json.dumps({
        'enabled': True,
        'total_percent': total_percent,
        'recipients': [{'role': r, 'percent': per_recipient} for r in recipients],
    }, indent=2))
    os.chmod(config_dir / 'revenue-share.json', 0o644)


def _resolve_broker_wallet(config: dict) -> Optional[str]:
    """Read the broker's wallet address from broker-allocation.json.

    The broker-client records the msg.sender of the broker's submitResponse
    transaction as broker_wallet when saving the allocation config.
    """
    try:
        alloc_file = Path('/etc/blockhost/broker-allocation.json')
        if not alloc_file.exists():
            return None

        alloc = json.loads(alloc_file.read_text())
        wallet = alloc.get('broker_wallet', '')
        if wallet and wallet.startswith('0x') and len(wallet) == 42:
            return wallet

        return None
    except Exception as e:
        print(f"Warning: Failed to read broker wallet: {e}")
        return None


def _finalize_complete(config: dict) -> tuple[bool, Optional[str]]:
    """Finalize setup: enable services, create default plan, mark complete.

    Note: NFT #0 minting is NOT done here. It requires the wallet connection
    step (after OTP auth) to be implemented first. NFT #0 should be minted
    to the admin's connected wallet, not the deployer wallet.
    """
    try:
        marker_dir = Path('/var/lib/blockhost')
        marker_dir.mkdir(parents=True, exist_ok=True)

        contracts = config.get('contracts', {})

        # Enable blockhost services (will start on reboot)
        subprocess.run(
            ['systemctl', 'enable', 'blockhost-monitor'],
            capture_output=True,
            timeout=30
        )
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

        # Create default plan if we deployed subscription contract
        if contracts.get('subscription'):
            try:
                _create_default_plan(config)
            except Exception as e:
                # Non-fatal - admin can create plan manually
                print(f"Warning: Failed to create default plan: {e}")

        # Write revenue sharing config (addressbook + revenue-share)
        try:
            _write_revenue_share_config(config)
        except Exception as e:
            # Non-fatal
            print(f"Warning: Failed to write revenue share config: {e}")

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


def _create_default_plan(config: dict):
    """Create a default hosting plan on the subscription contract."""
    contracts = config.get('contracts', {})
    blockchain = config.get('blockchain', {})

    subscription_contract = contracts.get('subscription')
    rpc_url = blockchain.get('rpc_url')

    # Read deployer key
    deployer_key_file = Path('/etc/blockhost/deployer.key')
    if not deployer_key_file.exists():
        raise FileNotFoundError("Deployer key not found")

    deployer_key = deployer_key_file.read_text().strip()

    # Use wizard-configured plan name and price, with sensible defaults
    plan_name = blockchain.get('plan_name', 'Basic VM')
    plan_price = str(blockchain.get('plan_price_cents', 50))

    # Check if plans already exist (idempotency)
    skip_plan = False
    check_cmd = ['cast', 'call', subscription_contract,
                 'nextPlanId()', '--rpc-url', rpc_url]
    check_result = subprocess.run(check_cmd, capture_output=True,
                                  text=True, timeout=30)
    if check_result.returncode == 0:
        raw = check_result.stdout.strip()
        next_plan_id = _parse_cast_int(raw)
        if next_plan_id > 1:
            print(f"Plans already exist (nextPlanId={next_plan_id}), skipping plan creation")
            skip_plan = True

    if not skip_plan:
        # createPlan(string name, uint256 pricePerDayUsdCents)
        cmd = [
            'cast', 'send',
            subscription_contract,
            'createPlan(string,uint256)',
            plan_name,
            plan_price,
            '--private-key', deployer_key,
            '--rpc-url', rpc_url,
            '--json',
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            raise RuntimeError(f"Plan creation failed: {result.stderr}")

        print(f"Plan '{plan_name}' created at {plan_price} cents/day")

    # Set primary stablecoin (USDC) based on chain
    chain_id = int(blockchain.get('chain_id', 11155111))
    usdc_address = USDC_BY_CHAIN.get(chain_id)
    if usdc_address:
        # Check current stablecoin before writing (idempotency)
        check_cmd = ['cast', 'call', subscription_contract,
                     'primaryStablecoin()', '--rpc-url', rpc_url]
        check_result = subprocess.run(check_cmd, capture_output=True,
                                      text=True, timeout=30)
        if check_result.returncode == 0:
            raw = check_result.stdout.strip()
            current = '0x' + raw[-40:] if len(raw) >= 40 else raw
            if current.lower() == usdc_address.lower():
                print(f"Primary stablecoin already set to {usdc_address}, skipping")
                return

        cmd = [
            'cast', 'send',
            subscription_contract,
            'setPrimaryStablecoin(address)',
            usdc_address,
            '--private-key', deployer_key,
            '--rpc-url', rpc_url,
            '--json',
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            print(f"Primary stablecoin set to USDC ({usdc_address})")
        else:
            print(f"Warning: Failed to set stablecoin: {result.stderr}")
