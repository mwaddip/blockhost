#!/usr/bin/env python3
"""
BlockHost Web Installer - Flask Application

Provides web-based installation wizard with:
- OTP authentication
- Network configuration
- Storage detection
- Blockchain configuration
- Provisioner integration
- IPv6 allocation
- Package configuration
"""

import importlib
import os
import ssl
import json
import secrets
import subprocess
import threading
import datetime
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import (
    Flask, Response, render_template, request, redirect, url_for,
    session, flash, jsonify, abort
)

# Import common modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from installer.common.otp import OTPManager
from installer.common.network import NetworkManager
from installer.common.detection import detect_boot_medium, BootMedium

# Import extracted modules
from installer.web.utils import (
    detect_disks,
    generate_secp256k1_keypair,
    generate_secp256k1_keypair_with_pubkey,
    get_address_from_key,
    is_valid_address,
    is_valid_ipv6_prefix,
    get_broker_registry,
    get_wallet_balance,
    fetch_broker_registry_from_github,
    parse_pam_ciphertext,
    request_broker_allocation,
    generate_self_signed_cert,
)
from installer.web.finalize import (
    run_finalization_with_state,
    run_finalization,
)


# Chain ID to network name mapping
CHAIN_NAMES = {
    '1': 'Ethereum Mainnet',
    '11155111': 'Sepolia Testnet',
    '137': 'Polygon Mainnet',
    '80001': 'Polygon Mumbai',
}

# Provisioner manifest path (installed by provisioner .deb package)
PROVISIONER_MANIFEST_PATH = Path('/usr/share/blockhost/provisioner.json')


def _discover_provisioner() -> Optional[dict]:
    """Discover the active provisioner from its manifest.

    Returns a dict with 'manifest', 'module', and 'blueprint' keys,
    or None if no provisioner is installed.
    """
    if not PROVISIONER_MANIFEST_PATH.is_file():
        return None

    try:
        manifest = json.loads(PROVISIONER_MANIFEST_PATH.read_text())
        wizard_module_name = manifest.get('setup', {}).get('wizard_module')
        if not wizard_module_name:
            return {'manifest': manifest, 'module': None, 'blueprint': None}

        module = importlib.import_module(wizard_module_name)
        blueprint = getattr(module, 'blueprint', None)
        return {'manifest': manifest, 'module': module, 'blueprint': blueprint}
    except (json.JSONDecodeError, ImportError, Exception) as e:
        print(f"Warning: Failed to load provisioner: {e}")
        return None


# Discover active provisioner (if installed)
_provisioner = _discover_provisioner()

# Resolve provisioner session key from manifest (e.g. the value of config_keys.session_key)
_prov_session_key = None
if _provisioner and _provisioner.get('manifest'):
    _prov_session_key = _provisioner['manifest'].get('config_keys', {}).get('session_key')


def _gather_session_config() -> dict:
    """Build config dict from session, using the provisioner's session key."""
    return {
        'blockchain': session.get('blockchain', {}),
        'provisioner': session.get(_prov_session_key, {}) if _prov_session_key else {},
        'ipv6': session.get('ipv6', {}),
        'admin_wallet': session.get('admin_wallet', ''),
        'admin_signature': session.get('admin_signature', ''),
        'admin_public_secret': session.get('admin_public_secret', ''),
        'admin_commands': session.get('admin_commands', {}),
    }


# Core wizard steps (always present)
_CORE_STEPS = [
    {'id': 'network',        'label': 'Network',    'endpoint': 'wizard_network'},
    {'id': 'storage',        'label': 'Storage',    'endpoint': 'wizard_storage'},
    {'id': 'blockchain',     'label': 'Blockchain', 'endpoint': 'wizard_blockchain'},
]

# Provisioner wizard step (inserted dynamically from manifest)
_PROVISIONER_STEP = None
if _provisioner and _provisioner.get('manifest'):
    _prov_name = _provisioner['manifest'].get('name', 'provisioner')
    _prov_display = _provisioner['manifest'].get('display_name', _prov_name.title())
    _PROVISIONER_STEP = {
        'id': _prov_name,
        'label': _prov_display.split()[0],  # First word as short label
        'endpoint': f'provisioner_{_prov_name}.wizard_{_prov_name}',
    }

# Post-provisioner steps (always present)
_POST_STEPS = [
    {'id': 'ipv6',           'label': 'IPv6',       'endpoint': 'wizard_ipv6'},
    {'id': 'admin_commands', 'label': 'Admin',      'endpoint': 'wizard_admin_commands'},
    {'id': 'summary',        'label': 'Summary',    'endpoint': 'wizard_summary'},
]

# Build WIZARD_STEPS: core + provisioner (if present) + post
WIZARD_STEPS = list(_CORE_STEPS)
if _PROVISIONER_STEP:
    WIZARD_STEPS.append(_PROVISIONER_STEP)
WIZARD_STEPS.extend(_POST_STEPS)

# Pre-compute step navigation maps for wizard prev/next links
_NEXT_STEP = {}
_PREV_STEP = {}
for _i in range(len(WIZARD_STEPS) - 1):
    _NEXT_STEP[WIZARD_STEPS[_i]['id']] = WIZARD_STEPS[_i + 1]['endpoint']
    _PREV_STEP[WIZARD_STEPS[_i + 1]['id']] = WIZARD_STEPS[_i]['endpoint']

def _get_finalization_step_ids() -> list[str]:
    """Get finalization step IDs without requiring function references.

    Used by SetupState at module load time to know what steps exist.
    """
    core_ids = ['keypair', 'wallet', 'contracts', 'config']

    provisioner_ids = []
    if _provisioner and _provisioner.get('module'):
        prov_mod = _provisioner['module']
        if hasattr(prov_mod, 'get_finalization_steps'):
            provisioner_ids = [s[0] for s in prov_mod.get_finalization_steps()]
    elif _provisioner and _provisioner.get('manifest'):
        provisioner_ids = _provisioner['manifest'].get('setup', {}).get('finalization_steps', [])
    post_ids = ['ipv6', 'https', 'signup', 'nginx', 'mint_nft', 'finalize', 'validate']

    return core_ids + provisioner_ids + post_ids


# Global job storage for async operations
_jobs = {}

# Setup state file for persistent tracking
SETUP_STATE_FILE = Path('/var/lib/blockhost/setup-state.json')


class SetupState:
    """Persistent state management for setup process."""

    def __init__(self):
        self.state = self._load()

    def _load(self) -> dict:
        """Load state from disk."""
        if SETUP_STATE_FILE.exists():
            try:
                state = json.loads(SETUP_STATE_FILE.read_text())
                # Migrate: add any missing steps from default state
                default_steps = self._default_state()['steps']
                for step_id, step_default in default_steps.items():
                    if step_id not in state.get('steps', {}):
                        state.setdefault('steps', {})[step_id] = step_default
                return state
            except (json.JSONDecodeError, IOError):
                pass
        return self._default_state()

    def _default_state(self) -> dict:
        """Return default state structure.

        Step IDs are built dynamically from the finalization step list
        so that provisioner-provided steps are included automatically.
        """
        # Build step IDs from the finalization pipeline (core + provisioner + post)
        step_ids = _get_finalization_step_ids()
        steps = {sid: {'status': 'pending', 'error': None, 'completed_at': None}
                 for sid in step_ids}
        return {
            'status': 'pending',  # pending, running, completed, failed
            'started_at': None,
            'completed_at': None,
            'current_step': None,
            'steps': steps,
            'config': {},  # Stored configuration
        }

    def save(self):
        """Save state to disk."""
        try:
            SETUP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            SETUP_STATE_FILE.write_text(json.dumps(self.state, indent=2, default=str))
        except IOError as e:
            print(f"Warning: Could not save setup state: {e}")

    def reset(self):
        """Reset state to defaults."""
        self.state = self._default_state()
        self.save()

    def get_completed_steps(self) -> list:
        """Return list of completed step IDs."""
        return [step_id for step_id, step in self.state['steps'].items()
                if step['status'] == 'completed']

    def get_failed_step(self) -> Optional[str]:
        """Return the ID of the failed step, if any."""
        for step_id, step in self.state['steps'].items():
            if step['status'] == 'failed':
                return step_id
        return None

    def get_next_step(self) -> Optional[str]:
        """Return the next step to run (first non-completed step)."""
        step_order = _get_finalization_step_ids()
        for step_id in step_order:
            step = self.state['steps'].get(step_id)
            if step and step['status'] not in ('completed',):
                return step_id
        return None

    def mark_step_running(self, step_id: str):
        """Mark a step as currently running."""
        self.state['steps'][step_id]['status'] = 'in_progress'
        self.state['steps'][step_id]['error'] = None
        self.state['current_step'] = step_id
        self.save()

    def mark_step_completed(self, step_id: str, data: dict = None):
        """Mark a step as completed, optionally attaching result data."""
        import datetime
        self.state['steps'][step_id]['status'] = 'completed'
        self.state['steps'][step_id]['error'] = None
        self.state['steps'][step_id]['completed_at'] = datetime.datetime.now().isoformat()
        if data:
            self.state['steps'][step_id]['data'] = data
        self.save()

    def mark_step_failed(self, step_id: str, error: str):
        """Mark a step as failed."""
        self.state['steps'][step_id]['status'] = 'failed'
        self.state['steps'][step_id]['error'] = error
        self.state['status'] = 'failed'
        self.save()

    def start(self, config: dict):
        """Start the setup process."""
        import datetime
        self.state['status'] = 'running'
        self.state['started_at'] = datetime.datetime.now().isoformat()
        self.state['config'] = config
        self.save()

    def complete(self):
        """Mark setup as fully complete."""
        import datetime
        self.state['status'] = 'completed'
        self.state['completed_at'] = datetime.datetime.now().isoformat()
        self.state['current_step'] = None
        self.save()

    def to_api_response(self) -> dict:
        """Convert state to API response format."""
        completed = self.get_completed_steps()
        failed_step = self.get_failed_step()
        total_steps = len(self.state['steps'])
        progress = int((len(completed) / total_steps) * 100) if self.state['status'] != 'completed' else 100

        return {
            'status': self.state['status'],
            'progress': progress,
            'current_step': self.state['current_step'],
            'completed_steps': completed,
            'steps': self.state['steps'],
            'failed_step': failed_step,
            'error': self.state['steps'][failed_step]['error'] if failed_step else None,
        }


def create_app(config: Optional[dict] = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config: Optional configuration overrides

    Returns:
        Configured Flask application
    """
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    # Default configuration
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        SESSION_COOKIE_SECURE=False,  # Will be set based on HTTPS
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=4),
    )

    if config:
        app.config.update(config)

    # Initialize managers
    otp_manager = OTPManager()
    net_manager = NetworkManager()

    # Store in app context
    app.otp_manager = otp_manager
    app.net_manager = net_manager
    app.provisioner = _provisioner

    # Register provisioner Blueprint (if available)
    if _provisioner and _provisioner.get('blueprint'):
        app.register_blueprint(_provisioner['blueprint'])

    # Inject wizard steps and provisioner UI params into all templates
    @app.context_processor
    def inject_wizard_context():
        prov_ui = {}
        if _provisioner and _provisioner.get('module'):
            prov_mod = _provisioner['module']
            if hasattr(prov_mod, 'get_ui_params'):
                try:
                    prov_ui = prov_mod.get_ui_params(dict(session))
                except Exception:
                    pass
        return {
            'wizard_steps': WIZARD_STEPS,
            'prov_ui': prov_ui,
        }

    @app.template_global()
    def wizard_nav(current_step_id):
        """Return prev/next endpoint names for wizard navigation."""
        step_ids = [s['id'] for s in WIZARD_STEPS]
        try:
            idx = step_ids.index(current_step_id)
        except ValueError:
            return {'prev': None, 'next': None}
        return {
            'prev': WIZARD_STEPS[idx - 1]['endpoint'] if idx > 0 else None,
            'next': WIZARD_STEPS[idx + 1]['endpoint'] if idx < len(step_ids) - 1 else None,
        }

    # Authentication decorator
    def require_auth(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    # Routes
    @app.route('/')
    def index():
        """Redirect to login or wizard."""
        if session.get('authenticated'):
            # If wallet not yet connected, go to wallet gate first
            if not session.get('admin_wallet'):
                return redirect(url_for('wizard_wallet'))
            return redirect(url_for('wizard_network'))
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """OTP login page."""
        if session.get('authenticated'):
            if not session.get('admin_wallet'):
                return redirect(url_for('wizard_wallet'))
            return redirect(url_for('wizard_network'))

        error = None
        if request.method == 'POST':
            otp_code = request.form.get('otp', '').strip()

            if not otp_code:
                error = "Please enter the access code"
            else:
                success, message = otp_manager.verify(otp_code)
                if success:
                    session['authenticated'] = True
                    session.permanent = True
                    flash('Authentication successful', 'success')
                    return redirect(url_for('wizard_wallet'))
                else:
                    error = message

        # Get OTP status for display hints
        status = otp_manager.get_status()
        return render_template('login.html', error=error, otp_status=status)

    @app.route('/logout')
    def logout():
        """Log out and clear session."""
        session.clear()
        return redirect(url_for('login'))

    # Wizard routes
    @app.route('/wizard/wallet', methods=['GET', 'POST'])
    @require_auth
    def wizard_wallet():
        """Admin wallet connection gate - mandatory before wizard."""
        if request.method == 'POST':
            admin_wallet = request.form.get('admin_wallet', '').strip()
            admin_signature = request.form.get('admin_signature', '').strip()
            public_secret = request.form.get('public_secret', '').strip()

            if not is_valid_address(admin_wallet):
                flash('Invalid wallet address', 'error')
                return redirect(url_for('wizard_wallet'))

            if not admin_signature or not admin_signature.startswith('0x'):
                flash('Missing signature', 'error')
                return redirect(url_for('wizard_wallet'))

            session['admin_wallet'] = admin_wallet
            session['admin_signature'] = admin_signature
            session['admin_public_secret'] = public_secret
            return redirect(url_for('wizard_network'))

        # If wallet already connected, allow re-doing or skip
        return render_template('wizard/wallet.html')

    @app.route('/api/restore-config', methods=['POST'])
    @require_auth
    def api_restore_config():
        """Decrypt an uploaded config file and restore session data."""
        admin_signature = request.form.get('admin_signature', '').strip()
        if not admin_signature or not admin_signature.startswith('0x'):
            return jsonify({'error': 'Missing admin signature'}), 400

        uploaded = request.files.get('config_file')
        if not uploaded:
            return jsonify({'error': 'No file uploaded'}), 400

        ciphertext = uploaded.read().decode('utf-8', errors='ignore').strip()
        if not ciphertext.startswith('0x'):
            return jsonify({'error': 'Invalid config file (expected hex ciphertext)'}), 400

        try:
            result = subprocess.run(
                ['pam_web3_tool', 'decrypt-symmetric',
                 '--signature', admin_signature,
                 '--ciphertext', ciphertext],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return jsonify({'error': 'Decryption failed — wrong wallet or corrupted file'}), 400

            import yaml
            config = yaml.safe_load(result.stdout)
            if not isinstance(config, dict):
                return jsonify({'error': 'Decrypted content is not valid config'}), 400

            # Restore session data from config
            for key in ('blockchain', 'ipv6', 'admin_commands',
                        'admin_wallet', 'admin_public_secret'):
                if key in config:
                    session[key] = config[key]

            # Restore provisioner data: new format uses 'provisioner',
            # old Proxmox backups use 'proxmox' — map to the active session key
            prov_data = config.get('provisioner') or config.get('proxmox', {})
            if prov_data and _prov_session_key:
                session[_prov_session_key] = prov_data

            # Signature comes from the current session (just signed), not the file
            session['admin_signature'] = admin_signature

            return jsonify({'status': 'ok', 'redirect': url_for('wizard_summary')})
        except FileNotFoundError:
            return jsonify({'error': 'pam_web3_tool not installed'}), 500
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Decryption timed out'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/wizard/network', methods=['GET', 'POST'])
    @require_auth
    def wizard_network():
        """Network configuration step."""
        interfaces = net_manager.detect_interfaces()
        current_ip = net_manager.get_current_ip()
        current_gateway = net_manager.get_current_gateway()

        if request.method == 'POST':
            # Handle network configuration
            method = request.form.get('method', 'dhcp')
            interface = request.form.get('interface')

            if method == 'dhcp':
                # Check if we already have a working network
                current_ip = net_manager.get_current_ip()
                if current_ip and net_manager.test_connectivity():
                    flash(f'Network already configured: {current_ip}', 'success')
                    return redirect(url_for('wizard_storage'))

                success, msg = net_manager.run_dhcp(interface)
                if success:
                    flash(f'DHCP configured: {msg}', 'success')
                    return redirect(url_for('wizard_storage'))
                else:
                    flash(f'DHCP failed: {msg}', 'error')
            else:
                # Static configuration
                from installer.common.network import NetworkConfig
                config = NetworkConfig(
                    interface=interface,
                    method='static',
                    address=request.form.get('address'),
                    netmask=request.form.get('netmask'),
                    gateway=request.form.get('gateway'),
                    dns=request.form.get('dns', '').split(','),
                )
                success, msg = net_manager.configure_static(config)
                if success:
                    flash(f'Static IP configured: {msg}', 'success')
                    return redirect(url_for('wizard_storage'))
                else:
                    flash(f'Configuration failed: {msg}', 'error')

        return render_template('wizard/network.html',
                             interfaces=interfaces,
                             current_ip=current_ip,
                             current_gateway=current_gateway)

    @app.route('/wizard/storage', methods=['GET', 'POST'])
    @require_auth
    def wizard_storage():
        """Storage configuration step."""
        disks = detect_disks()

        if request.method == 'POST':
            selected_disk = request.form.get('disk')
            session['selected_disk'] = selected_disk
            return redirect(url_for('wizard_blockchain'))

        return render_template('wizard/storage.html',
                             disks=disks)

    @app.route('/wizard/blockchain', methods=['GET', 'POST'])
    @require_auth
    def wizard_blockchain():
        """Blockchain configuration step."""
        if request.method == 'POST':
            # Get deployer key based on wallet mode
            wallet_mode = request.form.get('wallet_mode')
            if wallet_mode == 'import':
                deployer_key = request.form.get('import_key')
            else:
                deployer_key = request.form.get('deployer_key')

            # Store blockchain configuration in session
            session['blockchain'] = {
                'chain_id': request.form.get('chain_id'),
                'rpc_url': request.form.get('rpc_url'),
                'wallet_mode': wallet_mode,
                'deployer_key': deployer_key,
                'contract_mode': request.form.get('contract_mode'),
                'nft_contract': request.form.get('nft_contract'),
                'subscription_contract': request.form.get('subscription_contract'),
                'plan_name': request.form.get('plan_name', 'Basic VM'),
                'plan_price_cents': int(request.form.get('plan_price_cents', 50)),
                'revenue_share_enabled': request.form.get('revenue_share_enabled') == 'on',
                'revenue_share_percent': float(request.form.get('revenue_share_percent', 1)),
                'revenue_share_dev': request.form.get('revenue_share_dev') == 'on',
                'revenue_share_broker': request.form.get('revenue_share_broker') == 'on',
            }
            return redirect(url_for(_NEXT_STEP.get('blockchain', 'wizard_ipv6')))

        return render_template('wizard/blockchain.html')

    @app.route('/wizard/ipv6', methods=['GET', 'POST'])
    @require_auth
    def wizard_ipv6():
        """IPv6 configuration step."""
        # Get broker registry from blockchain config if available
        blockchain = session.get('blockchain', {})
        broker_registry = get_broker_registry(blockchain.get('chain_id'))

        if request.method == 'POST':
            mode = request.form.get('ipv6_mode')
            session['ipv6'] = {
                'mode': mode,
            }

            if mode == 'broker':
                session['ipv6'].update({
                    'broker_registry': request.form.get('broker_registry'),
                    'prefix': request.form.get('broker_prefix'),
                    'broker_node': request.form.get('broker_node'),
                    'wg_config': request.form.get('broker_wg_config'),
                })
            else:
                session['ipv6'].update({
                    'prefix': request.form.get('manual_prefix'),
                    'allocation_size': request.form.get('allocation_size'),
                })

            return redirect(url_for('wizard_admin_commands'))

        return render_template('wizard/ipv6.html',
                             broker_registry=broker_registry,
                             prev_step_url=url_for(_PREV_STEP.get('ipv6', 'wizard_blockchain')))

    @app.route('/wizard/admin-commands', methods=['GET', 'POST'])
    @require_auth
    def wizard_admin_commands():
        """Admin commands configuration step."""
        if request.method == 'POST':
            admin_enabled = request.form.get('admin_enabled') == 'yes'

            admin_commands = {
                'enabled': admin_enabled,
            }

            if admin_enabled:
                # Parse ports
                ports_str = request.form.get('knock_ports', '22')
                ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]

                admin_commands.update({
                    'destination_mode': request.form.get('destination_mode', 'self'),
                    'knock_command': request.form.get('knock_command', ''),
                    'knock_ports': ports,
                    'knock_timeout': int(request.form.get('knock_timeout', 300)),
                })

            session['admin_commands'] = admin_commands
            return redirect(url_for('wizard_summary'))

        # Generate a random suggested command name
        suggested_command = secrets.token_hex(8)

        return render_template('wizard/admin_commands.html',
                             admin_wallet=session.get('admin_wallet'),
                             suggested_command=suggested_command)

    @app.route('/wizard/summary', methods=['GET', 'POST'])
    @require_auth
    def wizard_summary():
        """Summary and confirmation step."""
        blockchain = session.get('blockchain', {})
        ipv6 = session.get('ipv6', {})
        admin_commands = session.get('admin_commands', {})

        # Get deployer address from key
        deployer_address = None
        deployer_key = blockchain.get('deployer_key')
        if deployer_key:
            deployer_address = get_address_from_key(deployer_key)

        summary = {
            'network': {
                'ip': net_manager.get_current_ip(),
                'gateway': net_manager.get_current_gateway(),
            },
            'disk': session.get('selected_disk', 'Not selected'),
            'blockchain': {
                'chain_id': blockchain.get('chain_id'),
                'network_name': CHAIN_NAMES.get(blockchain.get('chain_id'), 'Custom'),
                'rpc_url': blockchain.get('rpc_url'),
                'deployer_address': deployer_address or 'Not configured',
                'deploy_contracts': blockchain.get('contract_mode') == 'deploy',
                'nft_contract': blockchain.get('nft_contract'),
                'subscription_contract': blockchain.get('subscription_contract'),
                'plan_name': blockchain.get('plan_name', 'Basic VM'),
                'plan_price_cents': blockchain.get('plan_price_cents', 50),
                'revenue_share_enabled': blockchain.get('revenue_share_enabled', False),
                'revenue_share_percent': blockchain.get('revenue_share_percent', 1),
                'revenue_share_dev': blockchain.get('revenue_share_dev', False),
                'revenue_share_broker': blockchain.get('revenue_share_broker', False),
            },
            'ipv6': {
                'mode': ipv6.get('mode'),
                'prefix': ipv6.get('prefix'),
                'broker_node': ipv6.get('broker_node'),
                'broker_registry': ipv6.get('broker_registry'),
            },
            'admin': {
                'wallet': session.get('admin_wallet', 'Not connected'),
                'enabled': admin_commands.get('enabled', False),
                'destination_mode': admin_commands.get('destination_mode', 'N/A'),
                'command_count': 1 if admin_commands.get('enabled') else 0,
            },
        }

        # Get provisioner summary data (if provisioner plugin provides it)
        provisioner_summary = None
        provisioner_summary_template = None
        if _provisioner and _provisioner.get('module'):
            prov_mod = _provisioner['module']
            if hasattr(prov_mod, 'get_summary_data'):
                provisioner_summary = prov_mod.get_summary_data(dict(session))
            if hasattr(prov_mod, 'get_summary_template'):
                provisioner_summary_template = prov_mod.get_summary_template()

        if request.method == 'POST':
            if request.form.get('confirm') == 'yes':
                return redirect(url_for('wizard_install'))
            else:
                flash('Installation cancelled', 'info')
                return redirect(url_for('wizard_network'))

        # Build finalization step metadata for the progress UI
        finalization_step_ids = _get_finalization_step_ids()

        # Build provisioner step metadata for dynamic rendering in progress list
        provisioner_steps_meta = []
        if _provisioner and _provisioner.get('module'):
            prov_mod = _provisioner['module']
            if hasattr(prov_mod, 'get_finalization_steps'):
                for step in prov_mod.get_finalization_steps():
                    meta = {'id': step[0], 'label': step[1]}
                    if len(step) > 3:
                        meta['hint'] = step[3]
                    provisioner_steps_meta.append(meta)

        return render_template('wizard/summary.html',
                             summary=summary,
                             provisioner=provisioner_summary,
                             provisioner_summary=provisioner_summary,
                             provisioner_summary_template=provisioner_summary_template,
                             finalization_step_ids=finalization_step_ids,
                             provisioner_steps=provisioner_steps_meta)

    @app.route('/wizard/install')
    @require_auth
    def wizard_install():
        """Execute installation."""
        return render_template('wizard/install.html')

    # API routes
    @app.route('/api/status')
    @require_auth
    def api_status():
        """Get current system status."""
        medium, details = detect_boot_medium()
        return jsonify({
            'boot_medium': medium.value,
            'network': {
                'ip': net_manager.get_current_ip(),
                'gateway': net_manager.get_current_gateway(),
                'connectivity': net_manager.test_connectivity(),
            },
        })

    @app.route('/api/network/interfaces')
    @require_auth
    def api_network_interfaces():
        """List network interfaces."""
        interfaces = net_manager.detect_interfaces()
        return jsonify([i.to_dict() for i in interfaces])

    @app.route('/api/network/dhcp', methods=['POST'])
    @require_auth
    def api_network_dhcp():
        """Run DHCP on interface."""
        data = request.get_json()
        interface = data.get('interface')
        if not interface:
            return jsonify({'error': 'Interface required'}), 400

        success, message = net_manager.run_dhcp(interface)
        return jsonify({
            'success': success,
            'message': message,
            'ip': net_manager.get_current_ip(interface) if success else None,
        })

    @app.route('/api/storage/disks')
    @require_auth
    def api_storage_disks():
        """List available disks."""
        return jsonify(detect_disks())

    # Blockchain API endpoints
    @app.route('/api/blockchain/generate-wallet', methods=['POST'])
    @require_auth
    def api_blockchain_generate_wallet():
        """Generate a new secp256k1 keypair for deployer wallet."""
        try:
            private_key, address = generate_secp256k1_keypair()
            return jsonify({
                'success': True,
                'private_key': private_key,
                'address': address,
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/blockchain/validate-key', methods=['POST'])
    @require_auth
    def api_blockchain_validate_key():
        """Validate a private key and return its address."""
        data = request.get_json()
        private_key = data.get('private_key', '').strip()

        address = get_address_from_key(private_key)
        if address:
            return jsonify({'valid': True, 'address': address})
        else:
            return jsonify({'valid': False, 'error': 'Invalid private key format'})

    @app.route('/api/blockchain/balance')
    @require_auth
    def api_blockchain_balance():
        """Check wallet balance via RPC."""
        address = request.args.get('address', '').strip()

        if not address or not is_valid_address(address):
            return jsonify({'success': False, 'error': 'Invalid address'}), 400

        # Get RPC URL from query param, then session, then default
        rpc_url = request.args.get('rpc_url', '').strip()
        if not rpc_url:
            blockchain = session.get('blockchain', {})
            rpc_url = blockchain.get('rpc_url', 'https://ethereum-sepolia-rpc.publicnode.com')

        balance = get_wallet_balance(address, rpc_url)
        if balance is not None:
            # Convert wei to ETH
            balance_eth = balance / 1e18
            return jsonify({
                'success': True,
                'balance': str(balance_eth),
                'balance_formatted': f"{balance_eth:.6f}",
                'balance_wei': str(balance),
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to fetch balance'})

    @app.route('/api/blockchain/deploy', methods=['POST'])
    @require_auth
    def api_blockchain_deploy():
        """Start smart contract deployment (async)."""
        blockchain = session.get('blockchain', {})
        job_id = f"deploy-{secrets.token_hex(4)}"

        # Start deployment in background
        thread = threading.Thread(
            target=_run_contract_deployment,
            args=(job_id, blockchain)
        )
        thread.start()

        _jobs[job_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Starting deployment...',
        }

        return jsonify({'job_id': job_id})

    @app.route('/api/blockchain/deploy-status/<job_id>')
    @require_auth
    def api_blockchain_deploy_status(job_id):
        """Check contract deployment status."""
        job = _jobs.get(job_id)
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(job)

    @app.route('/api/blockchain/set-contracts', methods=['POST'])
    @require_auth
    def api_blockchain_set_contracts():
        """Set existing contract addresses."""
        data = request.get_json()
        nft = data.get('nft_contract')
        subscription = data.get('subscription_contract')

        if not nft or not subscription:
            return jsonify({'error': 'Both contract addresses required'}), 400

        # Validate addresses
        if not is_valid_address(nft) or not is_valid_address(subscription):
            return jsonify({'error': 'Invalid contract address format'}), 400

        # Store in session
        blockchain = session.get('blockchain', {})
        blockchain['nft_contract'] = nft
        blockchain['subscription_contract'] = subscription
        session['blockchain'] = blockchain

        return jsonify({'success': True})

    # IPv6 API endpoints
    @app.route('/api/ipv6/broker-request', methods=['POST'])
    @require_auth
    def api_ipv6_broker_request():
        """Request IPv6 allocation from broker network."""
        data = request.get_json()
        registry = data.get('registry')

        if not registry or not is_valid_address(registry):
            return jsonify({'success': False, 'error': 'Invalid registry address'}), 400

        # Call broker-client to request allocation
        result = request_broker_allocation(registry)
        return jsonify(result)

    @app.route('/api/ipv6/manual', methods=['POST'])
    @require_auth
    def api_ipv6_manual():
        """Set manually-owned IPv6 prefix."""
        data = request.get_json()
        prefix = data.get('prefix')

        if not prefix or not is_valid_ipv6_prefix(prefix):
            return jsonify({'success': False, 'error': 'Invalid IPv6 prefix'}), 400

        session['ipv6'] = {
            'mode': 'manual',
            'prefix': prefix,
            'allocation_size': data.get('allocation_size', 64),
        }

        return jsonify({'success': True})

    @app.route('/api/ipv6/status')
    @require_auth
    def api_ipv6_status():
        """Check broker allocation status."""
        ipv6 = session.get('ipv6', {})
        return jsonify({
            'configured': bool(ipv6.get('prefix')),
            'mode': ipv6.get('mode'),
            'prefix': ipv6.get('prefix'),
        })

    @app.route('/api/ipv6/broker-registry')
    @require_auth
    def api_ipv6_broker_registry():
        """Fetch broker registry contract address from GitHub."""
        chain_id = request.args.get('chain_id', '11155111')

        registry = fetch_broker_registry_from_github(chain_id)
        if registry:
            return jsonify({'success': True, 'registry': registry, 'chain_id': chain_id})
        else:
            # Fallback to hardcoded values
            fallback = get_broker_registry(chain_id)
            if fallback:
                return jsonify({'success': True, 'registry': fallback, 'chain_id': chain_id, 'source': 'fallback'})
            return jsonify({'success': False, 'error': 'Registry not found for this chain'})

    # Template API endpoints
    @app.route('/api/template/build', methods=['POST'])
    @require_auth
    def api_template_build():
        """Start VM template build (async)."""
        job_id = f"template-{secrets.token_hex(4)}"

        thread = threading.Thread(
            target=_build_vm_template,
            args=(job_id,)
        )
        thread.start()

        _jobs[job_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Starting template build...',
        }

        return jsonify({'job_id': job_id})

    @app.route('/api/template/build-status/<job_id>')
    @require_auth
    def api_template_build_status(job_id):
        """Check template build progress."""
        job = _jobs.get(job_id)
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(job)

    # CI/CD test setup endpoint (testing mode only)
    @app.route('/api/setup-test', methods=['POST'])
    def api_setup_test():
        """
        One-shot endpoint: authenticate via OTP, populate session, trigger
        finalization. Only available when the ISO was built with --testing.
        Returns 404 on production systems.
        """
        testing_marker = Path('/etc/blockhost/.testing-mode')
        if not testing_marker.exists():
            abort(404)

        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON body required'}), 400

        # Verify OTP
        otp_code = data.get('otp', '').strip()
        if not otp_code:
            return jsonify({'error': 'otp field required'}), 400

        success, message = otp_manager.verify(otp_code)
        if not success:
            return jsonify({'error': f'OTP verification failed: {message}'}), 403

        # Populate session — mirrors the wizard steps
        session['authenticated'] = True
        session.permanent = True
        session['admin_wallet'] = data.get('admin_wallet', '')
        session['admin_signature'] = data.get('admin_signature', '')
        session['admin_public_secret'] = data.get('admin_public_secret', 'blockhost-access')

        # Blockchain config
        session['blockchain'] = data.get('blockchain', {})

        # Provisioner config — CI sends data under the provisioner's session key
        if _prov_session_key:
            prov_data = data.get(_prov_session_key, {})
            prov_data.pop('auto_detect', None)
            session[_prov_session_key] = prov_data

        # IPv6 config
        session['ipv6'] = data.get('ipv6', {})

        # Admin commands config
        session['admin_commands'] = data.get('admin_commands', {'enabled': False})

        # Build config dict identical to what /api/finalize uses
        config = _gather_session_config()

        # Start finalization (same as /api/finalize)
        setup_state = SetupState()

        if setup_state.state['status'] == 'completed':
            return jsonify({
                'status': 'completed',
                'message': 'Setup already complete',
                'poll_url': '/api/finalize/status',
            })

        setup_state.start(config)

        thread = threading.Thread(
            target=run_finalization_with_state,
            args=(setup_state, config, _provisioner)
        )
        thread.start()

        return jsonify({
            'status': 'running',
            'message': 'Test setup started — finalization running',
            'poll_url': '/api/finalize/status',
        })

    # Finalization API endpoints
    @app.route('/api/finalize', methods=['POST'])
    @require_auth
    def api_finalize():
        """Start or resume finalization process (async)."""
        data = request.get_json() or {}
        resume = data.get('resume', False)
        retry_step = data.get('retry_step')  # Specific step to retry

        setup_state = SetupState()

        # If resuming and already completed, just return success
        if setup_state.state['status'] == 'completed':
            return jsonify({
                'status': 'completed',
                'message': 'Setup already complete',
            })

        # Gather configuration from session (or use stored config if resuming)
        if resume and setup_state.state.get('config'):
            config = setup_state.state['config']
        else:
            config = _gather_session_config()

        # If retrying a specific step, reset it to pending
        if retry_step and retry_step in setup_state.state['steps']:
            setup_state.state['steps'][retry_step]['status'] = 'pending'
            setup_state.state['steps'][retry_step]['error'] = None
            setup_state.state['status'] = 'running'
            setup_state.save()

        # Start the finalization process
        setup_state.start(config)

        # Run in background thread
        thread = threading.Thread(
            target=run_finalization_with_state,
            args=(setup_state, config, _provisioner)
        )
        thread.start()

        return jsonify({
            'status': 'running',
            'message': 'Finalization started',
        })

    @app.route('/api/finalize/status')
    @require_auth
    def api_finalize_status():
        """Get finalization status from persistent state."""
        setup_state = SetupState()
        return jsonify(setup_state.to_api_response())

    @app.route('/api/finalize/config')
    @require_auth
    def api_finalize_config():
        """Download applied configuration, encrypted with admin's wallet key."""
        setup_state = SetupState()
        config = setup_state.state.get('config', {})
        if not config:
            return jsonify({'error': 'No configuration available'}), 404

        import yaml
        plaintext = yaml.dump(config, default_flow_style=False, sort_keys=False)

        admin_signature = config.get('admin_signature', '')
        if not admin_signature:
            return jsonify({'error': 'No admin signature available for encryption'}), 500

        try:
            result = subprocess.run(
                ['pam_web3_tool', 'encrypt-symmetric',
                 '--signature', admin_signature,
                 '--plaintext', plaintext],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return jsonify({'error': f'Encryption failed: {result.stderr}'}), 500

            ciphertext_hex = parse_pam_ciphertext(result.stdout)
            if not ciphertext_hex:
                return jsonify({'error': 'Could not parse encrypted output'}), 500

            return Response(
                ciphertext_hex,
                mimetype='text/plain',
                headers={'Content-Disposition': 'attachment; filename=blockhost-config.enc'},
            )
        except FileNotFoundError:
            return jsonify({'error': 'pam_web3_tool not installed'}), 500
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Encryption timed out'}), 500

    @app.route('/api/finalize/retry', methods=['POST'])
    @require_auth
    def api_finalize_retry():
        """Retry a failed step or resume from where we left off."""
        data = request.get_json() or {}
        step_id = data.get('step_id')

        setup_state = SetupState()

        if setup_state.state['status'] == 'completed':
            return jsonify({'error': 'Setup already complete'}), 400

        # Reset the failed step (or specific step) to pending
        if step_id:
            if step_id not in setup_state.state['steps']:
                return jsonify({'error': f'Unknown step: {step_id}'}), 400
            setup_state.state['steps'][step_id]['status'] = 'pending'
            setup_state.state['steps'][step_id]['error'] = None
        else:
            # Reset the failed step
            failed = setup_state.get_failed_step()
            if failed:
                setup_state.state['steps'][failed]['status'] = 'pending'
                setup_state.state['steps'][failed]['error'] = None

        setup_state.state['status'] = 'running'
        setup_state.save()

        # Get stored config
        config = setup_state.state.get('config', {})
        if not config:
            config = _gather_session_config()

        # Run in background thread
        thread = threading.Thread(
            target=run_finalization_with_state,
            args=(setup_state, config, _provisioner)
        )
        thread.start()

        return jsonify({
            'status': 'running',
            'message': 'Retry started',
        })

    @app.route('/api/finalize/reset', methods=['POST'])
    @require_auth
    def api_finalize_reset():
        """Reset finalization state to start over."""
        setup_state = SetupState()
        setup_state.reset()
        return jsonify({'status': 'reset', 'message': 'State reset successfully'})

    @app.route('/api/install/start', methods=['POST'])
    @require_auth
    def api_install_start():
        """Start installation process."""
        # Hypervisor already installed, just mark setup complete
        marker_dir = Path('/var/lib/blockhost')
        marker_file = marker_dir / '.setup-complete'
        try:
            marker_dir.mkdir(parents=True, exist_ok=True)
            marker_file.touch()
        except Exception:
            pass
        return jsonify({'status': 'started', 'job_id': 'install-001'})

    @app.route('/api/install/status/<job_id>')
    @require_auth
    def api_install_status(job_id):
        """Get installation status."""
        # Already complete, return immediately
        return jsonify({
            'job_id': job_id,
            'status': 'completed',
            'progress': 100,
            'message': 'Setup complete!',
        })

    @app.route('/api/complete', methods=['POST'])
    @require_auth
    def api_complete():
        """Mark setup as complete."""
        marker_dir = Path('/var/lib/blockhost')
        marker_file = marker_dir / '.setup-complete'

        try:
            marker_dir.mkdir(parents=True, exist_ok=True)
            marker_file.touch()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/reboot', methods=['POST'])
    @require_auth
    def api_reboot():
        """Reboot the system."""
        try:
            subprocess.Popen(['shutdown', '-r', 'now'])
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/validation-output')
    @require_auth
    def api_validation_output():
        """Get the validation output (testing mode only)."""
        output_file = Path('/var/lib/blockhost/validation-output.txt')
        if output_file.exists():
            return jsonify({
                'success': True,
                'output': output_file.read_text()
            })
        else:
            return jsonify({
                'success': True,
                'output': None  # Not in testing mode or validation hasn't run yet
            })

    return app


def _run_contract_deployment(job_id: str, blockchain: dict):
    """Run smart contract deployment in background."""
    try:
        _jobs[job_id]['message'] = 'Compiling contracts...'
        _jobs[job_id]['progress'] = 10

        # Run hardhat deploy
        engine_dir = Path('/opt/blockhost-engine')
        result = subprocess.run(
            ['npx', 'hardhat', 'deploy', '--network', 'sepolia'],
            cwd=engine_dir,
            capture_output=True,
            text=True,
            timeout=300,
            env={
                **os.environ,
                'DEPLOYER_PRIVATE_KEY': blockchain.get('deployer_key', ''),
                'RPC_URL': blockchain.get('rpc_url', ''),
            }
        )

        if result.returncode == 0:
            _jobs[job_id]['progress'] = 100
            _jobs[job_id]['status'] = 'completed'
            _jobs[job_id]['message'] = 'Contracts deployed successfully'
            # Parse output for contract addresses
            # _jobs[job_id]['contracts'] = {...}
        else:
            _jobs[job_id]['status'] = 'failed'
            _jobs[job_id]['error'] = result.stderr or 'Deployment failed'

    except Exception as e:
        _jobs[job_id]['status'] = 'failed'
        _jobs[job_id]['error'] = str(e)


def _build_vm_template(job_id: str):
    """Build VM template in background."""
    try:
        _jobs[job_id]['message'] = 'Downloading base image...'
        _jobs[job_id]['progress'] = 10

        # Run template build script via provisioner manifest
        build_cmd = _provisioner['manifest']['commands']['build-template'] if _provisioner else None
        if not build_cmd:
            _jobs[job_id]['status'] = 'failed'
            _jobs[job_id]['error'] = 'No provisioner installed'
            return

        result = subprocess.run(
            [build_cmd],
            capture_output=True,
            text=True,
            timeout=1800  # 30 minutes
        )

        if result.returncode == 0:
            _jobs[job_id]['progress'] = 100
            _jobs[job_id]['status'] = 'completed'
            _jobs[job_id]['message'] = 'Template built successfully'
        else:
            _jobs[job_id]['status'] = 'failed'
            _jobs[job_id]['error'] = result.stderr or 'Template build failed'

    except Exception as e:
        _jobs[job_id]['status'] = 'failed'
        _jobs[job_id]['error'] = str(e)


def run_server(host: str = '0.0.0.0', port: int = 80, use_https: bool = False):
    """
    Run the web installer server.

    Args:
        host: Bind address
        port: Port number
        use_https: Enable HTTPS with self-signed cert
    """
    app = create_app()

    if use_https:
        cert_dir = Path('/run/blockhost/ssl')
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_path = cert_dir / 'cert.pem'
        key_path = cert_dir / 'key.pem'

        if not cert_path.exists():
            print("Generating self-signed certificate...")
            if not generate_self_signed_cert(str(cert_path), str(key_path)):
                print("Failed to generate certificate, falling back to HTTP")
                use_https = False

        if use_https:
            app.config['SESSION_COOKIE_SECURE'] = True
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_path), str(key_path))
            app.run(host=host, port=443, ssl_context=context)
            return

    # HTTP mode
    app.run(host=host, port=port)


def main():
    """Main entry point."""
    import argparse
    parser = argparse.ArgumentParser(description='BlockHost Web Installer')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    parser.add_argument('--port', type=int, default=80, help='Port number')
    parser.add_argument('--https', action='store_true', help='Enable HTTPS')
    parser.add_argument('--auto-https', action='store_true',
                       help='Auto-enable HTTPS for public IPs')
    args = parser.parse_args()

    use_https = args.https
    port = args.port

    if args.auto_https:
        net = NetworkManager()
        ip = net.get_current_ip()
        if ip and not net.is_private_ip(ip):
            print(f"Public IP detected ({ip}), enabling HTTPS")
            use_https = True
            port = 443

    print(f"Starting BlockHost Web Installer on "
          f"{'https' if use_https else 'http'}://{args.host}:{port}/")
    run_server(args.host, port, use_https)


if __name__ == '__main__':
    main()
