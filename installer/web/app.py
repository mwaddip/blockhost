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

import grp
import importlib
import os
import ssl
import json
import secrets
import subprocess
import threading
import time
import socket
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
    post_ids = ['ipv6', 'https', 'signup', 'mint_nft', 'finalize', 'validate']

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

            if not admin_wallet or not admin_wallet.startswith('0x') or len(admin_wallet) != 42:
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
        disks = _detect_disks()

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
        broker_registry = _get_broker_registry(blockchain.get('chain_id'))

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
                    'knock_max_duration': int(request.form.get('knock_max_duration', 600)),
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
            deployer_address = _get_address_from_key(deployer_key)

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
        return jsonify(_detect_disks())

    # Blockchain API endpoints
    @app.route('/api/blockchain/generate-wallet', methods=['POST'])
    @require_auth
    def api_blockchain_generate_wallet():
        """Generate a new secp256k1 keypair for deployer wallet."""
        try:
            private_key, address = _generate_secp256k1_keypair()
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

        address = _get_address_from_key(private_key)
        if address:
            return jsonify({'valid': True, 'address': address})
        else:
            return jsonify({'valid': False, 'error': 'Invalid private key format'})

    @app.route('/api/blockchain/balance')
    @require_auth
    def api_blockchain_balance():
        """Check wallet balance via RPC."""
        address = request.args.get('address', '').strip()

        if not address or not _is_valid_address(address):
            return jsonify({'success': False, 'error': 'Invalid address'}), 400

        # Get RPC URL from query param, then session, then default
        rpc_url = request.args.get('rpc_url', '').strip()
        if not rpc_url:
            blockchain = session.get('blockchain', {})
            rpc_url = blockchain.get('rpc_url', 'https://ethereum-sepolia-rpc.publicnode.com')

        balance = _get_wallet_balance(address, rpc_url)
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
        if not _is_valid_address(nft) or not _is_valid_address(subscription):
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

        if not registry or not _is_valid_address(registry):
            return jsonify({'success': False, 'error': 'Invalid registry address'}), 400

        # Call broker-client to request allocation
        result = _request_broker_allocation(registry)
        return jsonify(result)

    @app.route('/api/ipv6/manual', methods=['POST'])
    @require_auth
    def api_ipv6_manual():
        """Set manually-owned IPv6 prefix."""
        data = request.get_json()
        prefix = data.get('prefix')

        if not prefix or not _is_valid_ipv6_prefix(prefix):
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

        registry = _fetch_broker_registry_from_github(chain_id)
        if registry:
            return jsonify({'success': True, 'registry': registry, 'chain_id': chain_id})
        else:
            # Fallback to hardcoded values
            fallback = _get_broker_registry(chain_id)
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
            target=_run_finalization_with_state,
            args=(setup_state, config)
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
            target=_run_finalization_with_state,
            args=(setup_state, config)
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

            ciphertext_hex = None
            for line in result.stdout.split('\n'):
                if 'Ciphertext' in line and '0x' in line:
                    ciphertext_hex = line[line.index('0x'):].strip()
                    break

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
            target=_run_finalization_with_state,
            args=(setup_state, config)
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


# Helper functions

def _set_blockhost_ownership(path, mode=0o640):
    """Set file to root:blockhost with given mode."""
    os.chmod(str(path), mode)
    gid = grp.getgrnam('blockhost').gr_gid
    os.chown(str(path), 0, gid)


def _detect_disks() -> list[dict]:
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


def _generate_secp256k1_keypair() -> tuple[str, str]:
    """Generate a secp256k1 keypair for Ethereum."""
    try:
        # Try using eth-keys library if available
        from eth_keys import keys
        private_key = keys.PrivateKey(secrets.token_bytes(32))
        return private_key.to_hex(), private_key.public_key.to_checksum_address()
    except ImportError:
        pass

    # Fallback: generate random key and use cast for address derivation
    try:
        # Generate random 32 bytes
        private_bytes = secrets.token_bytes(32)
        private_hex = '0x' + private_bytes.hex()

        # Use Foundry's cast to derive address
        result = subprocess.run(
            ['cast', 'wallet', 'address', '--private-key', private_hex],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            address = result.stdout.strip()
            return private_hex, address

        raise RuntimeError("cast wallet address failed")
    except Exception as e:
        raise RuntimeError(f"Failed to generate keypair: {e}")


def _generate_secp256k1_keypair_with_pubkey() -> tuple[str, str, str]:
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
    try:
        private_bytes = secrets.token_bytes(32)
        private_hex = '0x' + private_bytes.hex()

        # Get address
        result = subprocess.run(
            ['cast', 'wallet', 'address', '--private-key', private_hex],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError("cast wallet address failed")
        address = result.stdout.strip()

        # Get public key using cast sig (derive from private key)
        # cast wallet sign-auth doesn't work, use python ecdsa as backup
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

    except Exception as e:
        raise RuntimeError(f"Failed to generate keypair: {e}")


def _get_address_from_key(private_key: str) -> Optional[str]:
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
    try:
        result = subprocess.run(
            ['cast', 'wallet', 'address', '--private-key', '0x' + key],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Last resort fallback - return None to indicate we can't derive the address
    return None


def _is_valid_address(address: str) -> bool:
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


def _is_valid_ipv6_prefix(prefix: str) -> bool:
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


def _get_broker_registry(chain_id: str) -> Optional[str]:
    """Get broker registry contract address for chain."""
    # Placeholder - in production, these would be the actual deployed addresses
    registries = {
        '11155111': '0x0E5b567E0000000000000000000000000000dead',  # Sepolia
        '1': None,  # Mainnet - not deployed
        '137': None,  # Polygon - not deployed
    }
    return registries.get(chain_id)


def _get_wallet_balance(address: str, rpc_url: str) -> Optional[int]:
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


def _fetch_broker_registry_from_github(chain_id: str) -> Optional[str]:
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


def _request_broker_allocation(registry: str) -> dict:
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


def _get_finalization_steps() -> list[tuple]:
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
    if _provisioner and _provisioner.get('module'):
        prov_mod = _provisioner['module']
        if hasattr(prov_mod, 'get_finalization_steps'):
            provisioner_steps = prov_mod.get_finalization_steps()

    post_steps = [
        ('ipv6', 'Configuring IPv6', _finalize_ipv6),
        ('https', 'Configuring HTTPS for signup page', _finalize_https),
        ('signup', 'Generating signup page', _finalize_signup),
        ('mint_nft', 'Minting admin NFT', _finalize_mint_nft),
        ('finalize', 'Finalizing setup', _finalize_complete),
        ('validate', 'Validating system (testing only)', _finalize_validate),
    ]

    return core_steps + provisioner_steps + post_steps


def _run_finalization_with_state(setup_state: 'SetupState', config: dict):
    """Run the full finalization process with persistent state tracking."""
    steps = _get_finalization_steps()

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
                        addr = _get_address_from_key(deployer_key) if deployer_key else None
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


def _run_finalization(job_id: str, config: dict):
    """Legacy wrapper - run finalization with job-based tracking."""
    # This is kept for backward compatibility but uses the new state system
    setup_state = SetupState()
    setup_state.start(config)
    _run_finalization_with_state(setup_state, config)

    # Update job status from setup state
    if job_id in _jobs:
        state_response = setup_state.to_api_response()
        _jobs[job_id].update(state_response)


def _finalize_keypair(config: dict) -> tuple[bool, Optional[str]]:
    """Generate server keypair for ECIES encryption."""
    try:
        config_dir = Path('/etc/blockhost')
        config_dir.mkdir(parents=True, exist_ok=True)

        key_file = config_dir / 'server.key'

        private_key, address, public_key = _generate_secp256k1_keypair_with_pubkey()

        # Write private key without 0x prefix (pam_web3_tool expects raw hex)
        private_key_raw = private_key[2:] if private_key.startswith('0x') else private_key
        key_file.write_text(private_key_raw)
        _set_blockhost_ownership(key_file, 0o640)

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
        _set_blockhost_ownership(key_file, 0o640)

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

            if not _is_valid_address(nft) or not _is_valid_address(sub):
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
                'start': 2,  # Skip ::0 (network) and ::1 (host)
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
        bridge_file = Path('/run/blockhost/bridge')
        if bridge_file.exists():
            db_config['bridge'] = bridge_file.read_text().strip()
        else:
            # Fallback: find any bridge with an IP
            for p in Path('/sys/class/net').iterdir():
                if (p / 'bridge').is_dir():
                    db_config['bridge'] = p.name
                    break
        _write_yaml(config_dir / 'db.yaml', db_config)
        _set_blockhost_ownership(config_dir / 'db.yaml', 0o640)

        # USDC addresses by chain
        usdc_addresses = {
            11155111: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',  # Sepolia
            1: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',         # Mainnet
            137: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',       # Polygon
            42161: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',     # Arbitrum
        }
        chain_id = int(blockchain.get('chain_id', 11155111))

        # Write web3-defaults.yaml (nested structure expected by provisioner)
        web3_config = {
            'blockchain': {
                'chain_id': chain_id,
                'rpc_url': blockchain.get('rpc_url'),
                'nft_contract': contracts.get('nft'),
                'subscription_contract': contracts.get('subscription'),
                'usdc_address': usdc_addresses.get(chain_id, ''),
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
        _write_yaml(config_dir / 'web3-defaults.yaml', web3_config)
        _set_blockhost_ownership(config_dir / 'web3-defaults.yaml', 0o640)

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

        _write_yaml(config_dir / 'blockhost.yaml', blockhost_config)
        _set_blockhost_ownership(config_dir / 'blockhost.yaml', 0o640)

        # Write admin-commands.json if admin commands are enabled
        if admin_commands.get('enabled') and admin_commands.get('knock_command'):
            commands_db = {
                'commands': {
                    admin_commands['knock_command']: {
                        'action': 'knock',
                        'description': 'Open configured ports temporarily',
                        'params': {
                            'allowed_ports': admin_commands.get('knock_ports', [22]),
                            'max_duration': admin_commands.get('knock_max_duration', 600),
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
            _set_blockhost_ownership(sig_file, 0o640)

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
        _set_blockhost_ownership(env_file, 0o640)

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
                _set_blockhost_ownership(allocation_file, 0o640)
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
            _set_blockhost_ownership(allocation_file, 0o640)
            config['ipv6']['prefix'] = ipv6.get('prefix', '')

        # Step 4: Add gateway address to bridge for VM connectivity
        # VMs use the first host address in the prefix as their IPv6 gateway.
        # This address must exist on the bridge VMs are connected to.
        prefix = config.get('ipv6', {}).get('prefix', '')
        if prefix:
            import ipaddress
            try:
                # Discover bridge name from first-boot or system scan
                bridge_dev = None
                bridge_file = Path('/run/blockhost/bridge')
                if bridge_file.exists():
                    bridge_dev = bridge_file.read_text().strip()
                if not bridge_dev:
                    for p in Path('/sys/class/net').iterdir():
                        if (p / 'bridge').is_dir():
                            bridge_dev = p.name
                            break
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

        return True, None
    except subprocess.TimeoutExpired:
        return False, 'Broker request timed out (180s)'
    except Exception as e:
        return False, str(e)


def _finalize_https(config: dict) -> tuple[bool, Optional[str]]:
    """Configure HTTPS for the signup page using sslip.io and Let's Encrypt."""
    try:
        config_dir = Path('/etc/blockhost')
        ssl_dir = config_dir / 'ssl'
        ssl_dir.mkdir(parents=True, exist_ok=True)

        # Try to get IPv6 address from broker allocation
        ipv6_address = None
        broker_file = config_dir / 'broker-allocation.json'
        if broker_file.exists():
            broker_data = json.loads(broker_file.read_text())
            prefix = broker_data.get('prefix', '')
            if prefix:
                import ipaddress as _ipaddress
                network = _ipaddress.IPv6Network(prefix, strict=False)
                # Host/gateway is first address in prefix (e.g., ::701 for ::700/120)
                ipv6_address = str(network.network_address + 1)

        hostname = None
        use_sslip = False

        if ipv6_address:
            # Convert IPv6 to sslip.io format (replace : with -)
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
            'use_sslip': use_sslip,
            'ipv6_address': ipv6_address,
            'cert_file': str(ssl_dir / 'cert.pem'),
            'key_file': str(ssl_dir / 'key.pem'),
        }

        if use_sslip or (hostname and '.' in hostname and not hostname.endswith('.local')):
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
                # The signup server needs to be stopped or we use standalone mode
                result = subprocess.run(
                    [
                        'certbot', 'certonly',
                        '--standalone',
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

                if result.returncode == 0:
                    https_config['tls_mode'] = 'letsencrypt'
                    # Update paths to Let's Encrypt's actual locations
                    le_path = Path(f'/etc/letsencrypt/live/{hostname}')
                    if le_path.exists():
                        https_config['cert_file'] = str(le_path / 'fullchain.pem')
                        https_config['key_file'] = str(le_path / 'privkey.pem')
                else:
                    # Let's Encrypt failed, fall back to self-signed
                    _generate_self_signed_cert(hostname, ssl_dir)
                    https_config['tls_mode'] = 'self-signed'

            except Exception as e:
                # Certbot failed, use self-signed
                _generate_self_signed_cert(hostname, ssl_dir)
                https_config['tls_mode'] = 'self-signed'
        else:
            # No valid domain, use self-signed
            _generate_self_signed_cert(hostname, ssl_dir)
            https_config['tls_mode'] = 'self-signed'

        # Write HTTPS configuration
        https_config_file = config_dir / 'https.json'
        https_config_file.write_text(json.dumps(https_config, indent=2))

        # Store in running config for other steps
        config['https'] = https_config

        return True, None
    except Exception as e:
        return False, str(e)


def _generate_self_signed_cert(hostname: str, ssl_dir: Path):
    """Generate a self-signed certificate for fallback HTTPS."""
    cert_path = ssl_dir / 'cert.pem'
    key_path = ssl_dir / 'key.pem'

    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', str(key_path),
        '-out', str(cert_path),
        '-days', '365',
        '-nodes',
        '-subj', f'/CN={hostname}',
    ], capture_output=True, timeout=60)

    _set_blockhost_ownership(key_path, 0o640)


def _finalize_signup(config: dict) -> tuple[bool, Optional[str]]:
    """Generate signup page and create systemd service to serve it."""
    try:
        https_config = config.get('https', {})
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

        # Determine port and TLS settings based on HTTPS config
        tls_mode = https_config.get('tls_mode', 'self-signed')
        cert_file = https_config.get('cert_file', '/etc/blockhost/ssl/cert.pem')
        key_file = https_config.get('key_file', '/etc/blockhost/ssl/key.pem')

        # Create systemd service for signup page server
        # Use port 443 with TLS for HTTPS, or 8080 for HTTP fallback
        if tls_mode in ('letsencrypt', 'self-signed'):
            # Write the server script to a separate file (inline Python in systemd doesn't work)
            server_script = f'''#!/usr/bin/env python3
import http.server
import socket
import ssl
import socketserver

class DualStackTCPServer(socketserver.TCPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        # Allow dual-stack (IPv4 + IPv6) on a single socket
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='/var/www/blockhost', **kwargs)
    def do_GET(self):
        if self.path == '/' or self.path == '':
            self.path = '/signup.html'
        return super().do_GET()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('{cert_file}', '{key_file}')
with DualStackTCPServer(('::', 443), Handler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("Serving signup page on https://[::]:443 (IPv4+IPv6)")
    httpd.serve_forever()
'''
            script_file = Path('/usr/local/bin/blockhost-signup-server')
            script_file.write_text(server_script)
            script_file.chmod(0o755)

            service_content = """[Unit]
Description=Blockhost Signup Page Server (HTTPS)
After=network.target

[Service]
Type=simple
User=blockhost
Group=blockhost
ExecStart=/usr/local/bin/blockhost-signup-server
Restart=on-failure
RestartSec=10
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"""
        else:
            # HTTP fallback (no TLS)
            service_content = """[Unit]
Description=Blockhost Signup Page Server (HTTP)
After=network.target

[Service]
Type=simple
User=blockhost
Group=blockhost
ExecStart=/usr/bin/python3 -m http.server 8080 --directory /var/www/blockhost
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

        service_file = Path('/etc/systemd/system/blockhost-signup.service')
        service_file.write_text(service_content)

        # Reload systemd and enable the service
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)
        subprocess.run(['systemctl', 'enable', 'blockhost-signup'], capture_output=True, timeout=30)
        subprocess.run(['systemctl', 'start', 'blockhost-signup'], capture_output=True, timeout=30)

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

        # Parse ciphertext hex from output (line-by-line)
        ciphertext_hex = None
        for line in encrypt_result.stdout.split('\n'):
            if 'Ciphertext' in line and '0x' in line:
                # Extract hex: "Ciphertext (hex): 0x..."
                idx = line.index('0x')
                ciphertext_hex = line[idx:].strip()
                break

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
            balance = int(raw, 16) if raw.startswith('0x') else int(raw)
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
            token_id = str(int(raw, 16) if raw.startswith('0x') else int(raw))

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
        deployer_addr = _get_address_from_key(deployer_key)
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
    _set_blockhost_ownership(config_dir / 'addressbook.json', 0o640)

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
        next_plan_id = int(raw, 16) if raw.startswith('0x') else int(raw)
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
    usdc_addresses = {
        11155111: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',  # Sepolia
        1: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',         # Mainnet
        137: '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',       # Polygon
        42161: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',     # Arbitrum
    }

    usdc_address = usdc_addresses.get(chain_id)
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


def _write_yaml(path: Path, data: dict):
    """Write data to YAML file."""
    try:
        import yaml
        path.write_text(yaml.safe_dump(data, default_flow_style=False))
    except ImportError:
        # Fallback: simple YAML output
        lines = []
        _dict_to_yaml(data, lines, 0)
        path.write_text('\n'.join(lines))


def _dict_to_yaml(data: dict, lines: list, indent: int):
    """Simple dict to YAML converter."""
    prefix = '  ' * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            _dict_to_yaml(value, lines, indent + 1)
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


def generate_self_signed_cert(cert_path: str, key_path: str) -> bool:
    """Generate self-signed SSL certificate."""
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', '365',
            '-nodes',
            '-subj', '/CN=blockhost-installer',
        ], check=True, capture_output=True)
        return True
    except Exception:
        return False


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
