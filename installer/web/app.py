#!/usr/bin/env python3
"""
BlockHost Web Installer - Flask Application

Provides web-based installation wizard with:
- OTP authentication
- Network configuration
- Storage detection
- Blockchain configuration
- Proxmox integration
- IPv6 allocation
- Package configuration
"""

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
    Flask, render_template, request, redirect, url_for,
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
                return json.loads(SETUP_STATE_FILE.read_text())
            except (json.JSONDecodeError, IOError):
                pass
        return self._default_state()

    def _default_state(self) -> dict:
        """Return default state structure."""
        return {
            'status': 'pending',  # pending, running, completed, failed
            'started_at': None,
            'completed_at': None,
            'current_step': None,
            'steps': {
                'keypair': {'status': 'pending', 'error': None, 'completed_at': None},
                'wallet': {'status': 'pending', 'error': None, 'completed_at': None},
                'contracts': {'status': 'pending', 'error': None, 'completed_at': None},
                'config': {'status': 'pending', 'error': None, 'completed_at': None},
                'token': {'status': 'pending', 'error': None, 'completed_at': None},
                'terraform': {'status': 'pending', 'error': None, 'completed_at': None},
                'bridge': {'status': 'pending', 'error': None, 'completed_at': None},
                'ipv6': {'status': 'pending', 'error': None, 'completed_at': None},
                'https': {'status': 'pending', 'error': None, 'completed_at': None},
                'signup': {'status': 'pending', 'error': None, 'completed_at': None},
                'template': {'status': 'pending', 'error': None, 'completed_at': None},
                'finalize': {'status': 'pending', 'error': None, 'completed_at': None},
                'validate': {'status': 'pending', 'error': None, 'completed_at': None},
            },
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
        step_order = ['keypair', 'wallet', 'contracts', 'config', 'token', 'terraform', 'bridge', 'ipv6', 'https', 'signup', 'template', 'finalize', 'validate']
        for step_id in step_order:
            if self.state['steps'][step_id]['status'] not in ('completed',):
                return step_id
        return None

    def mark_step_running(self, step_id: str):
        """Mark a step as currently running."""
        self.state['steps'][step_id]['status'] = 'in_progress'
        self.state['steps'][step_id]['error'] = None
        self.state['current_step'] = step_id
        self.save()

    def mark_step_completed(self, step_id: str):
        """Mark a step as completed."""
        import datetime
        self.state['steps'][step_id]['status'] = 'completed'
        self.state['steps'][step_id]['error'] = None
        self.state['steps'][step_id]['completed_at'] = datetime.datetime.now().isoformat()
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
            return redirect(url_for('wizard_network'))
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """OTP login page."""
        if session.get('authenticated'):
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
                    return redirect(url_for('wizard_network'))
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
                             current_gateway=current_gateway,
                             step=1, total_steps=6)

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
                             disks=disks,
                             step=2, total_steps=6)

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
            }
            return redirect(url_for('wizard_proxmox'))

        return render_template('wizard/blockchain.html',
                             step=3, total_steps=6)

    @app.route('/wizard/proxmox', methods=['GET', 'POST'])
    @require_auth
    def wizard_proxmox():
        """Proxmox configuration step."""
        detected = _detect_proxmox_resources()

        if request.method == 'POST':
            # Store Proxmox configuration in session
            session['proxmox'] = {
                'api_url': request.form.get('pve_api_url'),
                'node': request.form.get('pve_node'),
                'storage': request.form.get('pve_storage'),
                'bridge': request.form.get('pve_bridge'),
                'user': request.form.get('pve_user'),
                'template_vmid': int(request.form.get('template_vmid', 9001)),
                'vmid_start': int(request.form.get('vmid_start', 100)),
                'vmid_end': int(request.form.get('vmid_end', 999)),
                'ip_network': request.form.get('ip_network'),
                'ip_start': request.form.get('ip_start'),
                'ip_end': request.form.get('ip_end'),
                'gateway': request.form.get('gateway'),
                'gc_grace_days': int(request.form.get('gc_grace_days', 7)),
            }
            return redirect(url_for('wizard_ipv6'))

        return render_template('wizard/proxmox.html',
                             detected=detected,
                             step=4, total_steps=6)

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

            return redirect(url_for('wizard_summary'))

        return render_template('wizard/ipv6.html',
                             broker_registry=broker_registry,
                             step=5, total_steps=6)

    @app.route('/wizard/summary', methods=['GET', 'POST'])
    @require_auth
    def wizard_summary():
        """Summary and confirmation step."""
        blockchain = session.get('blockchain', {})
        proxmox = session.get('proxmox', {})
        ipv6 = session.get('ipv6', {})

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
            },
            'proxmox': {
                'node': proxmox.get('node'),
                'storage': proxmox.get('storage'),
                'bridge': proxmox.get('bridge'),
                'vmid_start': proxmox.get('vmid_start'),
                'vmid_end': proxmox.get('vmid_end'),
                'ip_start': proxmox.get('ip_start'),
                'ip_end': proxmox.get('ip_end'),
                'gc_grace_days': proxmox.get('gc_grace_days', 7),
            },
            'ipv6': {
                'mode': ipv6.get('mode'),
                'prefix': ipv6.get('prefix'),
                'broker_node': ipv6.get('broker_node'),
                'broker_registry': ipv6.get('broker_registry'),
            },
        }

        if request.method == 'POST':
            if request.form.get('confirm') == 'yes':
                return redirect(url_for('wizard_install'))
            else:
                flash('Installation cancelled', 'info')
                return redirect(url_for('wizard_network'))

        return render_template('wizard/summary.html',
                             summary=summary,
                             step=6, total_steps=6)

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

    # Proxmox API endpoints
    @app.route('/api/proxmox/detect')
    @require_auth
    def api_proxmox_detect():
        """Auto-detect Proxmox resources."""
        return jsonify(_detect_proxmox_resources())

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
            config = {
                'blockchain': session.get('blockchain', {}),
                'proxmox': session.get('proxmox', {}),
                'ipv6': session.get('ipv6', {}),
            }

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
            config = {
                'blockchain': session.get('blockchain', {}),
                'proxmox': session.get('proxmox', {}),
                'ipv6': session.get('ipv6', {}),
            }

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
        # Proxmox is already installed, just mark setup complete
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
        # Proxmox is already installed, return completed
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


def _detect_proxmox_resources() -> dict:
    """Detect Proxmox VE resources (storage, bridges, node name)."""
    detected = {
        'api_url': 'https://127.0.0.1:8006',
        'node_name': socket.gethostname(),
        'storages': [],
        'bridges': [],
        'token_exists': False,
    }

    # Get storage pools
    # pvesm status output format:
    # Name             Type     Status           Total            Used       Available        %
    # local             dir     active       102297016        8654608        88423628    8.46%
    # Values are in KB (kibibytes)
    try:
        result = subprocess.run(
            ['pvesm', 'status', '-content', 'images'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if lines:
                # Parse header to find column positions
                header = lines[0].lower()
                # Default column indices (Name, Type, Status, Total, Used, Available, %)
                avail_col = 5  # 0-indexed, 'Available' is typically column 5

                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 6:
                        # Available is in KB, convert to bytes then to GB
                        try:
                            avail_kb = int(parts[avail_col])
                            avail_bytes = avail_kb * 1024  # KB to bytes
                            avail_gb = avail_bytes / (1024**3)
                        except (ValueError, IndexError):
                            avail_bytes = 0
                            avail_gb = 0.0

                        detected['storages'].append({
                            'name': parts[0],
                            'type': parts[1],
                            'status': parts[2],
                            'avail': avail_bytes,
                            'avail_human': f"{avail_gb:.1f} GB",
                        })
    except Exception:
        # Fallback
        detected['storages'] = [{'name': 'local-lvm', 'type': 'lvmthin', 'avail_human': 'Unknown'}]

    # Get network bridges
    try:
        result = subprocess.run(
            ['ip', '-j', 'link', 'show', 'type', 'bridge'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            bridges = json.loads(result.stdout)
            detected['bridges'] = [b['ifname'] for b in bridges]
    except Exception:
        detected['bridges'] = ['vmbr0']

    # Check if API token exists
    token_file = Path('/etc/blockhost/pve-token')
    detected['token_exists'] = token_file.exists()

    return detected


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

    url = 'https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json'

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

        # Run template build script
        result = subprocess.run(
            ['/opt/blockhost-provisioner/scripts/build-template.sh'],
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


def _run_finalization_with_state(setup_state: 'SetupState', config: dict):
    """Run the full finalization process with persistent state tracking."""
    steps = [
        ('keypair', 'Generating server keypair', _finalize_keypair),
        ('wallet', 'Configuring deployer wallet', _finalize_wallet),
        ('contracts', 'Handling contracts', _finalize_contracts),
        ('config', 'Writing configuration files', _finalize_config),
        ('token', 'Creating Proxmox API token', _finalize_token),
        ('terraform', 'Configuring Terraform provider', _finalize_terraform),
        ('bridge', 'Configuring network bridge', _finalize_bridge),
        ('ipv6', 'Configuring IPv6', _finalize_ipv6),
        ('https', 'Configuring HTTPS for signup page', _finalize_https),
        ('signup', 'Generating signup page', _finalize_signup),
        ('template', 'Building VM template', _finalize_template),
        ('finalize', 'Finalizing setup', _finalize_complete),
        ('validate', 'Validating system (testing only)', _finalize_validate),
    ]

    try:
        for step_id, step_name, step_func in steps:
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
                    setup_state.mark_step_completed(step_id)
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
        key_file.chmod(0o600)

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
        key_file.chmod(0o600)

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

            contracts_dir = Path('/opt/blockhost/contracts')

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
        proxmox = config.get('proxmox', {})
        ipv6 = config.get('ipv6', {})
        contracts = config.get('contracts', {})

        # Parse IP pool - extract last octet if full IP strings provided
        ip_start = proxmox.get('ip_start', '200')
        ip_end = proxmox.get('ip_end', '250')
        # Convert full IP strings to integers (last octet)
        if isinstance(ip_start, str) and '.' in ip_start:
            ip_start = int(ip_start.split('.')[-1])
        if isinstance(ip_end, str) and '.' in ip_end:
            ip_end = int(ip_end.split('.')[-1])

        # Write db.yaml (vmid_range is canonical, integers for ip_pool)
        db_config = {
            'db_file': '/var/lib/blockhost/vms.json',
            'terraform_dir': '/var/lib/blockhost/terraform',
            'vmid_range': {
                'start': proxmox.get('vmid_start', 100),
                'end': proxmox.get('vmid_end', 999),
            },
            'ip_pool': {
                'network': proxmox.get('ip_network', '192.168.122.0/24'),
                'start': ip_start,
                'end': ip_end,
                'gateway': proxmox.get('gateway', '192.168.122.1'),
            },
            'ipv6_pool': {
                'start': 2,  # Skip ::0 (network) and ::1 (host)
                'end': 254,
            },
            'default_expiry_days': 30,
            'gc_grace_days': proxmox.get('gc_grace_days', 7),
        }
        _write_yaml(config_dir / 'db.yaml', db_config)

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
                'decrypt_message': blockchain.get('decrypt_message', 'blockhost-access'),
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

        # Write blockhost.yaml (includes fields needed by generate-signup-page.py)
        blockhost_config = {
            'server': {
                'address': config.get('server_address'),
                'key_file': '/etc/blockhost/server.key',
            },
            'deployer': {
                'key_file': '/etc/blockhost/deployer.key',
            },
            'proxmox': {
                'node': proxmox.get('node'),
                'storage': proxmox.get('storage'),
                'bridge': proxmox.get('bridge'),
            },
            # Top-level fields for generate-signup-page.py
            'server_public_key': config.get('server_public_key', ''),
            'decrypt_message': blockchain.get('decrypt_message', 'blockhost-access'),
        }
        _write_yaml(config_dir / 'blockhost.yaml', blockhost_config)

        # Write .env file for blockhost-monitor service
        env_file = Path('/opt/blockhost/.env')
        env_file.parent.mkdir(parents=True, exist_ok=True)

        # Map chain_id to RPC env var name
        chain_id = int(blockchain.get('chain_id', 11155111))
        rpc_var = 'SEPOLIA_RPC' if chain_id == 11155111 else f'CHAIN_{chain_id}_RPC'

        env_lines = [
            f"{rpc_var}={blockchain.get('rpc_url', '')}",
            f"BLOCKHOST_CONTRACT={contracts.get('subscription', '')}",
            f"NFT_CONTRACT={contracts.get('nft', '')}",
            f"DEPLOYER_KEY_FILE=/etc/blockhost/deployer.key",
        ]
        env_file.write_text('\n'.join(env_lines) + '\n')

        return True, None
    except Exception as e:
        return False, str(e)


def _finalize_token(config: dict) -> tuple[bool, Optional[str]]:
    """Create Proxmox API token."""
    try:
        proxmox = config.get('proxmox', {})
        user = proxmox.get('user', 'root@pam')

        # Create API token using pveum
        token_name = 'blockhost'
        result = subprocess.run(
            ['pveum', 'user', 'token', 'add', user, token_name, '--privsep', '0'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            # Parse token from output
            # Format: "full-tokenid" "value" "..."
            for line in result.stdout.split('\n'):
                if 'value' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        token_value = parts[-1].strip('"')

                        # Write terraform.tfvars
                        terraform_dir = Path('/var/lib/blockhost/terraform')
                        terraform_dir.mkdir(parents=True, exist_ok=True)

                        tfvars = {
                            'proxmox_api_url': proxmox.get('api_url', 'https://127.0.0.1:8006/api2/json'),
                            'proxmox_api_token_id': f"{user}!{token_name}",
                            'proxmox_api_token_secret': token_value,
                            'proxmox_node': proxmox.get('node'),
                            'proxmox_storage': proxmox.get('storage'),
                            'proxmox_bridge': proxmox.get('bridge'),
                        }
                        _write_tfvars(terraform_dir / 'terraform.tfvars', tfvars)

                        return True, None

        return False, 'Failed to create API token'
    except Exception as e:
        return False, str(e)


def _finalize_terraform(config: dict) -> tuple[bool, Optional[str]]:
    """Configure Terraform with bpg/proxmox provider for VM provisioning."""
    try:
        terraform_dir = Path('/var/lib/blockhost/terraform')
        terraform_dir.mkdir(parents=True, exist_ok=True)

        config_dir = Path('/etc/blockhost')
        config_dir.mkdir(parents=True, exist_ok=True)

        proxmox = config.get('proxmox', {})
        node_name = proxmox.get('node', socket.gethostname())

        # Generate SSH keypair for Terraform to use
        ssh_key_file = config_dir / 'terraform_ssh_key'
        ssh_pub_file = config_dir / 'terraform_ssh_key.pub'

        if not ssh_key_file.exists():
            result = subprocess.run(
                ['ssh-keygen', '-t', 'ed25519', '-f', str(ssh_key_file), '-N', '', '-C', 'terraform@blockhost'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                return False, f'SSH keygen failed: {result.stderr}'

            # Set correct permissions
            ssh_key_file.chmod(0o600)
            ssh_pub_file.chmod(0o644)

        # Add public key to root's authorized_keys
        authorized_keys = Path('/root/.ssh/authorized_keys')
        authorized_keys.parent.mkdir(parents=True, exist_ok=True)

        pub_key = ssh_pub_file.read_text().strip()

        # Check if key already exists
        existing_keys = ''
        if authorized_keys.exists():
            existing_keys = authorized_keys.read_text()

        if pub_key not in existing_keys:
            with open(authorized_keys, 'a') as f:
                f.write(f'\n{pub_key}\n')
            authorized_keys.chmod(0o600)

        # Write provider.tf.json with bpg/proxmox provider
        provider_config = {
            "terraform": {
                "required_providers": {
                    "proxmox": {
                        "source": "bpg/proxmox",
                        "version": ">= 0.50.0"
                    }
                }
            },
            "provider": {
                "proxmox": {
                    "endpoint": "https://127.0.0.1:8006",
                    "api_token": "${var.proxmox_api_token}",
                    "insecure": True,
                    "ssh": {
                        "agent": False,
                        "username": "root",
                        "private_key": "${file(\"/etc/blockhost/terraform_ssh_key\")}",
                        "node": [
                            {
                                "name": node_name,
                                "address": "127.0.0.1"
                            }
                        ]
                    }
                }
            }
        }

        provider_file = terraform_dir / 'provider.tf.json'
        provider_file.write_text(json.dumps(provider_config, indent=2))

        # Write variables.tf.json with wizard values
        variables_config = {
            "variable": {
                "proxmox_api_token": {
                    "type": "string",
                    "description": "Proxmox API token in format user@realm!tokenid=secret",
                    "sensitive": True
                },
                "proxmox_node": {
                    "type": "string",
                    "description": "Proxmox node name",
                    "default": node_name
                },
                "proxmox_storage": {
                    "type": "string",
                    "description": "Storage pool for VM disks",
                    "default": proxmox.get('storage', 'local-lvm')
                },
                "proxmox_bridge": {
                    "type": "string",
                    "description": "Network bridge for VMs",
                    "default": proxmox.get('bridge', 'vmbr0')
                },
                "template_vmid": {
                    "type": "number",
                    "description": "VMID of the base VM template",
                    "default": proxmox.get('template_vmid', 9001)
                },
                "vmid_start": {
                    "type": "number",
                    "description": "Start of VMID range for provisioned VMs",
                    "default": proxmox.get('vmid_start', 100)
                },
                "vmid_end": {
                    "type": "number",
                    "description": "End of VMID range for provisioned VMs",
                    "default": proxmox.get('vmid_end', 999)
                }
            }
        }

        variables_file = terraform_dir / 'variables.tf.json'
        variables_file.write_text(json.dumps(variables_config, indent=2))

        # Run terraform init
        result = subprocess.run(
            ['terraform', 'init'],
            cwd=terraform_dir,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return False, f'Terraform init failed: {result.stderr}'

        return True, None
    except subprocess.TimeoutExpired:
        return False, 'Terraform init timed out'
    except Exception as e:
        return False, str(e)


def _finalize_bridge(config: dict) -> tuple[bool, Optional[str]]:
    """Ensure network bridge exists for VM networking.

    On bare metal Proxmox installs, vmbr0 is created by the installer.
    On nested/VM installs or custom setups, it may not exist.
    This step creates it if missing.
    """
    try:
        proxmox = config.get('proxmox', {})
        bridge_name = proxmox.get('bridge', 'vmbr0')

        # Check if bridge already exists
        bridge_path = Path(f'/sys/class/net/{bridge_name}')
        if bridge_path.exists():
            # Bridge exists, nothing to do
            return True, None

        # Bridge doesn't exist - need to create it
        # Find the primary network interface (the one with a default route)
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0 or not result.stdout.strip():
            return False, 'Could not determine default network interface'

        # Parse: "default via 192.168.122.1 dev ens3 proto dhcp src 192.168.122.195 metric 100"
        parts = result.stdout.strip().split()
        try:
            dev_idx = parts.index('dev')
            primary_iface = parts[dev_idx + 1]
        except (ValueError, IndexError):
            return False, f'Could not parse default route: {result.stdout}'

        # Get current IP configuration from the primary interface
        result = subprocess.run(
            ['ip', '-j', 'addr', 'show', primary_iface],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return False, f'Could not get IP config for {primary_iface}'

        import json as json_mod
        iface_info = json_mod.loads(result.stdout)

        # Find IPv4 address
        ipv4_addr = None
        ipv4_prefix = None
        gateway = None

        for info in iface_info:
            for addr_info in info.get('addr_info', []):
                if addr_info.get('family') == 'inet':
                    ipv4_addr = addr_info.get('local')
                    ipv4_prefix = addr_info.get('prefixlen')
                    break

        if not ipv4_addr or not ipv4_prefix:
            return False, f'Could not find IPv4 address on {primary_iface}'

        # Get gateway from default route
        parts = result.stdout.strip().split() if result.stdout else []
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True,
            text=True,
            timeout=10
        )
        parts = result.stdout.strip().split()
        try:
            via_idx = parts.index('via')
            gateway = parts[via_idx + 1]
        except (ValueError, IndexError):
            return False, 'Could not determine gateway'

        # Read current interfaces file
        interfaces_file = Path('/etc/network/interfaces')
        interfaces_content = interfaces_file.read_text() if interfaces_file.exists() else ''

        # Check if bridge is already configured (even if not up)
        if f'iface {bridge_name}' in interfaces_content:
            # Bridge is configured but not up - try to bring it up
            subprocess.run(['ifup', bridge_name], capture_output=True, timeout=30)
            if Path(f'/sys/class/net/{bridge_name}').exists():
                return True, None
            return False, f'Bridge {bridge_name} configured but failed to come up'

        # Create bridge configuration
        # We'll modify the primary interface to be part of the bridge
        bridge_config = f'''
# Bridge for VM networking (auto-generated by BlockHost wizard)
auto {bridge_name}
iface {bridge_name} inet static
    address {ipv4_addr}/{ipv4_prefix}
    gateway {gateway}
    bridge-ports {primary_iface}
    bridge-stp off
    bridge-fd 0

# Original interface becomes bridge port
auto {primary_iface}
iface {primary_iface} inet manual
'''

        # Backup original interfaces file
        backup_file = Path('/etc/network/interfaces.blockhost-backup')
        if not backup_file.exists():
            backup_file.write_text(interfaces_content)

        # Comment out existing configuration for the primary interface
        new_content = interfaces_content
        lines = interfaces_content.split('\n')
        new_lines = []
        in_primary_block = False

        for line in lines:
            # Check if this starts the primary interface block
            if line.strip().startswith(f'iface {primary_iface}') or line.strip().startswith(f'auto {primary_iface}'):
                in_primary_block = True
                new_lines.append(f'# DISABLED BY BLOCKHOST: {line}')
            elif in_primary_block:
                # Check if this is a new interface block (end of primary block)
                if line.strip().startswith('auto ') or line.strip().startswith('iface '):
                    in_primary_block = False
                    new_lines.append(line)
                else:
                    new_lines.append(f'# DISABLED BY BLOCKHOST: {line}')
            else:
                new_lines.append(line)

        new_content = '\n'.join(new_lines)

        # Add bridge configuration
        new_content += bridge_config

        # Write new interfaces file
        interfaces_file.write_text(new_content)

        # Bring up the bridge
        # First, we need to be careful not to lose network connectivity
        # The safest approach is to do this atomically
        result = subprocess.run(
            ['ip', 'link', 'add', 'name', bridge_name, 'type', 'bridge'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0 and 'exists' not in result.stderr:
            return False, f'Failed to create bridge: {result.stderr}'

        # Add primary interface to bridge
        subprocess.run(
            ['ip', 'link', 'set', primary_iface, 'master', bridge_name],
            capture_output=True,
            timeout=10
        )

        # Move IP to bridge
        subprocess.run(
            ['ip', 'addr', 'del', f'{ipv4_addr}/{ipv4_prefix}', 'dev', primary_iface],
            capture_output=True,
            timeout=10
        )

        subprocess.run(
            ['ip', 'addr', 'add', f'{ipv4_addr}/{ipv4_prefix}', 'dev', bridge_name],
            capture_output=True,
            timeout=10
        )

        # Bring up the bridge
        subprocess.run(['ip', 'link', 'set', bridge_name, 'up'], capture_output=True, timeout=10)

        # Re-add default route via bridge
        subprocess.run(
            ['ip', 'route', 'add', 'default', 'via', gateway, 'dev', bridge_name],
            capture_output=True,
            timeout=10
        )

        # Verify bridge exists now
        if not Path(f'/sys/class/net/{bridge_name}').exists():
            return False, f'Failed to create bridge {bridge_name}'

        return True, None

    except subprocess.TimeoutExpired:
        return False, 'Network configuration timed out'
    except Exception as e:
        return False, str(e)


def _finalize_ipv6(config: dict) -> tuple[bool, Optional[str]]:
    """Configure IPv6 tunnel if using broker."""
    try:
        ipv6 = config.get('ipv6', {})

        if ipv6.get('mode') == 'broker':
            registry = ipv6.get('broker_registry')
            contracts = config.get('contracts', {})
            nft_contract = contracts.get('nft')

            if not nft_contract:
                return False, 'NFT contract address not available for broker request'

            if not registry:
                return False, 'Broker registry address not configured'

            # Make broker allocation request
            # Note: --registry-contract is a global option, must come before subcommand
            cmd = [
                'broker-client',
                '--registry-contract', registry,
                'request',
                '--nft-contract', nft_contract,
                '--wallet-key', '/etc/blockhost/deployer.key',
                '--configure-wg',
                '--timeout', '120',
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # 3 minutes total timeout
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or 'Broker request failed'
                return False, f'Broker allocation failed: {error_msg}'

            # Parse allocation result from stdout (broker-client outputs JSON on success)
            allocation = {'prefix': '', 'broker_node': '', 'registry': registry}
            try:
                # Try to parse JSON output
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('{'):
                        data = json.loads(line)
                        allocation['prefix'] = data.get('prefix', data.get('ipv6_prefix', ''))
                        allocation['broker_node'] = data.get('broker_node', data.get('broker_id', ''))
                        break
            except json.JSONDecodeError:
                # Try to extract prefix from text output
                import re
                prefix_match = re.search(r'prefix[:\s]+([0-9a-fA-F:]+/\d+)', result.stdout)
                if prefix_match:
                    allocation['prefix'] = prefix_match.group(1)

            # Save broker allocation info
            allocation_file = Path('/etc/blockhost/broker-allocation.json')
            allocation_file.write_text(json.dumps(allocation, indent=2))

        elif ipv6.get('mode') == 'manual':
            # Manual mode - just save the provided prefix
            allocation_file = Path('/etc/blockhost/broker-allocation.json')
            allocation_file.write_text(json.dumps({
                'prefix': ipv6.get('prefix', ''),
                'broker_node': '',
                'registry': '',
                'mode': 'manual',
            }, indent=2))

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
                # Extract network from prefix (e.g., "2a11:6c7:f04:276::/120" -> "2a11:6c7:f04:276::")
                network = prefix.split('/')[0]
                # Host uses ::1 in the prefix
                ipv6_address = network.rstrip(':') + '::1'

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

    key_path.chmod(0o600)


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
import ssl
import socketserver

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='/var/www/blockhost', **kwargs)
    def do_GET(self):
        if self.path == '/' or self.path == '':
            self.path = '/signup.html'
        return super().do_GET()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('{cert_file}', '{key_file}')
with socketserver.TCPServer(('', 443), Handler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("Serving signup page on https://0.0.0.0:443")
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


def _finalize_template(config: dict) -> tuple[bool, Optional[str]]:
    """Build VM template with libpam-web3."""
    try:
        proxmox = config.get('proxmox', {})
        template_vmid = proxmox.get('template_vmid', 9001)
        storage = proxmox.get('storage', 'local-lvm')

        # Check if template already exists
        template_check = subprocess.run(
            ['qm', 'status', str(template_vmid)],
            capture_output=True,
            text=True,
            timeout=10
        )

        if template_check.returncode == 0:
            # Template VM already exists, skip building
            return True, None

        # Find libpam-web3 .deb in template-packages directory
        template_pkg_dir = Path('/var/lib/blockhost/template-packages')
        libpam_deb = None

        if template_pkg_dir.exists():
            debs = list(template_pkg_dir.glob('libpam-web3_*.deb'))
            if debs:
                # Use the most recent one if multiple exist
                libpam_deb = str(sorted(debs, key=lambda p: p.stat().st_mtime, reverse=True)[0])

        # Build template - check both installed location and development location
        build_script = Path('/usr/bin/blockhost-build-template')
        if not build_script.exists():
            build_script = Path('/opt/blockhost-provisioner/scripts/build-template.sh')
        if build_script.exists():
            # Set up environment for build script
            env = os.environ.copy()
            env['TEMPLATE_VMID'] = str(template_vmid)
            env['STORAGE'] = storage
            env['PROXMOX_HOST'] = 'localhost'

            if libpam_deb:
                env['LIBPAM_WEB3_DEB'] = libpam_deb

            result = subprocess.run(
                [str(build_script)],
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutes
                env=env
            )

            if result.returncode != 0:
                return False, result.stderr or 'Template build failed'
        else:
            # Template build script not found - skip for now
            return True, None

        return True, None
    except subprocess.TimeoutExpired:
        return False, 'Template build timed out'
    except Exception as e:
        return False, str(e)



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

        # Write setup complete marker
        (marker_dir / '.setup-complete').touch()

        # Disable first-boot service
        subprocess.run(
            ['systemctl', 'disable', 'blockhost-first-boot'],
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

    # Create default plan: 100 cents/day ($1/day)
    # createPlan(string name, uint256 pricePerDayUsdCents)
    cmd = [
        'cast', 'send',
        subscription_contract,
        'createPlan(string,uint256)',
        'Basic VM',         # name
        '100',              # pricePerDayUsdCents ($1/day)
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

    print("Default plan 'Basic VM' created")

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


def _write_tfvars(path: Path, data: dict):
    """Write Terraform tfvars file."""
    lines = []
    for key, value in data.items():
        if isinstance(value, bool):
            lines.append(f'{key} = {str(value).lower()}')
        elif isinstance(value, (int, float)):
            lines.append(f'{key} = {value}')
        else:
            lines.append(f'{key} = "{value}"')

    path.write_text('\n'.join(lines) + '\n')


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
