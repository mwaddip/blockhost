#!/usr/bin/env python3
"""
BlockHost Web Installer - Flask Application

Provides web-based installation wizard with:
- OTP authentication
- Network configuration
- Storage detection
- Package selection
- Installation execution
"""

import os
import ssl
import secrets
import subprocess
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
                             step=1, total_steps=4)

    @app.route('/wizard/storage', methods=['GET', 'POST'])
    @require_auth
    def wizard_storage():
        """Storage configuration step."""
        disks = _detect_disks()

        if request.method == 'POST':
            selected_disk = request.form.get('disk')
            session['selected_disk'] = selected_disk
            return redirect(url_for('wizard_packages'))

        return render_template('wizard/storage.html',
                             disks=disks,
                             step=2, total_steps=4)

    @app.route('/wizard/packages', methods=['GET', 'POST'])
    @require_auth
    def wizard_packages():
        """Package selection step."""
        packages = _get_available_packages()

        if request.method == 'POST':
            selected = request.form.getlist('packages')
            session['selected_packages'] = selected
            return redirect(url_for('wizard_summary'))

        return render_template('wizard/packages.html',
                             packages=packages,
                             step=3, total_steps=4)

    @app.route('/wizard/summary', methods=['GET', 'POST'])
    @require_auth
    def wizard_summary():
        """Summary and confirmation step."""
        summary = {
            'network': {
                'ip': net_manager.get_current_ip(),
                'gateway': net_manager.get_current_gateway(),
            },
            'disk': session.get('selected_disk', 'Not selected'),
            'packages': session.get('selected_packages', []),
        }

        if request.method == 'POST':
            if request.form.get('confirm') == 'yes':
                return redirect(url_for('wizard_install'))
            else:
                flash('Installation cancelled', 'info')
                return redirect(url_for('wizard_network'))

        return render_template('wizard/summary.html',
                             summary=summary,
                             step=4, total_steps=4)

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

    @app.route('/api/install/start', methods=['POST'])
    @require_auth
    def api_install_start():
        """Start installation process."""
        # This will be implemented to kick off the actual installation
        return jsonify({'status': 'started', 'job_id': 'install-001'})

    @app.route('/api/install/status/<job_id>')
    @require_auth
    def api_install_status(job_id):
        """Get installation status."""
        # Placeholder for installation progress tracking
        return jsonify({
            'job_id': job_id,
            'status': 'running',
            'progress': 50,
            'message': 'Installing packages...',
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

    return app


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
            import json
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


def _get_available_packages() -> list[dict]:
    """Get list of available BlockHost packages."""
    # Placeholder - will be populated with actual packages
    return [
        {
            'id': 'monitoring',
            'name': 'Monitoring Stack',
            'description': 'Prometheus, Grafana, and alerting',
            'default': True,
        },
        {
            'id': 'backup',
            'name': 'Backup Tools',
            'description': 'Automated backup and recovery',
            'default': True,
        },
        {
            'id': 'security',
            'name': 'Security Hardening',
            'description': 'Firewall rules and security configuration',
            'default': True,
        },
    ]


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
