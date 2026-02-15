#!/usr/bin/env python3
"""
BlockHost System Validation Module

Comprehensive validation of all configuration files, services, and system state
after wizard finalization. Only runs on ISOs built with --testing flag.

This module verifies:
- All config files exist and have correct syntax
- All required variables/keys are present
- File permissions are correct
- Services are in the expected state
- Network bridge is configured
- Terraform is initialized
"""

import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable


ENGINE_MANIFEST_PATH = Path('/usr/share/blockhost/engine.json')

# Engine-supplied address format (loaded once at startup)
_address_re = None


def _load_engine_constraints():
    """Load address format pattern from engine manifest."""
    global _address_re
    try:
        manifest = json.loads(ENGINE_MANIFEST_PATH.read_text())
        ap = manifest.get('constraints', {}).get('address_pattern')
        if ap:
            _address_re = re.compile(ap)
    except (OSError, json.JSONDecodeError, re.error):
        pass


_load_engine_constraints()


@dataclass
class ValidationResult:
    """Result of a single validation check."""
    category: str
    name: str
    passed: bool
    message: str
    critical: bool = True  # If False, failure is a warning not an error


@dataclass
class ValidationReport:
    """Complete validation report."""
    results: list[ValidationResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True if all critical checks passed."""
        return all(r.passed for r in self.results if r.critical)

    @property
    def warnings(self) -> list[ValidationResult]:
        """Non-critical failures."""
        return [r for r in self.results if not r.passed and not r.critical]

    @property
    def errors(self) -> list[ValidationResult]:
        """Critical failures."""
        return [r for r in self.results if not r.passed and r.critical]

    def add(self, result: ValidationResult):
        self.results.append(result)

    def detailed_output(self) -> str:
        """Generate detailed output showing V/X for each test."""
        lines = []
        current_category = None

        for r in self.results:
            # Add category header when it changes
            if r.category != current_category:
                if current_category is not None:
                    lines.append("")  # Blank line between categories
                lines.append(f"=== {r.category} ===")
                current_category = r.category

            # Format: [V] or [X] or [!] (warning)
            if r.passed:
                mark = "[V]"
            elif not r.critical:
                mark = "[!]"  # Warning
            else:
                mark = "[X]"

            lines.append(f"  {mark} {r.name}")
            if not r.passed:
                lines.append(f"      {r.message}")

        return "\n".join(lines)

    def summary(self) -> str:
        """Generate human-readable summary with all results."""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.errors)
        warned = len(self.warnings)

        lines = [
            self.detailed_output(),
            "",
            "=" * 40,
            f"TOTAL: {passed} passed, {failed} failed, {warned} warnings",
        ]

        if not self.passed:
            lines.append("")
            lines.append("FAILED CHECKS:")
            for r in self.errors:
                lines.append(f"  [X] {r.name}: {r.message}")
            lines.append("")

        return "\n".join(lines)


def is_testing_mode() -> bool:
    """Check if system was installed from a testing ISO."""
    # Testing mode creates a dedicated marker file
    marker_file = Path('/etc/blockhost/.testing-mode')
    if marker_file.exists():
        return True

    # Fallback: check for apt proxy (older testing ISOs)
    proxy_file = Path('/etc/apt/apt.conf.d/00proxy')
    return proxy_file.exists()


def _check_file_exists(path: Path, category: str, name: str, critical: bool = True) -> ValidationResult:
    """Check if a file exists."""
    if path.exists():
        return ValidationResult(category, name, True, f"File exists: {path}", critical)
    return ValidationResult(category, name, False, f"Missing: {path}", critical)


def _check_file_permissions(path: Path, expected_mode: int, category: str, name: str) -> ValidationResult:
    """Check file permissions (e.g., 0o600 for private keys)."""
    if not path.exists():
        return ValidationResult(category, name, False, f"Cannot check permissions: {path} doesn't exist")

    actual_mode = stat.S_IMODE(path.stat().st_mode)
    if actual_mode == expected_mode:
        return ValidationResult(category, name, True, f"Permissions OK ({oct(expected_mode)}): {path}")
    return ValidationResult(category, name, False, f"Wrong permissions on {path}: expected {oct(expected_mode)}, got {oct(actual_mode)}")


def _check_json_syntax(path: Path, category: str, name: str, required_keys: list[str] = None) -> ValidationResult:
    """Check if a JSON file is valid and optionally has required keys."""
    if not path.exists():
        return ValidationResult(category, name, False, f"Missing: {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        return ValidationResult(category, name, False, f"Invalid JSON in {path}: {e}")

    if required_keys:
        missing = []
        for key in required_keys:
            if '.' in key:
                # Nested key like "blockchain.chain_id"
                parts = key.split('.')
                obj = data
                found = True
                for part in parts:
                    if isinstance(obj, dict) and part in obj:
                        obj = obj[part]
                    else:
                        found = False
                        break
                if not found:
                    missing.append(key)
            elif key not in data:
                missing.append(key)

        if missing:
            return ValidationResult(category, name, False, f"Missing keys in {path}: {', '.join(missing)}")

    return ValidationResult(category, name, True, f"Valid JSON: {path}")


def _check_yaml_syntax(path: Path, category: str, name: str, required_keys: list[str] = None) -> ValidationResult:
    """Check if a YAML file is valid and optionally has required keys."""
    if not path.exists():
        return ValidationResult(category, name, False, f"Missing: {path}")

    try:
        import yaml
        data = yaml.safe_load(path.read_text())
    except ImportError:
        # Fallback: basic syntax check without full parsing
        try:
            content = path.read_text()
            if not content.strip():
                return ValidationResult(category, name, False, f"Empty file: {path}")
            return ValidationResult(category, name, True, f"File exists (yaml module unavailable): {path}")
        except Exception as e:
            return ValidationResult(category, name, False, f"Cannot read {path}: {e}")
    except Exception as e:
        return ValidationResult(category, name, False, f"Invalid YAML in {path}: {e}")

    if data is None:
        return ValidationResult(category, name, False, f"Empty YAML file: {path}")

    if required_keys:
        missing = []
        for key in required_keys:
            if '.' in key:
                # Nested key like "blockchain.chain_id"
                parts = key.split('.')
                obj = data
                found = True
                for part in parts:
                    if isinstance(obj, dict) and part in obj:
                        obj = obj[part]
                    else:
                        found = False
                        break
                if not found:
                    missing.append(key)
            elif key not in data:
                missing.append(key)

        if missing:
            return ValidationResult(category, name, False, f"Missing keys in {path}: {', '.join(missing)}")

    return ValidationResult(category, name, True, f"Valid YAML: {path}")


def _check_hex_key(path: Path, category: str, name: str, expected_length: int = None) -> ValidationResult:
    """Check if a file contains a valid hex key."""
    if not path.exists():
        return ValidationResult(category, name, False, f"Missing: {path}")

    try:
        content = path.read_text().strip()
        # Remove 0x prefix if present
        if content.startswith('0x'):
            content = content[2:]

        # Check if it's valid hex
        int(content, 16)

        if expected_length and len(content) != expected_length:
            return ValidationResult(
                category, name, False,
                f"Invalid key length in {path}: expected {expected_length}, got {len(content)}"
            )

        return ValidationResult(category, name, True, f"Valid hex key: {path}")
    except ValueError:
        return ValidationResult(category, name, False, f"Invalid hex in {path}")


def _check_address(address: str, category: str, name: str) -> ValidationResult:
    """Check if a string is a valid address (format from engine manifest)."""
    if not address:
        return ValidationResult(category, name, False, "Address is empty")

    if _address_re:
        if _address_re.match(address):
            return ValidationResult(category, name, True, f"Valid address: {address}")
        return ValidationResult(category, name, False, f"Invalid address format: {address}")

    # No engine constraints — accept non-empty
    return ValidationResult(category, name, True, f"Address present (no format check): {address}")


def _check_service_state(service: str, expected_enabled: bool, expected_active: bool = None,
                         category: str = "Services", critical: bool = True) -> ValidationResult:
    """Check systemd service state."""
    name = f"{service} state"

    # Check enabled state
    result = subprocess.run(
        ['systemctl', 'is-enabled', service],
        capture_output=True,
        text=True
    )
    is_enabled = result.stdout.strip() == 'enabled'

    if expected_enabled and not is_enabled:
        return ValidationResult(category, name, False, f"{service} should be enabled but is not", critical)
    if not expected_enabled and is_enabled:
        return ValidationResult(category, name, False, f"{service} should be disabled but is enabled", critical)

    # Check active state if requested
    if expected_active is not None:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True,
            text=True
        )
        is_active = result.stdout.strip() == 'active'

        if expected_active and not is_active:
            return ValidationResult(category, name, False, f"{service} should be running but is not", critical)
        if not expected_active and is_active:
            return ValidationResult(category, name, False, f"{service} should not be running but is", critical)

    state_desc = "enabled" if expected_enabled else "disabled"
    if expected_active is not None:
        state_desc += f", {'running' if expected_active else 'stopped'}"

    return ValidationResult(category, name, True, f"{service}: {state_desc}")


def _check_bridge_exists(bridge_name: str) -> ValidationResult:
    """Check if network bridge exists."""
    bridge_path = Path(f'/sys/class/net/{bridge_name}')
    if bridge_path.exists():
        return ValidationResult("Network", f"Bridge {bridge_name}", True, f"Bridge exists")
    return ValidationResult("Network", f"Bridge {bridge_name}", False, f"Bridge {bridge_name} not found")


def _check_bridge_has_ip(bridge_name: str) -> ValidationResult:
    """Check if bridge has an IP address configured."""
    try:
        result = subprocess.run(
            ['ip', 'addr', 'show', bridge_name],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return ValidationResult("Network", f"{bridge_name} IP", False, f"Cannot get IP for {bridge_name}")

        # Look for inet or inet6 line
        if 'inet ' in result.stdout or 'inet6 ' in result.stdout:
            return ValidationResult("Network", f"{bridge_name} IP", True, f"{bridge_name} has IP address configured")

        return ValidationResult("Network", f"{bridge_name} IP", False, f"{bridge_name} has no IP address", critical=False)
    except Exception as e:
        return ValidationResult("Network", f"{bridge_name} IP", False, f"Error checking {bridge_name}: {e}")


def _check_terraform_initialized() -> ValidationResult:
    """Check if Terraform is initialized."""
    tf_dir = Path('/var/lib/blockhost/terraform/.terraform')
    if tf_dir.exists() and tf_dir.is_dir():
        # Check for provider plugins
        providers_dir = tf_dir / 'providers'
        if providers_dir.exists():
            return ValidationResult("Terraform", "Initialized", True, "Terraform initialized with providers")
        return ValidationResult("Terraform", "Initialized", False, ".terraform exists but no providers found")
    return ValidationResult("Terraform", "Initialized", False, "Terraform not initialized (.terraform missing)")


def _check_ssh_key_in_authorized(key_path: Path) -> ValidationResult:
    """Check if a public key is in root's authorized_keys."""
    auth_keys_path = Path('/root/.ssh/authorized_keys')

    if not key_path.exists():
        return ValidationResult("SSH", "Terraform key in authorized_keys", False, f"Key file missing: {key_path}")

    if not auth_keys_path.exists():
        return ValidationResult("SSH", "Terraform key in authorized_keys", False, "authorized_keys doesn't exist")

    try:
        public_key = key_path.read_text().strip()
        authorized_keys = auth_keys_path.read_text()

        # Extract just the key part (algorithm + key, not comment)
        key_parts = public_key.split()
        if len(key_parts) >= 2:
            key_to_find = f"{key_parts[0]} {key_parts[1]}"
            if key_to_find in authorized_keys:
                return ValidationResult("SSH", "Terraform key in authorized_keys", True, "Terraform SSH key present")

        return ValidationResult("SSH", "Terraform key in authorized_keys", False, "Terraform SSH key not in authorized_keys")
    except Exception as e:
        return ValidationResult("SSH", "Terraform key in authorized_keys", False, f"Error checking: {e}")


def _check_env_file(path: Path, required_vars: list[str]) -> ValidationResult:
    """Check .env file for required variables."""
    if not path.exists():
        return ValidationResult("Environment", ".env file", False, f"Missing: {path}")

    try:
        content = path.read_text()
        missing = []

        for var in required_vars:
            # Check for VAR= or VAR =
            pattern = rf'^{re.escape(var)}\s*='
            if not re.search(pattern, content, re.MULTILINE):
                missing.append(var)

        if missing:
            return ValidationResult("Environment", ".env file", False, f"Missing variables: {', '.join(missing)}")

        return ValidationResult("Environment", ".env file", True, f"All required env vars present")
    except Exception as e:
        return ValidationResult("Environment", ".env file", False, f"Error reading: {e}")


def _check_signup_page_content() -> ValidationResult:
    """Check if signup.html has actual content."""
    signup_path = Path('/var/www/blockhost/signup.html')

    if not signup_path.exists():
        return ValidationResult("Web", "Signup page content", False, "signup.html missing")

    try:
        content = signup_path.read_text()
        size = len(content)

        # Should be substantial (the page is several KB at minimum)
        if size < 1000:
            return ValidationResult("Web", "Signup page content", False, f"signup.html suspiciously small ({size} bytes)")

        # Check for key elements
        if '<html' not in content.lower():
            return ValidationResult("Web", "Signup page content", False, "signup.html missing <html> tag")

        if 'ethers' not in content.lower() and 'ethereum' not in content.lower():
            return ValidationResult("Web", "Signup page content", False, "signup.html missing Web3 integration", critical=False)

        return ValidationResult("Web", "Signup page content", True, f"signup.html valid ({size} bytes)")
    except Exception as e:
        return ValidationResult("Web", "Signup page content", False, f"Error reading: {e}")


def run_full_validation() -> ValidationReport:
    """Run complete system validation."""
    report = ValidationReport()

    # Determine provisioner type early — many checks are conditional on this
    provisioner_name = None
    provisioner_manifest = Path('/usr/share/blockhost/provisioner.json')
    if provisioner_manifest.exists():
        try:
            provisioner_name = json.loads(provisioner_manifest.read_text()).get('name')
        except (json.JSONDecodeError, IOError):
            pass

    # ========== FILE EXISTENCE AND PERMISSIONS ==========

    # /etc/blockhost/ directory
    etc_blockhost = Path('/etc/blockhost')

    # Private keys (must be 0640, root:blockhost group-readable)
    private_keys = [
        (etc_blockhost / 'server.key', 'Server private key'),
        (etc_blockhost / 'deployer.key', 'Deployer private key'),
    ]

    # Proxmox-specific private keys
    if provisioner_name in (None, 'proxmox'):
        private_keys.extend([
            (etc_blockhost / 'terraform_ssh_key', 'Terraform SSH key'),
            (etc_blockhost / 'pve-token', 'Proxmox API token'),
        ])

    for path, name in private_keys:
        report.add(_check_file_exists(path, "Files", name))
        if path.exists():
            report.add(_check_file_permissions(path, 0o640, "Permissions", name))

    # Public keys (should be readable)
    public_keys = [
        (etc_blockhost / 'server.pubkey', 'Server public key'),
    ]

    if provisioner_name in (None, 'proxmox'):
        public_keys.append(
            (etc_blockhost / 'terraform_ssh_key.pub', 'Terraform SSH public key'),
        )

    for path, name in public_keys:
        report.add(_check_file_exists(path, "Files", name))

    # ========== YAML CONFIG FILES ==========

    # db.yaml — ip_pool written by provisioner finalization
    # 'bridge' is provisioner-specific (Proxmox has vmbr0, libvirt uses NAT network)
    db_yaml_keys = ['ip_pool.network']
    report.add(_check_yaml_syntax(
        etc_blockhost / 'db.yaml',
        "Config", "db.yaml",
        required_keys=db_yaml_keys
    ))

    # web3-defaults.yaml
    report.add(_check_yaml_syntax(
        etc_blockhost / 'web3-defaults.yaml',
        "Config", "web3-defaults.yaml",
        required_keys=['blockchain.chain_id', 'blockchain.rpc_url', 'blockchain.nft_contract',
                       'blockchain.subscription_contract', 'blockchain.server_public_key']
    ))

    # blockhost.yaml
    blockhost_yaml_keys = ['server.key_file',
                           'admin.wallet_address', 'public_secret', 'server_public_key']
    report.add(_check_yaml_syntax(
        etc_blockhost / 'blockhost.yaml',
        "Config", "blockhost.yaml",
        required_keys=blockhost_yaml_keys
    ))

    # ========== JSON CONFIG FILES ==========

    # broker-allocation.json (may not exist if not using broker)
    broker_alloc = etc_blockhost / 'broker-allocation.json'
    if broker_alloc.exists():
        report.add(_check_json_syntax(broker_alloc, "Config", "broker-allocation.json"))
    else:
        report.add(ValidationResult("Config", "broker-allocation.json", True, "Not present (OK if not using broker)", critical=False))

    # https.json
    report.add(_check_json_syntax(
        etc_blockhost / 'https.json',
        "Config", "https.json",
        required_keys=['hostname', 'cert_file', 'key_file']
    ))

    # addressbook.json (always written — admin and server at minimum)
    addressbook_file = etc_blockhost / 'addressbook.json'
    report.add(_check_json_syntax(addressbook_file, "Config", "addressbook.json",
                                  required_keys=['admin', 'server']))
    if addressbook_file.exists():
        report.add(_check_file_permissions(addressbook_file, 0o640, "Permissions", "addressbook.json"))
        try:
            ab_data = json.loads(addressbook_file.read_text())
            # Validate that admin and server have address fields
            for role in ('admin', 'server'):
                entry = ab_data.get(role, {})
                addr = entry.get('address', '') if isinstance(entry, dict) else ''
                report.add(_check_address(addr, "Config", f"addressbook.json {role} address"))
            # server should have keyfile
            server_entry = ab_data.get('server', {})
            if isinstance(server_entry, dict) and server_entry.get('keyfile'):
                report.add(ValidationResult("Config", "addressbook.json server keyfile", True,
                                            f"keyfile: {server_entry['keyfile']}"))
            else:
                report.add(ValidationResult("Config", "addressbook.json server keyfile", False,
                                            "server entry missing keyfile"))
            # Validate dev/broker addresses if present
            for role in ('dev', 'broker'):
                entry = ab_data.get(role)
                if entry and isinstance(entry, dict):
                    report.add(_check_address(entry.get('address', ''), "Config",
                                                  f"addressbook.json {role} address"))
        except (json.JSONDecodeError, IOError):
            pass  # Already caught by _check_json_syntax above

    # revenue-share.json (always written)
    revshare_file = etc_blockhost / 'revenue-share.json'
    report.add(_check_json_syntax(revshare_file, "Config", "revenue-share.json",
                                  required_keys=['enabled', 'total_percent', 'recipients']))
    if revshare_file.exists():
        report.add(_check_file_permissions(revshare_file, 0o640, "Permissions", "revenue-share.json"))
        try:
            rs_data = json.loads(revshare_file.read_text())
            if rs_data.get('enabled'):
                # When enabled, recipients must reference roles that exist in addressbook
                if addressbook_file.exists():
                    ab_roles = set(json.loads(addressbook_file.read_text()).keys())
                    for recipient in rs_data.get('recipients', []):
                        role = recipient.get('role', '')
                        if role in ab_roles:
                            report.add(ValidationResult("Config", f"revenue-share recipient '{role}'", True,
                                                        f"Role exists in addressbook"))
                        else:
                            report.add(ValidationResult("Config", f"revenue-share recipient '{role}'", False,
                                                        f"Role '{role}' not found in addressbook.json"))
        except (json.JSONDecodeError, IOError):
            pass

    # setup-state.json
    state_file = Path('/var/lib/blockhost/setup-state.json')
    report.add(_check_json_syntax(state_file, "Config", "setup-state.json", required_keys=['status']))

    # Check setup-state.json status
    # Note: validation runs DURING finalization, so status will be 'running' not 'completed'
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
            status = state.get('status')
            if status in ('running', 'completed'):
                report.add(ValidationResult("Config", "Setup state status", True, f"Setup status: {status}"))
            else:
                report.add(ValidationResult("Config", "Setup state status", False, f"Unexpected status: {status}"))
        except:
            pass

    # ========== PROVISIONER MANIFEST ==========

    manifest_result = _check_json_syntax(provisioner_manifest, "Provisioner", "provisioner.json")
    manifest_result.critical = False  # Not critical during transition
    report.add(manifest_result)

    if provisioner_name:
        report.add(ValidationResult("Provisioner", "Manifest loaded", True,
                                    f"Provisioner: {provisioner_name}"))

    # ========== TERRAFORM FILES (Proxmox provisioner only) ==========

    # Only check Terraform files if using Proxmox provisioner or no manifest yet (transition)
    if provisioner_name in (None, 'proxmox'):
        tf_dir = Path('/var/lib/blockhost/terraform')

        report.add(_check_json_syntax(tf_dir / 'provider.tf.json', "Terraform", "provider.tf.json"))
        report.add(_check_json_syntax(tf_dir / 'variables.tf.json', "Terraform", "variables.tf.json"))
        report.add(_check_file_exists(tf_dir / 'terraform.tfvars', "Terraform", "terraform.tfvars"))
        report.add(_check_terraform_initialized())

    # ========== MARKER FILES ==========

    report.add(_check_file_exists(
        Path('/var/lib/blockhost/.setup-complete'),
        "Markers", "Setup complete marker"
    ))

    # ========== KEY CONTENT VALIDATION ==========

    # Check keys are valid hex (64 chars = 32 bytes)
    if (etc_blockhost / 'server.key').exists():
        report.add(_check_hex_key(etc_blockhost / 'server.key', "Keys", "Server key format", expected_length=64))

    if (etc_blockhost / 'deployer.key').exists():
        report.add(_check_hex_key(etc_blockhost / 'deployer.key', "Keys", "Deployer key format", expected_length=64))

    # ========== ADMIN CONFIG ==========

    # admin-signature.key (always present if admin wallet was connected)
    admin_sig = etc_blockhost / 'admin-signature.key'
    report.add(_check_file_exists(admin_sig, "Admin", "Admin signature key"))
    if admin_sig.exists():
        report.add(_check_file_permissions(admin_sig, 0o640, "Permissions", "Admin signature key"))

    # Validate admin wallet address from blockhost.yaml
    blockhost_yaml_admin = etc_blockhost / 'blockhost.yaml'
    admin_enabled = False
    if blockhost_yaml_admin.exists():
        try:
            import yaml
            bh_data = yaml.safe_load(blockhost_yaml_admin.read_text())
            admin_section = bh_data.get('admin', {})
            admin_wallet = admin_section.get('wallet_address', '')
            report.add(_check_address(admin_wallet, "Admin", "Admin wallet address"))

            # Check if admin commands are enabled (has destination_mode means enabled)
            if admin_section.get('destination_mode'):
                admin_enabled = True
        except ImportError:
            report.add(ValidationResult("Admin", "Admin wallet validation", True,
                                        "Skipped (yaml module unavailable)", critical=False))
        except Exception as e:
            report.add(ValidationResult("Admin", "Admin wallet validation", False, f"Error: {e}"))

    # admin-commands.json (only present when admin commands enabled)
    admin_cmds_file = etc_blockhost / 'admin-commands.json'
    if admin_enabled:
        report.add(_check_json_syntax(admin_cmds_file, "Admin", "admin-commands.json",
                                      required_keys=['commands']))
    else:
        if admin_cmds_file.exists():
            report.add(ValidationResult("Admin", "admin-commands.json", False,
                                        "File exists but admin commands not enabled in blockhost.yaml"))
        else:
            report.add(ValidationResult("Admin", "admin-commands.json", True,
                                        "Not present (OK - admin commands not enabled)", critical=False))

    # ========== CONTRACT ADDRESSES ==========

    # Read and validate contract addresses from web3-defaults.yaml
    web3_defaults = etc_blockhost / 'web3-defaults.yaml'
    if web3_defaults.exists():
        try:
            import yaml
            data = yaml.safe_load(web3_defaults.read_text())
            blockchain = data.get('blockchain', {})

            nft_contract = blockchain.get('nft_contract', '')
            report.add(_check_address(nft_contract, "Contracts", "NFT contract address"))

            # Subscription contract is optional
            sub_contract = blockchain.get('subscription_contract', '')
            if sub_contract:
                report.add(_check_address(sub_contract, "Contracts", "Subscription contract address"))
        except ImportError:
            report.add(ValidationResult("Contracts", "Address validation", True, "Skipped (yaml module unavailable)", critical=False))
        except Exception as e:
            report.add(ValidationResult("Contracts", "Address validation", False, f"Error: {e}"))

    # ========== NFT #0 (ADMIN CREDENTIAL) ==========

    # Check if NFT contract exists at the configured address
    if web3_defaults.exists():
        try:
            import yaml
            data = yaml.safe_load(web3_defaults.read_text())
            blockchain = data.get('blockchain', {})
            nft_addr = blockchain.get('nft_contract', '')

            if nft_addr:
                try:
                    result = subprocess.run(
                        ['is', 'contract', nft_addr],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        report.add(ValidationResult(
                            "NFT", "NFT contract exists", True,
                            f"Contract verified at {nft_addr}", critical=False
                        ))
                    else:
                        report.add(ValidationResult(
                            "NFT", "NFT contract exists", False,
                            f"No contract at {nft_addr}", critical=False
                        ))
                except FileNotFoundError:
                    report.add(ValidationResult(
                        "NFT", "NFT contract exists", False,
                        "is CLI not found — is blockhost-engine installed?", critical=False
                    ))
                except subprocess.TimeoutExpired:
                    report.add(ValidationResult(
                        "NFT", "NFT contract exists", False,
                        "Contract check timed out", critical=False
                    ))
            else:
                report.add(ValidationResult(
                    "NFT", "NFT contract exists", True,
                    "Skipped (no NFT contract configured)", critical=False
                ))
        except ImportError:
            report.add(ValidationResult(
                "NFT", "NFT contract check", True,
                "Skipped (yaml module unavailable)", critical=False
            ))
        except Exception as e:
            report.add(ValidationResult(
                "NFT", "NFT contract check", False,
                f"Error: {e}", critical=False
            ))

    # ========== ENVIRONMENT FILE ==========

    env_path = Path('/opt/blockhost/.env')
    report.add(_check_env_file(
        env_path,
        required_vars=['RPC_URL', 'NFT_CONTRACT', 'DEPLOYER_KEY_FILE', 'BLOCKHOST_CONTRACT']
    ))
    if env_path.exists():
        report.add(_check_file_permissions(env_path, 0o640, "Permissions", ".env file"))
        # Check that RPC_URL is set
        try:
            env_content = env_path.read_text()
            if 'RPC_URL=' in env_content:
                report.add(ValidationResult("Environment", "RPC variable", True, "RPC endpoint configured"))
            else:
                report.add(ValidationResult("Environment", "RPC variable", False, "No RPC variable found in .env"))
        except Exception as e:
            report.add(ValidationResult("Environment", "RPC variable", False, f"Error reading .env: {e}"))

    # ========== PRIVILEGE SEPARATION ==========

    # blockhost user exists
    try:
        result = subprocess.run(
            ['id', '-u', 'blockhost'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            report.add(ValidationResult("Privilege Separation", "blockhost user", True, "User exists"))
        else:
            report.add(ValidationResult("Privilege Separation", "blockhost user", False, "blockhost system user not found"))
    except Exception as e:
        report.add(ValidationResult("Privilege Separation", "blockhost user", False, f"Error checking user: {e}"))

    # Root agent socket
    sock_path = Path('/run/blockhost/root-agent.sock')
    if sock_path.exists():
        report.add(ValidationResult("Privilege Separation", "Root agent socket", True, "Socket exists"))
        # Check socket permissions (660 root:blockhost)
        sock_stat = sock_path.stat()
        sock_mode = stat.S_IMODE(sock_stat.st_mode)
        if sock_mode == 0o660:
            report.add(ValidationResult("Privilege Separation", "Root agent socket permissions", True, "0660"))
        else:
            report.add(ValidationResult("Privilege Separation", "Root agent socket permissions", False,
                                        f"Expected 0660, got {oct(sock_mode)}"))
    else:
        report.add(ValidationResult("Privilege Separation", "Root agent socket", False,
                                    "Socket not found: /run/blockhost/root-agent.sock"))

    # Root agent service
    report.add(_check_service_state('blockhost-root-agent', expected_enabled=True, expected_active=True,
                                    category="Privilege Separation"))

    # /var/lib/blockhost ownership
    state_dir = Path('/var/lib/blockhost')
    if state_dir.exists():
        try:
            import pwd
            dir_stat = state_dir.stat()
            owner = pwd.getpwuid(dir_stat.st_uid).pw_name
            if owner == 'blockhost':
                report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost owner", True,
                                            "Owned by blockhost"))
            else:
                report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost owner", False,
                                            f"Owned by {owner}, expected blockhost"))
        except Exception as e:
            report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost owner", False, f"Error: {e}"))
    else:
        report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost owner", False,
                                    "Directory does not exist"))

    # /etc/blockhost directory permissions (750 root:blockhost)
    if etc_blockhost.exists():
        try:
            import grp
            dir_stat = etc_blockhost.stat()
            dir_mode = stat.S_IMODE(dir_stat.st_mode)
            if dir_mode == 0o750:
                report.add(ValidationResult("Privilege Separation", "/etc/blockhost permissions", True, "750"))
            else:
                report.add(ValidationResult("Privilege Separation", "/etc/blockhost permissions", False,
                                            f"Expected 0750, got {oct(dir_mode)}"))
            try:
                group_name = grp.getgrgid(dir_stat.st_gid).gr_name
                if group_name == 'blockhost':
                    report.add(ValidationResult("Privilege Separation", "/etc/blockhost group", True, "blockhost"))
                else:
                    report.add(ValidationResult("Privilege Separation", "/etc/blockhost group", False,
                                                f"Expected blockhost, got {group_name}"))
            except KeyError:
                report.add(ValidationResult("Privilege Separation", "/etc/blockhost group", False,
                                            f"Unknown GID {dir_stat.st_gid}"))
        except Exception as e:
            report.add(ValidationResult("Privilege Separation", "/etc/blockhost permissions", False, f"Error: {e}"))

    # /var/lib/blockhost/terraform ownership (Proxmox only)
    tf_state_dir = Path('/var/lib/blockhost/terraform')
    if tf_state_dir.exists() and provisioner_name in (None, 'proxmox'):
        try:
            import pwd
            tf_stat = tf_state_dir.stat()
            tf_owner = pwd.getpwuid(tf_stat.st_uid).pw_name
            if tf_owner == 'blockhost':
                report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost/terraform owner", True,
                                            "Owned by blockhost"))
            else:
                report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost/terraform owner", False,
                                            f"Owned by {tf_owner}, expected blockhost"))
        except Exception as e:
            report.add(ValidationResult("Privilege Separation", "/var/lib/blockhost/terraform owner", False, f"Error: {e}"))

    # YAML config file permissions (should be 0640 root:blockhost)
    yaml_configs = [
        (etc_blockhost / 'db.yaml', 'db.yaml'),
        (etc_blockhost / 'web3-defaults.yaml', 'web3-defaults.yaml'),
        (etc_blockhost / 'blockhost.yaml', 'blockhost.yaml'),
    ]
    for path, name in yaml_configs:
        if path.exists():
            report.add(_check_file_permissions(path, 0o640, "Permissions", name))

    # ========== SERVICES ==========

    # nginx should be enabled (serves signup page + reverse proxies admin panel)
    report.add(_check_service_state('nginx', expected_enabled=True, expected_active=None))

    # nginx config file exists
    nginx_conf = Path('/etc/nginx/sites-available/blockhost')
    report.add(_check_file_exists(nginx_conf, "Web", "nginx site config"))

    # nginx config syntax valid
    try:
        nginx_test = subprocess.run(
            ['nginx', '-t'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if nginx_test.returncode == 0:
            report.add(ValidationResult("Web", "nginx config syntax", True, "nginx -t passed"))
        else:
            report.add(ValidationResult("Web", "nginx config syntax", False,
                                        f"nginx -t failed: {nginx_test.stderr}"))
    except FileNotFoundError:
        report.add(ValidationResult("Web", "nginx config syntax", False, "nginx not installed"))
    except Exception as e:
        report.add(ValidationResult("Web", "nginx config syntax", False, f"Error: {e}"))

    # ========== CERTBOT RENEWAL (only when tls_mode == letsencrypt) ==========

    https_json = etc_blockhost / 'https.json'
    _tls_mode = None
    _le_hostname = None
    if https_json.exists():
        try:
            _https_data = json.loads(https_json.read_text())
            _tls_mode = _https_data.get('tls_mode')
            _le_hostname = _https_data.get('hostname')
        except Exception:
            pass

    if _tls_mode == 'letsencrypt' and _le_hostname:
        # ACME webroot directory
        certbot_webroot = Path('/var/www/certbot')
        report.add(ValidationResult(
            "Certbot", "webroot directory",
            certbot_webroot.is_dir(),
            f"{'Exists' if certbot_webroot.is_dir() else 'Missing'}: {certbot_webroot}",
        ))

        # Renewal config exists and uses webroot authenticator
        renewal_conf = Path(f'/etc/letsencrypt/renewal/{_le_hostname}.conf')
        if renewal_conf.exists():
            report.add(ValidationResult("Certbot", "renewal config", True, f"Exists: {renewal_conf}"))
            _renewal_txt = renewal_conf.read_text()
            report.add(ValidationResult(
                "Certbot", "webroot authenticator",
                'authenticator = webroot' in _renewal_txt,
                "authenticator = webroot" if 'authenticator = webroot' in _renewal_txt
                else f"Expected webroot, found other authenticator",
            ))
            report.add(ValidationResult(
                "Certbot", "webroot_path in renewalparams",
                'webroot_path' in _renewal_txt,
                "webroot_path present" if 'webroot_path' in _renewal_txt
                else "Missing webroot_path in [renewalparams]",
            ))
        else:
            report.add(ValidationResult("Certbot", "renewal config", False, f"Missing: {renewal_conf}"))

        # Deploy hook to reload nginx after renewal
        deploy_hook = Path('/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh')
        report.add(ValidationResult(
            "Certbot", "nginx reload deploy hook",
            deploy_hook.exists() and os.access(str(deploy_hook), os.X_OK),
            f"{'Exists and executable' if deploy_hook.exists() and os.access(str(deploy_hook), os.X_OK) else 'Missing or not executable'}: {deploy_hook}",
        ))

    # blockhost-monitor should be enabled (may not be active until reboot)
    report.add(_check_service_state('blockhost-monitor', expected_enabled=True, expected_active=None))

    # blockhost-admin should be enabled (behind nginx reverse proxy)
    report.add(_check_service_state('blockhost-admin', expected_enabled=True, expected_active=None))

    # blockhost-gc.timer should be enabled
    report.add(_check_service_state('blockhost-gc.timer', expected_enabled=True, expected_active=None))

    # blockhost-firstboot should be disabled after finalization
    report.add(_check_service_state('blockhost-firstboot', expected_enabled=False, expected_active=False))

    # ========== NETWORK ==========

    # Network bridge check — provisioner-agnostic
    # Bridge name from db.yaml (written by finalization from first-boot discovery)
    bridge_name = None
    db_yaml_path = etc_blockhost / 'db.yaml'
    if db_yaml_path.exists():
        try:
            import yaml
            db_data = yaml.safe_load(db_yaml_path.read_text())
            bridge_name = db_data.get('bridge') if db_data else None
        except:
            pass

    if not bridge_name:
        # Fallback: find any bridge device in /sys/class/net/*/bridge
        for p in Path('/sys/class/net').iterdir():
            if (p / 'bridge').is_dir():
                bridge_name = p.name
                break

    if bridge_name:
        report.add(_check_bridge_exists(bridge_name))
        report.add(_check_bridge_has_ip(bridge_name))
    else:
        report.add(ValidationResult("Network", "Bridge", False,
                                    "No bridge found in db.yaml or /sys/class/net/*/bridge",
                                    critical=False))

    # IPv6 forwarding sysctl
    sysctl_file = Path('/etc/sysctl.d/99-blockhost-ipv6.conf')
    if sysctl_file.exists():
        content = sysctl_file.read_text()
        if 'net.ipv6.conf.all.forwarding=1' in content:
            report.add(ValidationResult("Network", "IPv6 forwarding sysctl", True, "Persisted in 99-blockhost-ipv6.conf"))
        else:
            report.add(ValidationResult("Network", "IPv6 forwarding sysctl", False, "File exists but missing forwarding=1"))
    else:
        report.add(ValidationResult("Network", "IPv6 forwarding sysctl", False, "Missing: /etc/sysctl.d/99-blockhost-ipv6.conf", critical=False))

    # WireGuard persistent config (broker mode only)
    broker_alloc_data = None
    if broker_alloc.exists():
        try:
            broker_alloc_data = json.loads(broker_alloc.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    is_broker_mode = broker_alloc_data and broker_alloc_data.get('mode') != 'manual' and broker_alloc_data.get('prefix')
    if is_broker_mode:
        wg_conf = Path('/etc/wireguard/wg-broker.conf')
        report.add(_check_file_exists(wg_conf, "Network", "WireGuard broker config", critical=False))
        report.add(_check_service_state('wg-quick@wg-broker', expected_enabled=True, expected_active=None,
                                        category="Network", critical=False))

    # ========== SSH ==========

    if provisioner_name in (None, 'proxmox'):
        report.add(_check_ssh_key_in_authorized(etc_blockhost / 'terraform_ssh_key.pub'))

    # ========== WEB CONTENT ==========

    report.add(_check_file_exists(Path('/var/www/blockhost/signup.html'), "Web", "Signup page"))
    report.add(_check_signup_page_content())

    return report


VALIDATION_OUTPUT_FILE = Path('/var/lib/blockhost/validation-output.txt')


def validate_system() -> tuple[bool, str]:
    """
    Run full system validation and return result.

    Returns:
        Tuple of (success: bool, detailed_output: str)
    """
    if not is_testing_mode():
        return True, "Skipped (not in testing mode)"

    try:
        report = run_full_validation()
        output = report.summary()

        # Write output to file for frontend to display
        try:
            VALIDATION_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
            VALIDATION_OUTPUT_FILE.write_text(output)
        except Exception as e:
            output += f"\n\n(Warning: Could not write output file: {e})"

        return report.passed, output

    except Exception as e:
        error_msg = f"Validation error: {e}"
        try:
            VALIDATION_OUTPUT_FILE.write_text(error_msg)
        except:
            pass
        return False, error_msg


if __name__ == '__main__':
    # When run directly, always validate (ignore testing mode check)
    report = run_full_validation()
    print(report.summary())

    if report.passed:
        print("✓ System validation PASSED")
    else:
        print("✗ System validation FAILED")

    exit(0 if report.passed else 1)
