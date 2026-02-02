"""
Network utilities for BlockHost installer.

Handles:
- Interface detection
- DHCP client
- Static IP configuration
- Gateway/DNS setup
"""

import ipaddress
import json
import re
import subprocess
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional


@dataclass
class NetworkInterface:
    """Represents a network interface."""
    name: str
    mac: str
    state: str  # up, down, unknown
    has_carrier: bool
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    is_virtual: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkConfig:
    """Network configuration."""
    interface: str
    method: str  # dhcp, static
    address: Optional[str] = None
    netmask: Optional[str] = None
    gateway: Optional[str] = None
    dns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class NetworkManager:
    """Manages network configuration."""

    # Virtual interface patterns to exclude
    VIRTUAL_PATTERNS = [
        r'^lo$',
        r'^veth',
        r'^docker',
        r'^br-',
        r'^virbr',
        r'^vmbr',
        r'^tap',
        r'^tun',
        r'^bond',
        r'^dummy',
    ]

    def __init__(self):
        self._interfaces: Optional[list[NetworkInterface]] = None

    def _is_virtual(self, name: str) -> bool:
        """Check if interface is virtual."""
        for pattern in self.VIRTUAL_PATTERNS:
            if re.match(pattern, name):
                return True
        return False

    def _get_interface_state(self, name: str) -> tuple[str, bool]:
        """Get interface operational state and carrier status."""
        try:
            state_path = Path(f'/sys/class/net/{name}/operstate')
            carrier_path = Path(f'/sys/class/net/{name}/carrier')

            state = state_path.read_text().strip() if state_path.exists() else 'unknown'

            try:
                carrier = carrier_path.read_text().strip() == '1'
            except (OSError, IOError):
                # Carrier file may not be readable if interface is down
                carrier = False

            return state, carrier
        except Exception:
            return 'unknown', False

    def _get_interface_addresses(self, name: str) -> tuple[list[str], list[str]]:
        """Get IPv4 and IPv6 addresses for an interface."""
        ipv4 = []
        ipv6 = []

        try:
            result = subprocess.run(
                ['ip', '-j', 'addr', 'show', name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data:
                    for addr_info in data[0].get('addr_info', []):
                        addr = f"{addr_info['local']}/{addr_info['prefixlen']}"
                        if addr_info['family'] == 'inet':
                            ipv4.append(addr)
                        elif addr_info['family'] == 'inet6':
                            ipv6.append(addr)
        except Exception:
            pass

        return ipv4, ipv6

    def detect_interfaces(self, include_virtual: bool = False) -> list[NetworkInterface]:
        """
        Detect available network interfaces.

        Args:
            include_virtual: Include virtual interfaces

        Returns:
            List of NetworkInterface objects
        """
        interfaces = []
        net_dir = Path('/sys/class/net')

        if not net_dir.exists():
            return interfaces

        for iface_path in net_dir.iterdir():
            name = iface_path.name
            is_virtual = self._is_virtual(name)

            if is_virtual and not include_virtual:
                continue

            # Get MAC address
            try:
                mac = (iface_path / 'address').read_text().strip()
            except Exception:
                mac = ''

            state, carrier = self._get_interface_state(name)
            ipv4, ipv6 = self._get_interface_addresses(name)

            interfaces.append(NetworkInterface(
                name=name,
                mac=mac,
                state=state,
                has_carrier=carrier,
                ipv4=ipv4,
                ipv6=ipv6,
                is_virtual=is_virtual,
            ))

        # Sort: interfaces with carrier first, then by name
        interfaces.sort(key=lambda i: (not i.has_carrier, i.name))
        self._interfaces = interfaces
        return interfaces

    def get_default_interface(self) -> Optional[NetworkInterface]:
        """Get the best interface for configuration (has carrier, not virtual)."""
        interfaces = self.detect_interfaces(include_virtual=False)

        # Prefer interface with carrier
        for iface in interfaces:
            if iface.has_carrier:
                return iface

        # Fall back to first non-virtual interface
        return interfaces[0] if interfaces else None

    def run_dhcp(self, interface: str, timeout: int = 30) -> tuple[bool, str]:
        """
        Run DHCP client on interface.

        Args:
            interface: Interface name
            timeout: DHCP timeout in seconds

        Returns:
            Tuple of (success, message)
        """
        # Bring interface up first
        subprocess.run(['ip', 'link', 'set', interface, 'up'],
                      capture_output=True, timeout=5)

        # Try dhclient first (more common on Debian)
        dhcp_commands = [
            ['dhclient', '-v', '-1', '-timeout', str(timeout), interface],
            ['dhcpcd', '-w', '-t', str(timeout), interface],
        ]

        for cmd in dhcp_commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 10
                )
                if result.returncode == 0:
                    # Verify we got an IP
                    time.sleep(1)
                    ipv4, _ = self._get_interface_addresses(interface)
                    if ipv4:
                        return True, f"DHCP configured: {ipv4[0]}"
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                return False, f"DHCP timeout after {timeout}s"
            except Exception as e:
                return False, f"DHCP error: {e}"

        return False, "No DHCP client available"

    def configure_static(self, config: NetworkConfig) -> tuple[bool, str]:
        """
        Configure static IP address.

        Args:
            config: Network configuration

        Returns:
            Tuple of (success, message)
        """
        iface = config.interface

        try:
            # Flush existing addresses
            subprocess.run(['ip', 'addr', 'flush', 'dev', iface],
                          capture_output=True, timeout=5)

            # Bring interface up
            subprocess.run(['ip', 'link', 'set', iface, 'up'],
                          capture_output=True, timeout=5)

            # Add IP address
            if config.address and config.netmask:
                # Convert netmask to CIDR if needed
                try:
                    network = ipaddress.IPv4Network(f"0.0.0.0/{config.netmask}", strict=False)
                    prefix_len = network.prefixlen
                except ValueError:
                    prefix_len = config.netmask

                addr_cidr = f"{config.address}/{prefix_len}"
                result = subprocess.run(
                    ['ip', 'addr', 'add', addr_cidr, 'dev', iface],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    return False, f"Failed to set IP: {result.stderr}"

            # Add default gateway
            if config.gateway:
                # Remove existing default route
                subprocess.run(['ip', 'route', 'del', 'default'],
                              capture_output=True, timeout=5)

                result = subprocess.run(
                    ['ip', 'route', 'add', 'default', 'via', config.gateway],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    return False, f"Failed to set gateway: {result.stderr}"

            # Configure DNS
            if config.dns:
                self._configure_dns(config.dns)

            return True, f"Static IP configured: {config.address}"

        except subprocess.TimeoutExpired:
            return False, "Configuration timeout"
        except Exception as e:
            return False, f"Configuration error: {e}"

    def _configure_dns(self, servers: list[str]) -> None:
        """Configure DNS servers in /etc/resolv.conf."""
        content = "# Generated by BlockHost installer\n"
        for server in servers:
            content += f"nameserver {server}\n"

        try:
            Path('/etc/resolv.conf').write_text(content)
        except Exception:
            pass

    def get_current_ip(self, interface: Optional[str] = None) -> Optional[str]:
        """
        Get current IPv4 address.

        Args:
            interface: Specific interface or None for any

        Returns:
            IP address without prefix or None
        """
        if interface:
            ipv4, _ = self._get_interface_addresses(interface)
            if ipv4:
                return ipv4[0].split('/')[0]
        else:
            interfaces = self.detect_interfaces()
            for iface in interfaces:
                if iface.ipv4:
                    return iface.ipv4[0].split('/')[0]
        return None

    def get_current_gateway(self) -> Optional[str]:
        """Get current default gateway."""
        try:
            result = subprocess.run(
                ['ip', '-j', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data:
                    return data[0].get('gateway')
        except Exception:
            pass
        return None

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in a private range."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def test_connectivity(self, host: str = '8.8.8.8', timeout: int = 5) -> bool:
        """Test network connectivity with ping."""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), host],
                capture_output=True,
                timeout=timeout + 2
            )
            return result.returncode == 0
        except Exception:
            return False


if __name__ == '__main__':
    # CLI for testing
    import sys

    mgr = NetworkManager()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == 'interfaces':
            interfaces = mgr.detect_interfaces(include_virtual='--all' in sys.argv)
            for iface in interfaces:
                carrier = 'UP' if iface.has_carrier else 'DOWN'
                ips = ', '.join(iface.ipv4) if iface.ipv4 else 'no IP'
                print(f"{iface.name}: {iface.mac} [{carrier}] {ips}")

        elif cmd == 'dhcp':
            if len(sys.argv) < 3:
                iface = mgr.get_default_interface()
                if iface:
                    iface_name = iface.name
                else:
                    print("No interface found")
                    sys.exit(1)
            else:
                iface_name = sys.argv[2]
            print(f"Running DHCP on {iface_name}...")
            success, msg = mgr.run_dhcp(iface_name)
            print(msg)
            sys.exit(0 if success else 1)

        elif cmd == 'status':
            ip = mgr.get_current_ip()
            gw = mgr.get_current_gateway()
            print(f"IP: {ip or 'none'}")
            print(f"Gateway: {gw or 'none'}")
            print(f"Private IP: {mgr.is_private_ip(ip) if ip else 'N/A'}")
            print(f"Connectivity: {'OK' if mgr.test_connectivity() else 'FAIL'}")

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)
    else:
        print("Usage: network.py <interfaces|dhcp|status> [args]")
