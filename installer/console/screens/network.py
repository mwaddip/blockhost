"""
Network configuration wizard for console installer.

Guides user through:
1. Interface selection (if multiple)
2. DHCP attempt with timeout
3. Manual IP configuration fallback
"""

from typing import Optional
from ..whiptail import Whiptail, DialogResult
from ...common.network import NetworkManager, NetworkConfig, NetworkInterface


class NetworkWizard:
    """Network configuration wizard."""

    def __init__(self, whiptail: Optional[Whiptail] = None):
        """
        Initialize network wizard.

        Args:
            whiptail: Whiptail instance (creates one if not provided)
        """
        self.wt = whiptail or Whiptail(title="Network Configuration")
        self.net = NetworkManager()
        self.selected_interface: Optional[NetworkInterface] = None
        self.config: Optional[NetworkConfig] = None

    def run(self) -> bool:
        """
        Run the network wizard.

        Returns:
            True if network was configured successfully
        """
        # Step 1: Detect and select interface
        if not self._select_interface():
            return False

        # Step 2: Try DHCP first
        if self._try_dhcp():
            return True

        # Step 3: Manual configuration
        return self._manual_config()

    def _select_interface(self) -> bool:
        """
        Select network interface.

        Returns:
            True if interface selected
        """
        interfaces = self.net.detect_interfaces(include_virtual=False)

        if not interfaces:
            self.wt.msgbox(
                "No network interfaces detected!\n\n"
                "Please check your hardware and try again."
            )
            return False

        # If only one interface, use it
        if len(interfaces) == 1:
            self.selected_interface = interfaces[0]
            return True

        # Multiple interfaces - let user choose
        # Prefer interfaces with carrier
        choices = []
        for iface in interfaces:
            carrier = "[CONNECTED]" if iface.has_carrier else "[no link]"
            desc = f"{iface.mac} {carrier}"
            choices.append((iface.name, desc))

        result = self.wt.menu(
            "Select network interface:",
            choices
        )

        if not result.ok:
            return False

        # Find selected interface
        for iface in interfaces:
            if iface.name == result.value:
                self.selected_interface = iface
                return True

        return False

    def _try_dhcp(self) -> bool:
        """
        Attempt DHCP configuration.

        Returns:
            True if DHCP succeeded
        """
        if not self.selected_interface:
            return False

        iface = self.selected_interface.name

        # Show trying DHCP message
        self.wt.infobox(
            f"Attempting DHCP on {iface}...\n\n"
            "Please wait, this may take up to 30 seconds."
        )

        success, message = self.net.run_dhcp(iface, timeout=30)

        if success:
            # Get the assigned IP
            ip = self.net.get_current_ip(iface)
            gateway = self.net.get_current_gateway()

            self.config = NetworkConfig(
                interface=iface,
                method='dhcp',
                address=ip,
                gateway=gateway,
            )

            self.wt.msgbox(
                f"DHCP configuration successful!\n\n"
                f"Interface: {iface}\n"
                f"IP Address: {ip}\n"
                f"Gateway: {gateway or 'N/A'}"
            )
            return True
        else:
            # Ask if user wants to try manual config
            result = self.wt.yesno(
                f"DHCP failed: {message}\n\n"
                "Would you like to configure the network manually?"
            )
            return False  # Will proceed to manual config if user said yes

    def _manual_config(self) -> bool:
        """
        Manual network configuration.

        Returns:
            True if configuration succeeded
        """
        if not self.selected_interface:
            return False

        iface = self.selected_interface.name

        # Get IP address
        result = self.wt.inputbox(
            "Enter IP address (e.g., 192.168.1.100):",
            ""
        )
        if not result.ok or not result.value:
            return False
        ip_address = result.value.strip()

        # Validate IP format
        if not self._validate_ip(ip_address):
            self.wt.msgbox(f"Invalid IP address: {ip_address}")
            return self._manual_config()  # Retry

        # Get netmask
        result = self.wt.inputbox(
            "Enter netmask (e.g., 255.255.255.0):",
            "255.255.255.0"
        )
        if not result.ok or not result.value:
            return False
        netmask = result.value.strip()

        # Get gateway
        # Suggest gateway based on IP
        suggested_gw = self._suggest_gateway(ip_address)
        result = self.wt.inputbox(
            "Enter gateway address:",
            suggested_gw
        )
        if not result.ok:
            return False
        gateway = result.value.strip()

        # Get DNS
        result = self.wt.inputbox(
            "Enter DNS server(s) (comma-separated):",
            "8.8.8.8, 8.8.4.4"
        )
        if not result.ok:
            return False
        dns_input = result.value.strip()
        dns = [s.strip() for s in dns_input.split(',') if s.strip()]

        # Confirm configuration
        confirm_text = (
            f"Apply the following configuration?\n\n"
            f"Interface: {iface}\n"
            f"IP Address: {ip_address}\n"
            f"Netmask: {netmask}\n"
            f"Gateway: {gateway}\n"
            f"DNS: {', '.join(dns)}"
        )

        result = self.wt.yesno(confirm_text)
        if not result.ok:
            return False

        # Apply configuration
        self.config = NetworkConfig(
            interface=iface,
            method='static',
            address=ip_address,
            netmask=netmask,
            gateway=gateway,
            dns=dns,
        )

        self.wt.infobox("Applying network configuration...")

        success, message = self.net.configure_static(self.config)

        if success:
            # Test connectivity
            self.wt.infobox("Testing network connectivity...")

            if self.net.test_connectivity():
                self.wt.msgbox(
                    "Network configured successfully!\n\n"
                    f"{message}\n"
                    "Internet connectivity: OK"
                )
            else:
                self.wt.msgbox(
                    "Network configured, but no internet access.\n\n"
                    f"{message}\n\n"
                    "You may need to check your gateway settings."
                )
            return True
        else:
            self.wt.msgbox(f"Configuration failed: {message}")
            return False

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _suggest_gateway(self, ip: str) -> str:
        """Suggest gateway based on IP address."""
        try:
            parts = ip.split('.')
            parts[-1] = '1'
            return '.'.join(parts)
        except Exception:
            return ""


def run_network_wizard() -> Optional[NetworkConfig]:
    """
    Run network wizard and return configuration.

    Returns:
        NetworkConfig if successful, None otherwise
    """
    wizard = NetworkWizard()
    if wizard.run():
        return wizard.config
    return None


if __name__ == '__main__':
    config = run_network_wizard()
    if config:
        print(f"Network configured: {config.to_dict()}")
    else:
        print("Network configuration cancelled or failed")
