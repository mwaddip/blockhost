#!/usr/bin/env python3
"""
BlockHost Console Installer - Main Entry Point

This is launched when:
1. DHCP fails during automatic network setup
2. User explicitly requests console access
3. No web browser available

Provides a whiptail-based wizard for basic configuration.
"""

import sys
import os
from pathlib import Path

# Add parent to path for imports when running directly
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from installer.console.whiptail import Whiptail
from installer.console.screens.network import NetworkWizard, run_network_wizard
from installer.common.network import NetworkManager
from installer.common.otp import OTPManager, display_otp_on_console


class ConsoleInstaller:
    """Main console installer orchestrator."""

    def __init__(self):
        self.wt = Whiptail(title="BlockHost Setup")
        self.net = NetworkManager()
        self.otp = OTPManager()

    def run(self) -> int:
        """
        Run the console installer.

        Returns:
            Exit code (0 = success)
        """
        # Welcome screen
        self._show_welcome()

        # Network configuration
        if not self._configure_network():
            self.wt.msgbox(
                "Network configuration failed.\n\n"
                "The system will continue to boot, but the web installer\n"
                "will not be accessible.\n\n"
                "You can run this wizard again with:\n"
                "  blockhost-console"
            )
            return 1

        # Show OTP and web access info
        self._show_web_access_info()

        return 0

    def _show_welcome(self) -> None:
        """Display welcome message."""
        self.wt.msgbox(
            "Welcome to BlockHost Setup!\n\n"
            "This wizard will help you configure network access\n"
            "so you can complete the installation via web browser.\n\n"
            "Press OK to continue.",
            height=12
        )

    def _configure_network(self) -> bool:
        """Run network configuration."""
        # Check if we already have network
        current_ip = self.net.get_current_ip()
        if current_ip and self.net.test_connectivity():
            result = self.wt.yesno(
                f"Network is already configured:\n\n"
                f"IP Address: {current_ip}\n"
                f"Gateway: {self.net.get_current_gateway() or 'N/A'}\n\n"
                "Do you want to reconfigure?",
                default_no=True
            )
            if not result.ok:
                return True  # Keep existing config

        # Run network wizard
        wizard = NetworkWizard(self.wt)
        return wizard.run()

    def _show_web_access_info(self) -> None:
        """Display web installer access information."""
        ip = self.net.get_current_ip()

        if not ip:
            self.wt.msgbox(
                "Could not determine IP address.\n\n"
                "Please check your network configuration."
            )
            return

        # Generate OTP
        otp_code = self.otp.generate()

        # Determine URL scheme based on IP
        scheme = "http" if self.net.is_private_ip(ip) else "https"
        url = f"{scheme}://{ip}/"

        self.wt.msgbox(
            f"Network configured successfully!\n\n"
            f"Complete the installation using the web interface:\n\n"
            f"URL: {url}\n\n"
            f"Access Code: {otp_code}\n\n"
            f"The code is also displayed on the console (TTY1).\n\n"
            f"IMPORTANT: The code expires in 4 hours and allows\n"
            f"a maximum of 10 attempts.",
            height=18
        )

        # Also display on TTY1 for physical console access
        try:
            display_otp_on_console(otp_code)
        except Exception:
            pass  # Non-critical if TTY display fails


def main() -> int:
    """Main entry point."""
    # Ensure we're running as root
    if os.geteuid() != 0:
        print("Error: This installer must be run as root", file=sys.stderr)
        return 1

    installer = ConsoleInstaller()
    return installer.run()


def run_console_wizard() -> int:
    """Entry point for module usage."""
    return main()


if __name__ == '__main__':
    sys.exit(main())
