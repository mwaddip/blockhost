"""
OTP (One-Time Password) system for BlockHost installer.

Session-based OTP for authenticating web installer access.
- 6 character alphanumeric (excluding confusing chars: 0/O, 1/I/l)
- Stored in /run/blockhost/otp.json
- 4-hour timeout
- 10 maximum attempts before lockout
"""

import json
import os
import secrets
import string
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


# Characters that can be confused are excluded
OTP_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
OTP_LENGTH = 6
OTP_TIMEOUT_SECONDS = 4 * 60 * 60  # 4 hours
OTP_MAX_ATTEMPTS = 10
OTP_STATE_DIR = Path('/run/blockhost')
OTP_STATE_FILE = OTP_STATE_DIR / 'otp.json'


@dataclass
class OTPState:
    """OTP session state."""
    code: str
    created_at: float
    expires_at: float
    attempts: int
    locked: bool
    verified: bool

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'OTPState':
        return cls(**data)


class OTPManager:
    """Manages OTP generation and validation."""

    def __init__(self, state_dir: Optional[Path] = None):
        """
        Initialize OTP manager.

        Args:
            state_dir: Override state directory (for testing)
        """
        self.state_dir = state_dir or OTP_STATE_DIR
        self.state_file = self.state_dir / 'otp.json'
        self._state: Optional[OTPState] = None

    def _ensure_state_dir(self) -> None:
        """Create state directory if needed."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        # Secure permissions - only root should access
        os.chmod(self.state_dir, 0o700)

    def _load_state(self) -> Optional[OTPState]:
        """Load OTP state from disk."""
        if not self.state_file.exists():
            return None
        try:
            data = json.loads(self.state_file.read_text())
            return OTPState.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def _save_state(self, state: OTPState) -> None:
        """Save OTP state to disk."""
        self._ensure_state_dir()
        self.state_file.write_text(json.dumps(state.to_dict(), indent=2))
        os.chmod(self.state_file, 0o600)

    def _generate_code(self) -> str:
        """Generate a new OTP code."""
        return ''.join(secrets.choice(OTP_CHARS) for _ in range(OTP_LENGTH))

    def generate(self, force: bool = False) -> str:
        """
        Generate a new OTP.

        Args:
            force: Force regeneration even if valid OTP exists

        Returns:
            The OTP code
        """
        current = self._load_state()
        now = time.time()

        # Return existing valid OTP unless forced
        if current and not force:
            if not current.locked and not current.verified and current.expires_at > now:
                return current.code

        # Generate new OTP
        code = self._generate_code()
        state = OTPState(
            code=code,
            created_at=now,
            expires_at=now + OTP_TIMEOUT_SECONDS,
            attempts=0,
            locked=False,
            verified=False,
        )
        self._save_state(state)
        return code

    def verify(self, code: str) -> tuple[bool, str]:
        """
        Verify an OTP code.

        Args:
            code: The code to verify

        Returns:
            Tuple of (success, message)
        """
        state = self._load_state()
        now = time.time()

        # No OTP generated
        if state is None:
            return False, "No OTP generated"

        # Already locked out
        if state.locked:
            return False, "Too many attempts. Please regenerate OTP."

        # Already verified (prevent replay)
        if state.verified:
            return False, "OTP already used"

        # Expired
        if state.expires_at < now:
            return False, "OTP expired"

        # Increment attempt counter
        state.attempts += 1

        # Check for lockout
        if state.attempts >= OTP_MAX_ATTEMPTS:
            state.locked = True
            self._save_state(state)
            return False, "Too many attempts. OTP locked."

        # Verify code (case-insensitive)
        if code.upper().strip() != state.code:
            self._save_state(state)
            remaining = OTP_MAX_ATTEMPTS - state.attempts
            return False, f"Invalid OTP. {remaining} attempts remaining."

        # Success!
        state.verified = True
        self._save_state(state)
        return True, "OTP verified successfully"

    def get_status(self) -> dict:
        """
        Get current OTP status (without revealing the code).

        Returns:
            Dict with status information
        """
        state = self._load_state()
        now = time.time()

        if state is None:
            return {
                'exists': False,
                'valid': False,
                'locked': False,
                'verified': False,
                'attempts': 0,
                'expires_in': 0,
            }

        return {
            'exists': True,
            'valid': not state.locked and not state.verified and state.expires_at > now,
            'locked': state.locked,
            'verified': state.verified,
            'attempts': state.attempts,
            'expires_in': max(0, int(state.expires_at - now)),
        }

    def get_code(self) -> Optional[str]:
        """
        Get the current OTP code (for display on console).

        Returns:
            The OTP code or None if not available
        """
        state = self._load_state()
        if state and not state.locked and not state.verified:
            if state.expires_at > time.time():
                return state.code
        return None

    def invalidate(self) -> None:
        """Invalidate the current OTP."""
        if self.state_file.exists():
            self.state_file.unlink()


def display_otp_on_console(otp_code: str, tty: str = '/dev/tty1') -> None:
    """
    Display OTP code on the physical console.

    Args:
        otp_code: The OTP to display
        tty: TTY device to write to
    """
    # ANSI escape codes for formatting
    CLEAR = '\033[2J\033[H'
    BOLD = '\033[1m'
    GREEN = '\033[32m'
    CYAN = '\033[36m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

    message = f"""
{CLEAR}
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════╗
║                      BlockHost Installer                          ║
╚══════════════════════════════════════════════════════════════════╝{RESET}

{BOLD}Web Installer Access Code:{RESET}

    {BOLD}{GREEN}┌─────────────────┐
    │     {otp_code}      │
    └─────────────────┘{RESET}

{YELLOW}Instructions:{RESET}
1. Open a web browser on another device
2. Navigate to the IP address shown below
3. Enter the code above to authenticate

{BOLD}This code expires in 4 hours.{RESET}
{BOLD}Maximum 10 attempts allowed.{RESET}

Press Ctrl+C to regenerate the code.
"""

    try:
        with open(tty, 'w') as f:
            f.write(message)
    except PermissionError:
        # Fallback to stdout if we can't write to TTY
        print(message)


if __name__ == '__main__':
    # CLI for testing
    import sys

    mgr = OTPManager()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == 'generate':
            code = mgr.generate(force='--force' in sys.argv)
            print(f"OTP: {code}")

        elif cmd == 'verify':
            if len(sys.argv) < 3:
                print("Usage: otp.py verify <code>")
                sys.exit(1)
            success, msg = mgr.verify(sys.argv[2])
            print(msg)
            sys.exit(0 if success else 1)

        elif cmd == 'status':
            status = mgr.get_status()
            for k, v in status.items():
                print(f"{k}: {v}")

        elif cmd == 'display':
            code = mgr.get_code()
            if code:
                display_otp_on_console(code)
            else:
                print("No valid OTP to display")

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)
    else:
        print("Usage: otp.py <generate|verify|status|display> [args]")
