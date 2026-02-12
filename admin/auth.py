"""Wallet-based authentication for the admin panel.

Same flow as libpam-web3 SSH login: generate challenge code, admin signs
with wallet, backend verifies via `cast wallet verify`.

Admin identity resolved via NFT ownership: `bw who admin` queries the chain
for the current holder of the admin credential NFT.
"""

import os
import secrets
import socket
import subprocess
import time
from functools import wraps
from pathlib import Path

from flask import redirect, request, session, url_for

KNOCK_ACTIVE_PATH = Path("/run/blockhost/knock.active")

CHALLENGE_TTL = 300  # 5 minutes
SESSION_TTL = 3600  # 1 hour
OTP_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L
OTP_LENGTH = 6

# Module-level state (same pattern as broker-manager)
_challenges = {}  # code → expiry timestamp
_sessions = {}  # token → (address, expiry)

# Cached admin wallet (from bw who admin)
_admin_wallet = None
_admin_wallet_ts = 0
_WALLET_CACHE_TTL = 60


def _purge_expired():
    """Remove expired challenges and sessions."""
    now = time.time()
    expired_c = [k for k, v in _challenges.items() if v < now]
    for k in expired_c:
        del _challenges[k]
    expired_s = [k for k, (_, exp) in _sessions.items() if exp < now]
    for k in expired_s:
        del _sessions[k]


def generate_challenge():
    """Generate a random 6-char OTP code and store it with expiry."""
    _purge_expired()
    code = "".join(secrets.choice(OTP_CHARS) for _ in range(OTP_LENGTH))
    _challenges[code] = time.time() + CHALLENGE_TTL
    return code


def get_admin_wallet():
    """Query NFT ownership for admin credential via `bw who admin`. Cached briefly."""
    global _admin_wallet, _admin_wallet_ts
    now = time.time()
    if _admin_wallet and (now - _admin_wallet_ts) < _WALLET_CACHE_TTL:
        return _admin_wallet
    try:
        result = subprocess.run(
            ["bw", "who", "admin"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            addr = result.stdout.strip()
            if addr.startswith("0x") and len(addr) == 42:
                _admin_wallet = addr
                _admin_wallet_ts = now
                return addr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def get_hostname():
    """Get machine hostname for challenge message."""
    return socket.gethostname()


def build_message(code):
    """Build the signing message — same format as PAM module."""
    return f"Authenticate to {get_hostname()} with code: {code}"


def verify_signature(code, signature):
    """Verify a wallet signature against a challenge code.

    Returns (success, address_or_error).
    """
    # Validate challenge exists and hasn't expired
    expiry = _challenges.get(code)
    if expiry is None:
        return False, "unknown or expired code"
    if time.time() > expiry:
        del _challenges[code]
        return False, "code expired"

    # Consume the challenge (one-time use)
    del _challenges[code]

    admin_wallet = get_admin_wallet()
    if not admin_wallet:
        return False, "admin wallet not configured"

    # Validate signature format before passing to subprocess
    sig = signature.strip()
    if not sig.startswith("0x") or len(sig) != 132:
        return False, "invalid signature format"

    message = build_message(code)

    try:
        result = subprocess.run(
            [
                "cast", "wallet", "verify",
                "--address", admin_wallet,
                message,
                sig,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return True, admin_wallet
        return False, "signature verification failed"
    except FileNotFoundError:
        return False, "cast not found — is Foundry installed?"
    except subprocess.TimeoutExpired:
        return False, "verification timed out"


def create_session(address):
    """Create a new auth session. Returns the session token."""
    _purge_expired()
    token = secrets.token_hex(32)
    _sessions[token] = (address, time.time() + SESSION_TTL)
    return token


def validate_session(token):
    """Check if a session token is valid. Returns address or None."""
    if not token:
        return None
    entry = _sessions.get(token)
    if entry is None:
        return None
    address, expiry = entry
    if time.time() > expiry:
        del _sessions[token]
        return None
    return address


def invalidate_session(token):
    """Remove a session."""
    _sessions.pop(token, None)


def _touch_knock_active():
    """Write client IP to /run/blockhost/knock.active to signal active admin session."""
    try:
        KNOCK_ACTIVE_PATH.write_text(request.remote_addr or "")
    except OSError:
        pass


def login_required(f):
    """Decorator: redirect to /login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("auth_token")
        address = validate_session(token)
        if not address:
            session.pop("auth_token", None)
            return redirect(url_for("admin.login"))
        _touch_knock_active()
        return f(*args, **kwargs)
    return decorated
