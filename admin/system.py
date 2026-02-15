"""Data collection and system actions for the admin panel.

Reads from host-level sources (procfs, ip, lsblk, config files).
VM operations go through the provisioner CLI contract.
"""

import json
import os
import platform
import re
import shutil
import socket
import subprocess

ADMIN_CONFIG_PATH = "/etc/blockhost/admin.json"
ADMIN_COMMANDS_PATH = "/etc/blockhost/admin-commands.json"
ADDRESSBOOK_PATH = "/etc/blockhost/addressbook.json"
BW_ENV_PATH = "/opt/blockhost/.env"
ENGINE_MANIFEST_PATH = "/usr/share/blockhost/engine.json"

# Engine-supplied format constraints (loaded once at startup)
_address_re = None
_token_re = None
_native_token = None


def _load_engine_constraints():
    """Load format patterns from engine manifest for input validation."""
    global _address_re, _token_re, _native_token
    try:
        with open(ENGINE_MANIFEST_PATH) as f:
            manifest = json.load(f)
        constraints = manifest.get('constraints', {})
        ap = constraints.get('address_pattern')
        if ap:
            _address_re = re.compile(ap)
        tp = constraints.get('token_pattern')
        if tp:
            _token_re = re.compile(tp)
        _native_token = constraints.get('native_token')
    except (OSError, json.JSONDecodeError, re.error):
        pass


_load_engine_constraints()


def _valid_token(token):
    """Validate token identifier against engine constraints."""
    if not token:
        return False
    # Chain-agnostic keywords (accepted by all bw implementations)
    if token in ('native', 'stable', 'stablecoin'):
        return True
    # Engine native token keyword (e.g. 'eth' for EVM)
    if _native_token and token == _native_token:
        return True
    # Token address matching engine pattern
    if _token_re and _token_re.match(token):
        return True
    return False


def _valid_destination(dest):
    """Validate destination (addressbook role name or raw address)."""
    if not dest:
        return False
    # Addressbook role name
    if re.match(r'^[a-zA-Z0-9_-]{1,32}$', dest):
        return True
    # Raw address matching engine pattern
    if _address_re and _address_re.match(dest):
        return True
    return False


def _valid_address(addr):
    """Validate a raw address against engine constraints."""
    if not addr:
        return False
    if _address_re:
        return bool(_address_re.match(addr))
    # No engine constraints — accept non-empty, let CLI validate
    return True


def _run(cmd, timeout=10):
    """Run a command, return (ok, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return False, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s"


def _run_json(cmd, timeout=10):
    """Run a command expecting JSON stdout. Returns parsed dict/list or None."""
    ok, out, err = _run(cmd, timeout=timeout)
    if not ok or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# --- System ---

def get_system_info():
    hostname = socket.gethostname()

    uptime_seconds = None
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass

    os_name = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass

    return {
        "hostname": hostname,
        "uptime_seconds": uptime_seconds,
        "os": os_name,
        "kernel": platform.release(),
    }


def set_hostname(name):
    """Set system hostname via hostnamectl. Returns (ok, error)."""
    if not name or not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', name):
        return False, "invalid hostname"
    ok, _, err = _run(["hostnamectl", "set-hostname", name])
    if not ok:
        return False, err or "hostnamectl failed"
    return True, None


# --- Network ---

def get_network_info():
    ipv4 = None
    gateway = None
    dns = []

    # IPv4 address — first non-loopback
    addrs = _run_json(["ip", "-j", "addr", "show"])
    if addrs:
        for iface in addrs:
            if iface.get("ifname") == "lo":
                continue
            for info in iface.get("addr_info", []):
                if info.get("family") == "inet" and not ipv4:
                    ipv4 = info.get("local")

    # Default gateway
    routes = _run_json(["ip", "-j", "route", "show", "default"])
    if routes and len(routes) > 0:
        gateway = routes[0].get("gateway")

    # DNS
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns.append(parts[1])
    except OSError:
        pass

    # IPv6 broker allocation (read directly — no subprocess needed)
    ipv6_broker = None
    try:
        with open("/etc/blockhost/broker-allocation.json") as f:
            ipv6_broker = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        pass

    return {
        "ipv4": ipv4,
        "gateway": gateway,
        "dns": dns,
        "ipv6_broker": ipv6_broker,
    }


def renew_broker_lease():
    """Renew broker allocation via root agent (needs root for WireGuard + config files)."""
    from blockhost.root_agent import call, RootAgentError
    try:
        result = call("broker-renew", timeout=60)
        if not result.get("ok"):
            return False, result.get("error", "broker-renew failed")
        return True, None
    except RootAgentError as e:
        return False, str(e)


def renew_letsencrypt_cert():
    """Run certbot renew (webroot mode, no downtime). Returns (ok, error)."""
    ok, out, err = _run(["certbot", "renew", "--non-interactive"], timeout=120)
    if not ok:
        return False, err or out or "certbot renew failed"
    return True, None


# --- Security ---

def get_security_info():
    """Read admin-commands.json and flatten for dashboard display.

    File structure: {"commands": {"<name>": {"action": "knock", "params": {...}}}}
    Returns flat dict: {enabled, knock_command, knock_ports, knock_timeout}
    """
    try:
        with open(ADMIN_COMMANDS_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    commands = data.get("commands", {})
    if not commands:
        return {"enabled": False}

    # Find the first knock command
    for name, cmd in commands.items():
        if cmd.get("action") == "knock":
            params = cmd.get("params", {})
            return {
                "enabled": True,
                "knock_command": name,
                "knock_ports": params.get("allowed_ports", []),
                "knock_timeout": params.get("default_duration", 300),
            }

    return {"enabled": True, "knock_command": list(commands.keys())[0]}


def update_security_settings(updates):
    """Update knock settings in admin-commands.json.

    Dashboard sends flat keys; this writes them back into the nested structure.
    Returns (ok, error).
    """
    allowed_keys = {"knock_command", "knock_ports", "knock_timeout"}
    filtered = {k: v for k, v in updates.items() if k in allowed_keys}
    if not filtered:
        return False, "no valid fields to update"

    try:
        with open(ADMIN_COMMANDS_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return False, f"cannot read config: {e}"

    commands = data.get("commands", {})

    # Find the existing knock command entry
    old_name = None
    cmd_entry = None
    for name, cmd in commands.items():
        if cmd.get("action") == "knock":
            old_name = name
            cmd_entry = cmd
            break

    if cmd_entry is None:
        return False, "no knock command configured"

    new_name = filtered.get("knock_command", old_name)
    params = cmd_entry.get("params", {})

    if "knock_ports" in filtered:
        params["allowed_ports"] = filtered["knock_ports"]
    if "knock_timeout" in filtered:
        params["default_duration"] = filtered["knock_timeout"]
    cmd_entry["params"] = params

    # If command name changed, rename the key
    if new_name != old_name:
        del commands[old_name]
    commands[new_name] = cmd_entry
    data["commands"] = commands

    try:
        with open(ADMIN_COMMANDS_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        return False, f"cannot write config: {e}"

    return True, None


# --- Admin Path ---

def get_admin_path():
    """Read current admin path prefix from config."""
    try:
        with open(ADMIN_CONFIG_PATH) as f:
            cfg = json.load(f)
        return "/" + cfg.get("path_prefix", "/admin").strip("/")
    except (OSError, json.JSONDecodeError):
        return "/admin"


def update_admin_path(new_path):
    """Change admin panel URL path. Writes config, then root agent updates nginx.

    Returns (ok, error).
    """
    if not new_path:
        return False, "path is required"

    # Normalize
    new_path = "/" + new_path.strip("/")

    if not re.match(r'^/[a-z0-9][a-z0-9/-]{0,62}[a-z0-9]$', new_path):
        return False, "invalid path (lowercase letters, numbers, hyphens, slashes only)"

    if "//" in new_path:
        return False, "consecutive slashes not allowed"

    # Write admin.json (blockhost user owns this file)
    try:
        with open(ADMIN_CONFIG_PATH) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        cfg = {}

    cfg["path_prefix"] = new_path

    try:
        with open(ADMIN_CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except OSError as e:
        return False, f"cannot write admin config: {e}"

    # Root agent handles nginx update + scheduled admin restart
    from blockhost.root_agent import call, RootAgentError
    try:
        result = call("admin-path-update", path_prefix=new_path, timeout=15)
        if not result.get("ok"):
            return False, result.get("error", "path update failed")
        return True, None
    except RootAgentError as e:
        return False, str(e)


# --- Storage ---

def get_storage_info():
    devices = _run_json(["lsblk", "-J"])
    if devices:
        devices = devices.get("blockdevices", [])
    else:
        devices = []

    # Disk usage — root + separately mounted filesystems
    usage = []
    root_dev = None
    try:
        root_dev = os.stat("/").st_dev
        u = shutil.disk_usage("/")
        usage.append({"mount": "/", "total": u.total, "used": u.used, "free": u.free})
    except OSError:
        pass

    # Find other mount points on different devices (real separate mounts)
    boot_device = None
    mount_data = _run_json(["lsblk", "-J", "-o", "NAME,MOUNTPOINT,TYPE"])
    if mount_data:
        seen_devs = {root_dev} if root_dev else set()
        for dev in mount_data.get("blockdevices", []):
            if _find_root_mount(dev):
                boot_device = dev.get("name")
            for mp in _collect_mountpoints(dev):
                try:
                    dev_id = os.stat(mp).st_dev
                    if dev_id in seen_devs:
                        continue
                    seen_devs.add(dev_id)
                    u = shutil.disk_usage(mp)
                    usage.append({"mount": mp, "total": u.total, "used": u.used, "free": u.free})
                except OSError:
                    pass

    return {
        "devices": devices,
        "usage": usage,
        "boot_device": boot_device,
    }


def _collect_mountpoints(dev):
    """Recursively collect non-empty mount points from lsblk device tree."""
    mounts = []
    mp = dev.get("mountpoint")
    if mp:
        mounts.append(mp)
    for mp in (dev.get("mountpoints") or []):
        if mp:
            mounts.append(mp)
    for child in dev.get("children", []):
        mounts.extend(_collect_mountpoints(child))
    return mounts


def _find_root_mount(dev):
    """Recursively check if device or children mount at /."""
    if dev.get("mountpoint") == "/":
        return True
    for child in dev.get("children", []):
        if _find_root_mount(child):
            return True
    return False


# --- VMs ---

def get_vms():
    data = _run_json(["blockhost-vm-list", "--format", "json"], timeout=15)
    if data is None:
        return []
    return data


def vm_action(name, action):
    """Run a VM lifecycle action. action is one of: start, stop, kill, destroy.

    Returns (ok, error).
    """
    if not re.match(r'^[a-z0-9-]{1,64}$', name):
        return False, "invalid VM name"

    cmd_map = {
        "start": "blockhost-vm-start",
        "stop": "blockhost-vm-stop",
        "kill": "blockhost-vm-kill",
        "destroy": "blockhost-vm-destroy",
    }
    cmd = cmd_map.get(action)
    if not cmd:
        return False, f"unknown action: {action}"

    ok, out, err = _run([cmd, name], timeout=60)
    if not ok:
        return False, err or f"{action} failed"
    return True, None


# --- Wallet ---

def _get_bw_env():
    """Load RPC_URL and BLOCKHOST_CONTRACT from /opt/blockhost/.env."""
    env = dict(os.environ)
    try:
        with open(BW_ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    except OSError:
        pass
    return env


def _run_bw(args, timeout=30):
    """Run a bw command with proper env. Returns (ok, stdout, stderr)."""
    try:
        r = subprocess.run(
            ["bw"] + args,
            capture_output=True, text=True, timeout=timeout,
            env=_get_bw_env(),
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return False, "", "bw not found"
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s"


def get_wallet_info():
    """Read addressbook.json. Return list of {role, address, can_sign}."""
    try:
        with open(ADDRESSBOOK_PATH) as f:
            book = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    wallets = []
    for role, entry in book.items():
        wallets.append({
            "role": role,
            "address": entry.get("address", ""),
            "can_sign": "keyfile" in entry,
        })
    return wallets


def get_wallet_balances(role):
    """Run `bw balance <role>`. Returns (output, error)."""
    if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', role):
        return None, "invalid role"
    ok, out, err = _run_bw(["balance", role])
    if not ok:
        return None, err or "bw balance failed"
    return out, None


def wallet_send(amount, token, from_role, to):
    """Run `bw send <amount> <token> <from> <to>`. Returns (ok, output, error)."""
    if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', from_role):
        return False, "", "invalid from role"
    if not _valid_token(token):
        return False, "", "invalid token"
    if not _valid_destination(to):
        return False, "", "invalid destination"
    try:
        float(amount)
    except (ValueError, TypeError):
        return False, "", "invalid amount"

    ok, out, err = _run_bw(["send", str(amount), token, from_role, to], timeout=60)
    if not ok:
        return False, "", err or "send failed"
    return True, out, None


def wallet_withdraw(to, token=None):
    """Run `bw withdraw [token] <to>`. Returns (ok, output, error)."""
    if not _valid_destination(to):
        return False, "", "invalid destination"

    args = ["withdraw"]
    if token:
        if not _valid_token(token):
            return False, "", "invalid token"
        args.append(token)
    args.append(to)

    ok, out, err = _run_bw(args, timeout=60)
    if not ok:
        return False, "", err or "withdraw failed"
    return True, out, None


# --- Addressbook ---

def _run_ab(args, timeout=30):
    """Run an ab command with proper env. Returns (ok, stdout, stderr)."""
    try:
        r = subprocess.run(
            ["ab"] + args,
            capture_output=True, text=True, timeout=timeout,
            env=_get_bw_env(),
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return False, "", "ab not found"
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s"


def addressbook_add(name, address):
    """Run `ab add <name> <address>`. Returns (ok, output, error)."""
    if not re.match(r'^[a-zA-Z0-9]{1,20}$', name):
        return False, "", "invalid name"
    if not _valid_address(address):
        return False, "", "invalid address"
    ok, out, err = _run_ab(["add", name, address])
    if not ok:
        return False, "", err or "add failed"
    return True, out, None


def addressbook_remove(name):
    """Run `ab del <name>`. Returns (ok, output, error)."""
    if not re.match(r'^[a-zA-Z0-9]{1,20}$', name):
        return False, "", "invalid name"
    ok, out, err = _run_ab(["del", name])
    if not ok:
        return False, "", err or "delete failed"
    return True, out, None


def addressbook_generate(name):
    """Run `ab new <name>`. Returns (ok, output, error)."""
    if not re.match(r'^[a-zA-Z0-9]{1,20}$', name):
        return False, "", "invalid name"
    ok, out, err = _run_ab(["new", name])
    if not ok:
        return False, "", err or "generate failed"
    return True, out, None
