Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
First, update your facts submodule: `cd facts && git pull origin main && cd ..`
Read `facts/COMMON_INTERFACE.md` §7 (`/etc/blockhost/network-mode`, Network Hook, Root Agent Tor Actions) before making changes.

---

# Common: Network Hook + Root Agent Tor Actions + Guest-Exec Dispatcher

## Observable problem
The framework currently has no network hook abstraction. Connectivity details (broker vs manual) are handled directly in the provisioner and engine handler. There's no generic `guest-exec` command resolution in the provisioner dispatcher.

## Target state
A `blockhost/network_hook.py` module providing network-mode-agnostic connection endpoint resolution. Two new root agent actions for tor hidden service lifecycle. `guest-exec` command resolution in the provisioner dispatcher.

## Deliverables

1. **New file: `usr/lib/python3/dist-packages/blockhost/network_hook.py`**

```python
"""Network-mode-agnostic connection endpoint resolution."""

import subprocess
import time
from pathlib import Path

TOR_DIR = Path("/var/lib/tor")


def get_connection_endpoint(vm_name: str, bridge_ip: str, mode: str) -> str:
    """Return the subscriber-facing host for a VM.

    broker/manual: pass-through the existing IP
    onion: create Tor hidden service, push .onion into VM, return .onion
    """
    if mode == "onion":
        return _setup_onion(vm_name, bridge_ip)
    return bridge_ip


def cleanup(vm_name: str, mode: str) -> None:
    """Remove network resources on VM destroy."""
    if mode == "onion":
        _teardown_onion(vm_name)


def _setup_onion(vm_name: str, bridge_ip: str) -> str:
    result = subprocess.run(
        ["blockhost-root-agent", "tor-hidden-service-add",
         "--vm-name", vm_name, "--bridge-ip", bridge_ip, "--port", "22"],
        capture_output=True, text=True, check=True,
    )
    onion = result.stdout.strip()

    # Push .onion into VM — update /etc/hosts and signing_host file
    subprocess.run(
        ["blockhost-vm-guest-exec", vm_name,
         f"sed -i '/^{bridge_ip} /d' /etc/hosts && echo '{bridge_ip} {onion} {vm_name}' >> /etc/hosts"],
        check=True,
    )
    subprocess.run(
        ["blockhost-vm-guest-exec", vm_name,
         f"echo '{onion}' > /run/libpam-web3/signing_host"],
        check=True,
    )
    subprocess.run(
        ["blockhost-vm-guest-exec", vm_name,
         f"sed -i 's|signing_url = .*|signing_url = \"http://{onion}:8443\"|' /etc/pam_web3/config.toml"],
        check=True,
    )
    return onion


def _teardown_onion(vm_name: str) -> None:
    subprocess.run(
        ["blockhost-root-agent", "tor-hidden-service-remove",
         "--vm-name", vm_name],
        check=True,
    )
```

2. **Modify: `usr/lib/python3/dist-packages/blockhost/__init__.py`**

Export `get_connection_endpoint` and `cleanup` from `network_hook`.

3. **Modify: `usr/share/blockhost/root-agent-actions/system.py`**

Add two actions to the ACTIONS dict:

```python
# tor-hidden-service-add
def _tor_hidden_service_add(params):
    import time
    vm_name = params["vm_name"]
    bridge_ip = params["bridge_ip"]
    port = params.get("port", 22)

    tor_dir = Path(f"/var/lib/tor/blockhost-{vm_name}")
    tor_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["chown", "-R", "debian-tor:debian-tor", str(tor_dir)], check=True)

    with open("/etc/tor/torrc", "a") as f:
        f.write(f"\nHiddenServiceDir /var/lib/tor/blockhost-{vm_name}/\n")
        f.write(f"HiddenServicePort {port} {bridge_ip}:{port}\n")

    subprocess.run(["systemctl", "reload", "tor"], check=True)
    time.sleep(1)  # Tor generates the hostname file
    return (tor_dir / "hostname").read_text().strip()


# tor-hidden-service-remove
def _tor_hidden_service_remove(params):
    import shutil
    vm_name = params["vm_name"]

    with open("/etc/tor/torrc") as f:
        lines = f.readlines()

    marker = f"/var/lib/tor/blockhost-{vm_name}/"
    lines = [l for l in lines if marker not in l]

    with open("/etc/tor/torrc", "w") as f:
        f.writelines(lines)

    subprocess.run(["systemctl", "reload", "tor"], check=True)
    shutil.rmtree(f"/var/lib/tor/blockhost-{vm_name}", ignore_errors=True)
    return "removed"
```

Register both in ACTIONS with the action names `tor-hidden-service-add` and `tor-hidden-service-remove`.

4. **Modify: `usr/lib/python3/dist-packages/blockhost/provisioner.py`**

Ensure `get_command("guest-exec")` resolves from the manifest's `commands.guest-exec`.

## Verification
- `python3 -c "from blockhost.network_hook import get_connection_endpoint, cleanup"`
- `grep tor-hidden-service-add /usr/share/blockhost/root-agent-actions/system.py`
- Provisioner dispatcher resolves `guest-exec` command
