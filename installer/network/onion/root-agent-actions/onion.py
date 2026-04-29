"""Root-agent actions for the onion network plugin.

Discovered by the root agent at /usr/share/blockhost/root-agent-actions/onion.py.
Plugin-owned per `facts/COMMON_INTERFACE.md §7 Network plugins`.

Actions:
  - onion-service-add:    create/lookup the per-VM hidden service, return its hostname
  - onion-service-remove: tear down the per-VM hidden service
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

TOR_DATA_DIR = Path("/var/lib/tor")
TORRC = Path("/etc/tor/torrc")
HOSTNAME_TIMEOUT_S = 30


def _service_dir(vm_name: str) -> Path:
    return TOR_DATA_DIR / f"blockhost-{vm_name}"


def _block_marker(vm_name: str) -> str:
    return f"# BlockHost — VM hidden service: {vm_name}"


def _reload_tor() -> None:
    subprocess.run(
        ["systemctl", "reload-or-restart", "tor@default"],
        capture_output=True, check=False,
    )


def _wait_hostname(svc_dir: Path) -> str | None:
    deadline = time.time() + HOSTNAME_TIMEOUT_S
    hostname_file = svc_dir / "hostname"
    while time.time() < deadline:
        if hostname_file.exists():
            return hostname_file.read_text().strip()
        time.sleep(0.5)
    return None


def _add(params: dict) -> dict:
    vm_name = params.get("vm_name", "")
    port = int(params.get("port", 22))
    if not vm_name:
        return {"ok": False, "error": "vm_name required"}

    svc_dir = _service_dir(vm_name)
    svc_dir.mkdir(parents=True, exist_ok=True)
    svc_dir.chmod(0o700)
    shutil.chown(svc_dir, "debian-tor", "debian-tor")

    if not TORRC.exists():
        return {"ok": False, "error": f"{TORRC} missing — tor not installed?"}

    existing = TORRC.read_text()
    marker = _block_marker(vm_name)
    if f"HiddenServiceDir {svc_dir}" not in existing:
        with TORRC.open("a") as f:
            f.write(
                f"\n{marker}\n"
                f"HiddenServiceDir {svc_dir}\n"
                f"HiddenServicePort {port} 127.0.0.1:{port}\n"
            )
        _reload_tor()

    onion = _wait_hostname(svc_dir)
    if not onion:
        return {"ok": False, "error": f"tor did not publish hostname for {vm_name}"}
    return {"ok": True, "hostname": onion}


def _remove(params: dict) -> dict:
    vm_name = params.get("vm_name", "")
    if not vm_name:
        return {"ok": False, "error": "vm_name required"}

    svc_dir = _service_dir(vm_name)
    marker = _block_marker(vm_name)

    if TORRC.exists():
        # Strip the marker line and the two directives that follow it.
        lines = TORRC.read_text().splitlines(keepends=True)
        kept: list[str] = []
        skip = 0
        for line in lines:
            if skip > 0:
                skip -= 1
                continue
            if line.rstrip("\n") == marker:
                skip = 2
                continue
            kept.append(line)
        TORRC.write_text("".join(kept))
        _reload_tor()

    if svc_dir.exists():
        shutil.rmtree(svc_dir, ignore_errors=True)

    return {"ok": True}


# Root-agent action registration: maps action name (hyphenated, as used by
# clients) to the handler callable. The root-agent loader picks this up.
ACTIONS = {
    "onion-service-add": _add,
    "onion-service-remove": _remove,
}
