#!/usr/bin/env python3
"""Onion plugin — cleanup command.

Invoked as: cleanup.py <vm_name>

Removes the per-VM hidden service (host-side via root agent) and reverses
the VM-side config push (best-effort guest-exec; VM may already be gone).
"""
import os
import subprocess
import sys

from blockhost import root_agent
from blockhost.provisioner import get_provisioner


def main() -> int:
    vm_name = os.environ.get("BH_VM_NAME") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not vm_name:
        print("cleanup: vm_name required", file=sys.stderr)
        return 2

    # 1. Reverse VM-side config (best-effort — VM may be destroyed already).
    guest_exec_cmd = None
    try:
        guest_exec_cmd = get_provisioner().get_command("guest-exec")
    except Exception:
        pass

    if guest_exec_cmd:
        # Drop /etc/hosts entry, signing_host file, and use_tls override.
        for shell in (
            f"sed -i '/ {vm_name}$/d' /etc/hosts || true",
            "rm -f /run/libpam-web3/signing_host || true",
            "sed -i 's|signing_url = .*|signing_url = \"\"|' /etc/pam_web3/config.toml || true",
            "sed -i '/^use_tls = false$/d' /etc/pam_web3/config.toml || true",
        ):
            subprocess.run(
                [guest_exec_cmd, vm_name, shell],
                capture_output=True, text=True,
            )

    # 2. Host-side teardown (always attempted).
    try:
        root_agent.call("onion-service-remove", vm_name=vm_name)
    except Exception as e:
        print(f"cleanup: host teardown failed for {vm_name}: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
