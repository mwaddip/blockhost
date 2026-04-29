#!/usr/bin/env python3
"""Onion plugin — push-vm-config command.

Invoked as: push-vm-config.py <vm_name>

Pushes onion-mode VM-side config via the provisioner's `guest-exec` CLI:
  - /run/libpam-web3/signing_host = <onion>
  - /etc/pam_web3/config.toml: signing_url = http://<onion>:8443, use_tls = false
  - /etc/hosts: bridge-ip <onion> <vm_name>

Idempotent. Returns:
  0 — config now correct
  1 — at least one push failed; caller (engine reconciler) retries
"""
import os
import subprocess
import sys

from blockhost.provisioner import get_provisioner
from blockhost.vm_db import get_database


def guest_exec(provisioner_command: str, vm_name: str, shell: str) -> bool:
    result = subprocess.run(
        [provisioner_command, vm_name, shell],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(
            f"push-vm-config: guest-exec failed (vm={vm_name}, exit={result.returncode}): "
            f"{result.stderr.strip()}",
            file=sys.stderr,
        )
        return False
    return True


def main() -> int:
    vm_name = os.environ.get("BH_VM_NAME") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not vm_name:
        print("push-vm-config: vm_name required", file=sys.stderr)
        return 2

    vm = get_database().get_vm(vm_name)
    if not vm:
        print(f"push-vm-config: vm {vm_name} not in vm-db", file=sys.stderr)
        return 1

    bridge_ip = vm.get("ip_address", "")
    if not bridge_ip:
        print(f"push-vm-config: no ip_address for {vm_name}", file=sys.stderr)
        return 1

    # Resolve the onion hostname (idempotent — same root agent action as
    # public-address). Could also read directly from /var/lib/tor but that
    # requires root and the dispatcher path is already idempotent.
    addr_result = subprocess.run(
        ["blockhost-network-hook", "public-address", vm_name],
        capture_output=True, text=True,
    )
    if addr_result.returncode != 0:
        print(
            f"push-vm-config: public-address lookup failed: {addr_result.stderr.strip()}",
            file=sys.stderr,
        )
        return 1
    onion = addr_result.stdout.strip()

    guest_exec_cmd = get_provisioner().get_command("guest-exec")
    ok = True

    # /etc/hosts
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        f"sed -i '/^{bridge_ip} /d' /etc/hosts && "
        f"echo '{bridge_ip} {onion} {vm_name}' >> /etc/hosts",
    )
    # signing_host
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        f"mkdir -p /run/libpam-web3 && echo '{onion}' > /run/libpam-web3/signing_host",
    )
    # signing_url
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        f'sed -i \'s|signing_url = .*|signing_url = "http://{onion}:8443"|\' '
        f"/etc/pam_web3/config.toml",
    )
    # use_tls = false (Tor handles transport encryption)
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        "if grep -q '^use_tls' /etc/pam_web3/config.toml; then "
        "sed -i 's/^use_tls = .*/use_tls = false/' /etc/pam_web3/config.toml; "
        "else sed -i '/^\\[auth\\]/a use_tls = false' /etc/pam_web3/config.toml; fi",
    )

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
