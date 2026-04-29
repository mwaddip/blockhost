#!/usr/bin/env python3
"""Onion plugin — push-vm-config command.

Invoked as: push-vm-config.py <vm_name>

In onion mode the customer VM needs three things pushed:
  - Its own .onion mapped in /etc/hosts so anything in-VM that looks up
    the VM's public name resolves to its bridge IP.
  - Its own .onion written to /etc/blockhost/host-address. libpam-web3's
    auth-svc runs inside this VM at port 63108 (chain-derived); customers
    reach it via this VM's own hidden service (not the host's). The
    libpam resolve-signing-host.sh reads this file as override before its
    FQDN/sslip.io fallback chain.
  - use_tls = false in /etc/pam_web3/config.toml so libpam's PAM prompt
    uses http:// (Tor handles transport encryption end-to-end). The
    auth-svc binary now honors this flag and binds plain HTTP when set.

After writing host-address, restart libpam-web3-signing-host so its
resolver re-runs and picks up the override (writes signing_host +
regenerates the SAN cert).

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

    # Per-VM .onion (the customer's outward address).
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
    vm_onion = addr_result.stdout.strip()

    guest_exec_cmd = get_provisioner().get_command("guest-exec")
    ok = True

    # /etc/hosts: VM's own .onion → bridge IP. Idempotent (sed strips prior).
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        f"sed -i '/^{bridge_ip} /d' /etc/hosts && "
        f"echo '{bridge_ip} {vm_onion} {vm_name}' >> /etc/hosts",
    )

    # /etc/blockhost/host-address: this VM's own .onion. Read by libpam-web3's
    # resolve-signing-host.sh as override before its fallback chain. The
    # in-VM auth-svc runs on this VM's port 63108 (chain-derived), so the
    # signing URL must reach this VM — not the BlockHost host.
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        f"mkdir -p /etc/blockhost && echo '{vm_onion}' > /etc/blockhost/host-address",
    )

    # use_tls = false — Tor handles transport encryption; auth-svc honors
    # this flag (binds plain HTTP) starting in libpam-web3 ace42d2.
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        "if grep -q '^use_tls' /etc/pam_web3/config.toml; then "
        "sed -i 's/^use_tls = .*/use_tls = false/' /etc/pam_web3/config.toml; "
        "else sed -i '/^\\[auth\\]/a use_tls = false' /etc/pam_web3/config.toml; fi",
    )

    # Restart libpam-web3-signing-host so its resolver re-runs and picks up
    # the override, then restart auth-svc so it reads the new use_tls value.
    ok &= guest_exec(
        guest_exec_cmd, vm_name,
        "systemctl unmask libpam-web3-signing-host 2>/dev/null || true; "
        "systemctl restart libpam-web3-signing-host && "
        "systemctl restart 'web3-auth-svc-*.service'",
    )

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
