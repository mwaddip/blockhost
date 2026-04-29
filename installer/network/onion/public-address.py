#!/usr/bin/env python3
"""Onion plugin — public-address command.

Invoked as: public-address.py <vm_name>      (also reads BH_VM_NAME)

Returns the per-VM .onion hostname on stdout. Idempotent: creating the
hidden service is delegated to the root agent (action `onion-service-add`),
which is itself idempotent.
"""
import os
import sys

from blockhost import root_agent
from blockhost.vm_db import get_database


def main() -> int:
    vm_name = os.environ.get("BH_VM_NAME") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not vm_name:
        print("public-address: vm_name required (env BH_VM_NAME or argv[1])", file=sys.stderr)
        return 2

    # The hidden service forwards to the VM's bridge IP — not localhost. The
    # host hidden service (signup page) is set up by the plugin's finalize.d
    # and uses 127.0.0.1; this path is per-VM only.
    vm = get_database().get_vm(vm_name)
    if not vm:
        print(f"public-address: vm {vm_name} not in vm-db", file=sys.stderr)
        return 1
    target_ip = vm.get("ip_address", "").strip()
    if not target_ip:
        print(f"public-address: vm {vm_name} has no ip_address", file=sys.stderr)
        return 1

    response = root_agent.call(
        "onion-service-add",
        vm_name=vm_name,
        port=22,
        target_ip=target_ip,
    )
    onion = response.get("hostname", "").strip()
    if not onion:
        print(f"public-address: no hostname returned for {vm_name}", file=sys.stderr)
        return 1

    print(onion)
    return 0


if __name__ == "__main__":
    sys.exit(main())
