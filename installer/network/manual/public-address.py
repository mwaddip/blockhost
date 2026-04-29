#!/usr/bin/env python3
"""Manual plugin — public-address command.

Same shape as broker: vm-db.ipv6_address, allocated from the operator-configured
prefix at vm-create time.
"""
import os
import sys

from blockhost.vm_db import get_database


def main() -> int:
    vm_name = os.environ.get("BH_VM_NAME") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not vm_name:
        print("public-address: vm_name required", file=sys.stderr)
        return 2

    vm = get_database().get_vm(vm_name)
    if not vm:
        print(f"public-address: vm {vm_name} not in vm-db", file=sys.stderr)
        return 1

    ipv6 = vm.get("ipv6_address", "").strip()
    if not ipv6:
        print(f"public-address: vm {vm_name} has no ipv6_address", file=sys.stderr)
        return 1

    print(ipv6)
    return 0


if __name__ == "__main__":
    sys.exit(main())
