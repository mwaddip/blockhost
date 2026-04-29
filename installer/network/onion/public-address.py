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


def main() -> int:
    vm_name = os.environ.get("BH_VM_NAME") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not vm_name:
        print("public-address: vm_name required (env BH_VM_NAME or argv[1])", file=sys.stderr)
        return 2

    response = root_agent.call(
        "onion-service-add",
        vm_name=vm_name,
        port=22,
    )
    onion = response.get("hostname", "").strip()
    if not onion:
        print(f"public-address: no hostname returned for {vm_name}", file=sys.stderr)
        return 1

    print(onion)
    return 0


if __name__ == "__main__":
    sys.exit(main())
