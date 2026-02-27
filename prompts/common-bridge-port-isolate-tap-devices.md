# Common: Allow tap devices in bridge-port-isolate

## Context

`/usr/share/blockhost/root-agent-actions/_common.py` defines `ALLOWED_ROUTE_DEVS` used by `validate_dev()`. The `bridge-port-isolate` action calls `validate_dev()` to check the device name, but `tap` devices (e.g. `tap100i0`) are not in the allowed set.

When a VM is created, the provisioner calls `bridge-port-isolate` with the VM's tap interface. This fails:
```
ValueError: Device not allowed: tap100i0
```

## Current allowed devices

```python
ALLOWED_ROUTE_DEVS = frozenset({'vmbr0', 'virbr0', 'br0', 'br-ext', 'docker0'})
```

## Fix

`validate_dev()` needs to also accept tap devices. Tap device names follow the pattern `tap<vmid>i<interface>` (e.g. `tap100i0`, `tap101i0`). Rather than adding every possible tap name to the frozenset, add a pattern check:

```python
import re

TAP_DEV_RE = re.compile(r'^tap\d+i\d+$')

def validate_dev(dev):
    if dev not in ALLOWED_ROUTE_DEVS and not TAP_DEV_RE.match(dev):
        raise ValueError(f'Device not allowed: {dev}')
    return dev
```

This allows bridge/vmbr devices (static set) and tap devices (pattern match) while still rejecting arbitrary device names.
