Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
First, update your facts submodule: `cd facts && git pull origin main && cd ..`
Read `facts/ENGINE_INTERFACE.md` §13 (Network Hook Integration) before making changes.

---

# Engine-OPNet: Network Hook Integration

## Observable problem
The engine handler currently reads IPv6 from the provisioner's `create` result and uses it directly for connection details. There's no network-mode awareness — the engine assumes broker/manual IPv6.

## Target state
After `provisioner.create()`, call `network_hook.get_connection_endpoint()` to get the subscriber-facing host. Use `guest-exec` instead of `update-gecos` for GECOS updates. The engine is network-mode-agnostic.

## Changes needed

### 1. Read network mode
At handler startup, read `/etc/blockhost/network-mode`. If absent, default to `broker`.

### 2. VM creation flow
After `provisioner.create()` returns, call:
```python
host = subprocess.run(
    ["python3", "-c",
     f"from blockhost.network_hook import get_connection_endpoint; print(get_connection_endpoint('{vm_name}', '{bridge_ip}', '{network_mode}'))"],
    capture_output=True, text=True, check=True
).stdout.strip()
```

### 3. GECOS update
Replace `update-gecos` with `guest-exec`.

### 4. VM destroy flow
Call `network_hook.cleanup(vm_name, network_mode)` after `provisioner.destroy()`.

## Deliverables
1. Modify: VM creation handler — add network hook call after create
2. Modify: VM destroy handler — add cleanup call after destroy
3. Modify: GECOS update — use `guest-exec`
4. Modify: connection details — use host from network hook

## Verification
- Broker mode still works (no regression)
