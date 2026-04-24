Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/ENGINE_INTERFACE.md` §13 (Network Hook Integration) before making changes.

---

# Engine-EVM: Network Hook Integration

## Observable problem
The engine handler currently reads IPv6 from the provisioner's `create` result and uses it directly for connection details. It also calls the domain-specific `update-gecos` provisioner command. There's no network-mode awareness — the engine assumes broker/manual IPv6.

## Target state
After `provisioner.create()`, call `network_hook.get_connection_endpoint()` to get the subscriber-facing host. Use `guest-exec` instead of `update-gecos` for GECOS updates. The engine is network-mode-agnostic — it receives an opaque host string.

## Changes needed

### 1. Read network mode

At handler startup, read `/etc/blockhost/network-mode`. If absent, default to `broker`.

### 2. VM creation flow

After `provisioner.create()` returns, call the network hook:

```python
host = subprocess.run(
    ["python3", "-c",
     f"from blockhost.network_hook import get_connection_endpoint; print(get_connection_endpoint('{vm_name}', '{bridge_ip}', '{network_mode}'))"],
    capture_output=True, text=True, check=True
).stdout.strip()
```

Where `bridge_ip` is `result.ip` from the provisioner's create output.

### 3. GECOS update

Replace `blockhost-vm-update-gecos <name> <wallet> --nft-id <id>` with:

```
blockhost-vm-guest-exec <name> "sed -i GECOS update command"
```

Or keep the `update-gecos` CLI if it's already refactored to delegate to `guest-exec`.

### 4. VM destroy flow

After `provisioner.destroy()`, call:

```python
subprocess.run(
    ["python3", "-c",
     f"from blockhost.network_hook import cleanup; cleanup('{vm_name}', '{network_mode}')"],
    check=True
)
```

## Deliverables

1. Modify: VM creation handler — add `get_connection_endpoint` call after `provisioner.create()`
2. Modify: VM destroy handler — add `network_hook.cleanup()` after `provisioner.destroy()`
3. Modify: GECOS update — use `guest-exec` (or keep `update-gecos` if already refactored)
4. Modify: connection details encryption — use the `host` from network hook instead of `result.ipv6`

## Verification
- Broker mode: connection details still contain IPv6 address (no regression)
- The network hook subprocess call succeeds (test with mock or on a live system)
