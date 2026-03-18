# Building a Provisioner

A provisioner manages VM lifecycle on a specific hypervisor. It handles creation, destruction, starting, stopping, template building, metrics collection, and resource throttling. The engine and installer interact with it through CLI commands resolved from the manifest.

## What you need to implement

### 1. Provisioner manifest (`provisioner.json`)

Installed to `/usr/share/blockhost/provisioner.json`.

```json
{
  "name": "mybackend",
  "version": "0.2.0",
  "display_name": "My Hypervisor",
  "accent_color": "#336699",
  "commands": {
    "create": "blockhost-vm-create",
    "destroy": "blockhost-vm-destroy",
    "start": "blockhost-vm-start",
    "stop": "blockhost-vm-stop",
    "kill": "blockhost-vm-kill",
    "status": "blockhost-vm-status",
    "list": "blockhost-vm-list",
    "metrics": "blockhost-vm-metrics",
    "throttle": "blockhost-vm-throttle",
    "build-template": "blockhost-build-template",
    "gc": "blockhost-vm-gc",
    "resume": "blockhost-vm-resume",
    "update-gecos": "blockhost-vm-update-gecos"
  },
  "setup": { ... },
  "root_agent_actions": "/usr/share/blockhost/root-agent-actions/mybackend.py",
  "config_keys": { ... }
}
```

### 2. VM lifecycle CLIs

Every command receives the VM name as the primary identifier. Exit 0 = success, non-zero = failure. Structured output (JSON) on stdout where specified, progress/errors on stderr.

| Command | Key requirements |
|---------|-----------------|
| `create` | Create VM with cloud-init, GECOS config. Return JSON with ip, ipv6, vmid, username. |
| `destroy` | Must be idempotent — destroying a non-existent VM is not an error. |
| `metrics` | Return JSON with CPU, memory, disk, network stats. Must be cheap — called frequently. |
| `throttle` | Apply CPU/bandwidth/IOPS limits. Additive options. `--reset` to remove all limits. |
| `build-template` | Create base VM image with libpam-web3 and auth-svc pre-installed. |

### 3. Wizard plugin

Same pattern as engines — Flask blueprint with finalization steps.

### 4. Root agent actions

A Python module loaded by the root agent daemon for privileged operations (VM start/stop if needed, network config, etc.).

### 5. Metrics and throttle

These are critical for the host monitor. The metrics command must:
- Return all fields from the contract schema (use -1 for unavailable fields)
- Never block waiting for the guest agent
- Be fast enough to call for every VM every 10-30 seconds

The throttle command must:
- Support CPU shares/quota, bandwidth in/out, IOPS read/write
- Apply limits to running VMs without restart
- Support `--reset` to restore defaults

## Reference implementations

- **libvirt**: [`blockhost-provisioner-libvirt`](https://github.com/mwaddip/blockhost-provisioner-libvirt) — virsh, qcow2 overlays, cloud-localds
- **Proxmox**: [`blockhost-provisioner-proxmox`](https://github.com/mwaddip/blockhost-provisioner-proxmox) — Proxmox API, Terraform, PVE templates

The libvirt provisioner is the cleaner reference — it's more direct, with fewer abstraction layers between the code and the hypervisor.

## Contract reference

Read [`facts/PROVISIONER_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/PROVISIONER_INTERFACE.md) for the full specification covering all CLI commands, wizard exports, root agent actions, and .deb packaging.
