Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/PROVISIONER_INTERFACE.md` §2 (the `guest-exec` section) before making changes.

---

# Provisioner-Proxmox: guest-exec CLI

## Observable problem
The provisioner currently has no generic way to run commands inside running VMs. The network hook and engine need `guest-exec` for pushing `.onion` addresses, updating signing URLs, and updating GECOS fields.

## Target state
A generic `blockhost-vm-guest-exec <name> <command...>` CLI that runs a shell command inside a running VM via `qm guest exec`.

## Implementation

Proxmox has a native `qm guest exec` command:
```
qm guest exec <vmid> -- <command...>
```

Map the VM name to VMID via the VM database, then delegate to `qm guest exec`. Exit with the command's exit code. Print stdout to stdout, stderr to stderr.

## Deliverables

1. **New file: `scripts/guest-exec.py`** — implements the command (resolves name → VMID, calls `qm guest exec <vmid> -- <args>`)
2. **Symlink/script**: `blockhost-vm-guest-exec` → `guest-exec.py` in the .deb's bin dir
3. **Modify: `provisioner.json`** — add `"guest-exec": "blockhost-vm-guest-exec"` to `commands`
4. **Modify: `scripts/update-gecos.py`** (if it exists) — refactor to delegate to `guest-exec`
5. **Add to `.deb` packaging**: ensure `guest-exec.py` is included and symlinked

## Verification
- `blockhost-vm-guest-exec testvm "echo hello"` returns "hello"
- `blockhost-vm-guest-exec testvm "cat /etc/hostname"` returns the VM's hostname
- `blockhost-vm-update-gecos` still works if it exists and was refactored
