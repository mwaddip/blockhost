Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/PROVISIONER_INTERFACE.md` §2 (the `guest-exec` section) before making changes.

---

# Provisioner-Libvirt: guest-exec CLI

## Observable problem
The provisioner has a domain-specific `update-gecos` command that knows about `/etc/passwd` format. The network hook and engine need a generic way to run commands inside VMs (update `/etc/hosts`, update signing URL, update GECOS).

## Target state
A generic `blockhost-vm-guest-exec <name> <command...>` CLI that runs a shell command inside a running VM. The existing `update-gecos` is refactored to delegate to `guest-exec`.

## Implementation

Use qemu-guest-agent primitives:
- `guest-exec` with `path: "/bin/sh"`, `arg: ["-c", "<command>"]`
- Poll `guest-exec-status` for exit code and output
- Exit with the command's exit code. Print stdout to stdout, stderr to stderr.

Note: large commands (>4096 bytes) may need chunking via `guest-file-open`/`guest-file-write`/`guest-file-close` + `guest-exec` on the temp file. For typical use cases (sed, echo), direct `guest-exec` with `-c` is sufficient.

## Deliverables

1. **New file: `scripts/guest-exec.py`** — implements the command
2. **Symlink/script**: `blockhost-vm-guest-exec` → `guest-exec.py` in the .deb's bin dir
3. **Modify: `provisioner.json`** — add `"guest-exec": "blockhost-vm-guest-exec"` to `commands`
4. **Modify: `scripts/update-gecos.py`** — refactor to call `blockhost-vm-guest-exec <name> "sed -i ... /etc/passwd"` instead of direct guest-agent calls. Keep the GECOS string construction logic; only the execution path changes.
5. **Add to `.deb` packaging**: ensure `guest-exec.py` is included and symlinked

## Verification
- `blockhost-vm-guest-exec testvm "echo hello"` returns "hello"
- `blockhost-vm-guest-exec testvm "cat /etc/hostname"` returns the VM's hostname
- `blockhost-vm-update-gecos testvm addr1test... --nft-id 42` still works
