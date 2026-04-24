# Onion Routing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add host-level Tor onion routing as a third network mode in the wizard.

**Architecture:** Network mode choice (broker/manual/onion) on the wizard connectivity page. Choosing onion skips broker registration, IPv6 allocation, and Let's Encrypt. The host runs a single Tor daemon. Each VM gets a hidden service via a network hook between the engine handler and the root agent. Provisioners and engines stay agnostic.

**Tech Stack:** Python (Flask wizard, finalize.py), Bash (first-boot), HTML (wizard templates), Tor daemon

**Spec:** `docs/superpowers/specs/2026-04-24-onion-routing-design.md`

---

## File Map

### Main session (this repo)
| File | Action | Purpose |
|------|--------|---------|
| `facts/PROVISIONER_INTERFACE.md` | Modify | Add `guest-exec` to manifest commands |
| `facts/COMMON_INTERFACE.md` | Modify | Document network_hook, tor root agent actions |
| `facts/ENGINE_INTERFACE.md` | Modify | Document network_hook call in handler flow |
| `installer/web/templates/wizard/connectivity.html` | Modify | Add Onion radio option |
| `installer/web/app.py` | Modify | Handle onion in session, skip mutual exclusion |
| `installer/web/finalize.py` | Modify | Skip ipv6/https finalization for onion |
| `scripts/first-boot.sh` | Modify | Install tor, generate host hidden service |

### Submodule repos (dispatched as prompts)
| Repo | Changes |
|------|---------|
| `blockhost-common` | `network_hook.py`, root agent tor actions, `guest-exec` in dispatcher |
| `blockhost-provisioner-libvirt` | `guest-exec` CLI, refactor `update-gecos` |
| `blockhost-provisioner-proxmox` | `guest-exec` CLI |
| `blockhost-engine-evm` | Call `network_hook` in handler, use `guest-exec` |
| `blockhost-engine-opnet` | Same |
| `blockhost-engine-cardano` | Same |
| `blockhost-engine-ergo` | Same |

---

## Part A: Main Session

### Task 1: Update Facts Contracts

**Files:**
- Modify: `facts/PROVISIONER_INTERFACE.md`
- Modify: `facts/COMMON_INTERFACE.md`
- Modify: `facts/ENGINE_INTERFACE.md`

- [ ] **Step 1: Add `guest-exec` to provisioner manifest commands**

In `facts/PROVISIONER_INTERFACE.md`, add `"guest-exec"` to the manifest commands schema example (section 1), and add a new subsection after `update-gecos` in section 2:

```markdown
### `guest-exec`

Executes a command inside a running VM. Used by the network hook to push configuration
changes after VM creation (signing URL updates, /etc/hosts entries).

```
blockhost-vm-guest-exec <name> <command...>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `name` | yes | VM name |
| `command...` | yes | Shell command to execute inside the VM |

**stdout:** Command output.
**Exit:** 0 on success, 1 on failure.

**Implementation:**
- libvirt: `virsh qemu-agent-command <domain> '{"execute":"guest-exec", "arguments":{"path":"/bin/sh", "arg":["-c","<command>"]}}'` + poll `guest-exec-status`
- Proxmox: `qm guest exec <vmid> -- <command...>`

**Note:** The existing `update-gecos` command should be refactored to use `guest-exec` internally:
`blockhost-vm-guest-exec <name> "sed -i 's/^\([^:]*:[^:]*:[^:]*:[^:]*:\)[^:]*/\1wallet=<addr>,nft=<id>/' /etc/passwd"`
```

- [ ] **Step 2: Update provisioner manifest command list**

In the manifest schema example in `facts/PROVISIONER_INTERFACE.md` §1, add `"guest-exec": "<executable-name>"` to the `commands` object.

- [ ] **Step 3: Document network_hook and tor actions in COMMON_INTERFACE.md**

In `facts/COMMON_INTERFACE.md`, add a new section 8 after section 7 (Config File Schemas):

```markdown
## 8. Network Hook

Module: `blockhost.network_hook`

Provides network-mode-agnostic connection endpoint resolution. The engine handler
calls this after `provisioner.create()` to get the endpoint subscribers use.

```python
get_connection_endpoint(vm_name: str, bridge_ip: str, mode: str) -> str
```

| Mode | Behavior | Returns |
|------|----------|---------|
| `broker` | Pass-through (IPv6 from broker-allocation.json) | IPv6 address string |
| `manual` | Pass-through (static IP from config) | Static IP string |
| `onion` | Calls root agent `tor-hidden-service-add`, pushes `.onion` into VM via `guest-exec`, updates signing URL | `.onion` address |

```python
cleanup(vm_name: str, mode: str) -> None
```

Removes network resources on VM destroy. Onion mode calls root agent `tor-hidden-service-remove`.

### Root Agent — Tor Actions

The root agent gains two actions for tor hidden service management:

**`tor-hidden-service-add`:** Creates `/var/lib/tor/blockhost-{name}/`, appends
`HiddenServiceDir` and `HiddenServicePort` to `/etc/tor/torrc`, reloads tor,
returns the `.onion` from the `hostname` file.

**`tor-hidden-service-remove`:** Removes torrc entries, reloads tor, deletes the
hidden service directory.
```

- [ ] **Step 4: Document network_hook call in ENGINE_INTERFACE.md**

In `facts/ENGINE_INTERFACE.md`, after the VM creation flow section, add:

```markdown
### Network Hook Integration

After `provisioner.create()` returns, the engine handler calls
`network_hook.get_connection_endpoint(vm_name, bridge_ip, mode)` to resolve
the subscriber-facing connection endpoint. The network mode is read from
`/etc/blockhost/network-mode` (written by the wizard during finalization).

For destroy, call `network_hook.cleanup(vm_name, mode)` after
`provisioner.destroy()`.
```

- [ ] **Step 5: Commit facts updates**

```bash
cd facts && git add -A && git commit -m "facts: add guest-exec, network_hook, tor root agent actions" && cd ..
git add facts && git commit -m "facts: bump pointer — guest-exec, network_hook, tor actions"
```

---

### Task 2: Add Onion Option to Wizard Template

**Files:**
- Modify: `installer/web/templates/wizard/connectivity.html`

- [ ] **Step 1: Update page subtitle**

Change the subtitle from IPv6-specific to network-mode-generic (line 12):

```html
<p class="text-muted mb-2">Choose how your VMs are reachable and how subscribers connect.</p>
```

- [ ] **Step 2: Add onion radio option before the broker block**

Insert after the Manual section's closing `</div>` (after line 48) and before the broker block (line 50):

```html
        <!-- Onion Option (always available, no package required) -->
        <label class="checkbox-group" id="label-onion" onclick="toggleOption(this, 'onion')">
            <input type="checkbox" name="connectivity_options" value="onion" id="opt-onion">
            <div class="checkbox-label">
                <h4>Onion Routing (Tor)</h4>
                <p>Host reachable only via .onion addresses — no public IP needed</p>
            </div>
        </label>

        <div id="section-onion" class="form-section hidden" style="margin-top: 0.5rem; margin-bottom: 1.5rem;">
            <h3>Onion Routing</h3>
            <p class="text-muted mb-2" style="font-size: 0.875rem;">
                The host runs a Tor daemon. Each VM gets its own <code>.onion</code> hidden service.
                Subscribers connect via Tor: <code>torsocks ssh user@xxx.onion</code>.
            </p>
            <div class="alert alert-info">
                <strong>No broker, no IPv6, no TLS.</strong> Tor provides end-to-end encryption.
                Subscribers will need Tor installed locally.
            </div>
        </div>
```

- [ ] **Step 3: Update exclusion map in JavaScript**

Change the `EXCLUSIONS` declaration (around line 110) to include onion:

```javascript
const EXCLUSIONS = {{ exclusion_map | safe }};
```

And update the backend to include onion in the exclusion map (see Task 3 step 2).

- [ ] **Step 4: Commit**

```bash
git add installer/web/templates/wizard/connectivity.html
git commit -m "wizard: add onion routing option to connectivity page"
```

---

### Task 3: Handle Onion in Wizard Backend

**Files:**
- Modify: `installer/web/app.py`

- [ ] **Step 1: Add onion handling in `wizard_connectivity()` POST handler**

In the POST branch of `wizard_connectivity()` (after the manual block around line 824, before the broker block at line 826), add:

```python
            if 'onion' in selected:
                connectivity['onion'] = {}
```

- [ ] **Step 2: Update exclusion map**

In the GET branch of `wizard_connectivity()` (around line 860), change the exclusion map to include onion:

```python
        # Build exclusion map: all three modes are mutually exclusive
        exclusion_map = {
            'manual': ['broker', 'onion'],
            'broker': ['manual', 'onion'],
            'onion': ['manual', 'broker'],
        }
        if _broker:
            manifest_excludes = _broker['manifest'].get('excludes', [])
            if manifest_excludes:
                exclusion_map['broker'] = manifest_excludes
```

- [ ] **Step 3: Map onion mode to session**

After the existing `session['ipv6']` mapping block (around lines 841-854), extend:

```python
            # Map to session['ipv6'] for backwards compat with finalize.py
            if 'broker' in selected:
                session['ipv6'] = {
                    'mode': 'broker',
                    'broker_registry': connectivity.get('broker', {}).get('broker_registry', ''),
                }
            elif 'manual' in selected:
                session['ipv6'] = {
                    'mode': 'manual',
                    'prefix': connectivity.get('manual', {}).get('prefix', ''),
                    'allocation_size': connectivity.get('manual', {}).get('allocation_size', 64),
                }
            elif 'onion' in selected:
                session['ipv6'] = {'mode': 'onion'}
            else:
                session['ipv6'] = {'mode': 'none'}
```

- [ ] **Step 4: Skip ipv6 and https finalization steps when mode is onion**

In `_get_finalization_step_ids()` (lines 228-263), or in the finalization view that builds `all_finalization_steps` (line 965), filter out `ipv6` and `https` when network mode is onion:

Find the section around line 992:

```python
        # Installer post-steps
        all_finalization_steps.extend([
            {'id': 'ipv6', 'label': 'Configuring IPv6'},
            {'id': 'https', 'label': 'Configuring HTTPS'},
            {'id': 'signup', 'label': 'Setting up signup page'},
            {'id': 'nginx', 'label': 'Configuring Nginx'},
        ])
```

Change to:

```python
        # Installer post-steps — skip ipv6/https for onion mode
        network_mode = session.get('ipv6', {}).get('mode', 'none')
        if network_mode != 'onion':
            all_finalization_steps.extend([
                {'id': 'ipv6', 'label': 'Configuring IPv6'},
                {'id': 'https', 'label': 'Configuring HTTPS'},
            ])
        all_finalization_steps.extend([
            {'id': 'signup', 'label': 'Setting up signup page'},
            {'id': 'nginx', 'label': 'Configuring Nginx'},
        ])
```

- [ ] **Step 5: Commit**

```bash
git add installer/web/app.py
git commit -m "wizard: handle onion network mode in connectivity and finalization"
```

---

### Task 4: Skip ipv6/https in Finalize Script

**Files:**
- Modify: `installer/web/finalize.py`

- [ ] **Step 1: Guard ipv6 finalization step**

Read the ipv6 finalization function signature and add a mode guard at the top. Locate the `finalize_ipv6` function (search for `def finalize_ipv6` or the ipv6 step handler around line 479):

At the top of the ipv6 handler, add:

```python
    if session.get('ipv6', {}).get('mode') == 'onion':
        return True, None  # Skip — Tor handles connectivity
```

Do the same for the https handler:

```python
    if session.get('ipv6', {}).get('mode') == 'onion':
        return True, None  # Skip — Tor provides encryption, no TLS needed
```

- [ ] **Step 2: Write network mode config in finalize**

In the finalization flow, after the existing steps complete, write the network mode to a config file the engine can read. Add a new step or extend the nginx step:

```python
    network_mode = session.get('ipv6', {}).get('mode', 'none')
    with open('/etc/blockhost/network-mode', 'w') as f:
        f.write(network_mode + '\n')
```

- [ ] **Step 3: Commit**

```bash
git add installer/web/finalize.py
git commit -m "finalize: skip ipv6/https for onion mode, write network-mode config"
```

---

### Task 5: First-Boot — Install Tor and Generate Host Hidden Service

**Files:**
- Modify: `scripts/first-boot.sh`

- [ ] **Step 1: Add tor installation block**

After the network wait step and before the package installation loop (after the bridge setup, around the end of the script's early phase), add:

```bash
# ── Onion Routing ──────────────────────────────────────────────
NETWORK_MODE_FILE="/etc/blockhost/network-mode"
NETWORK_MODE="none"
if [ -f "$NETWORK_MODE_FILE" ]; then
    NETWORK_MODE=$(cat "$NETWORK_MODE_FILE")
fi

if [ "$NETWORK_MODE" = "onion" ]; then
    log "Installing Tor for onion routing..."
    apt-get install -y tor

    # Generate host hidden service (for admin/signup access to the host itself)
    HOST_ONION_DIR="/var/lib/tor/blockhost-host"
    mkdir -p "$HOST_ONION_DIR"
    chown -R debian-tor:debian-tor "$HOST_ONION_DIR"

    cat >> /etc/tor/torrc << TOREOF

# BlockHost — host hidden service (admin/signup)
HiddenServiceDir $HOST_ONION_DIR
HiddenServicePort 80 127.0.0.1:80
TOREOF

    systemctl enable --now tor
    sleep 2  # Tor generates the hostname file
    if [ -f "$HOST_ONION_DIR/hostname" ]; then
        log "Host onion address: $(cat "$HOST_ONION_DIR/hostname")"
    fi
    log "Onion routing enabled — no broker, no IPv6, no Let's Encrypt"
fi
```

- [ ] **Step 2: Skip broker-client installation in onion mode**

In the package installation fallback order (around line 157), guard the broker-client:

```bash
if [ "$NETWORK_MODE" != "onion" ]; then
    FALLBACK_ORDER+=(blockhost-broker-client)
fi
```

- [ ] **Step 3: Commit**

```bash
git add scripts/first-boot.sh
git commit -m "first-boot: install tor and generate host hidden service for onion mode"
```

---

### Task 6: Create Prompt Files for Submodule Sessions

**Files:**
- Create: `prompts/common-network-hook.md`
- Create: `prompts/provisioner-libvirt-guest-exec.md`
- Create: `prompts/provisioner-proxmox-guest-exec.md`
- Create: `prompts/engine-evm-network-hook.md`
- Create: `prompts/engine-opnet-network-hook.md`
- Create: `prompts/engine-cardano-network-hook.md`
- Create: `prompts/engine-ergo-network-hook.md`

- [ ] **Step 1: Write prompt for blockhost-common**

```markdown
Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/COMMON_INTERFACE.md` §8 before making changes.

---

# Common: Network Hook + Root Agent Tor Actions + Guest-Exec Dispatcher

## Observable problem
The framework currently has no network hook abstraction. Connectivity details
(broker vs manual) are handled directly in the provisioner and engine handler.

## Target state
A `blockhost/network_hook.py` module that provides network-mode-agnostic
connection endpoint resolution. The engine handler calls it after
`provisioner.create()`. In broker/manual modes it passes through the existing
IP. In onion mode it creates a Tor hidden service and returns a `.onion` address.

Also: two new root agent actions for tor hidden service lifecycle, and
`guest-exec` command resolution in the provisioner dispatcher.

## Deliverables

1. **New file: `usr/lib/python3/dist-packages/blockhost/network_hook.py`**

   ```python
   """Network-mode-agnostic connection endpoint resolution."""

   import subprocess
   from pathlib import Path

   TOR_DIR = Path("/var/lib/tor")

   def get_connection_endpoint(vm_name: str, bridge_ip: str, mode: str) -> str:
       if mode == "onion":
           return _setup_onion(vm_name, bridge_ip)
       # broker/manual: return bridge_ip (provisioner already has the IPv6)
       return bridge_ip

   def cleanup(vm_name: str, mode: str) -> None:
       if mode == "onion":
           _teardown_onion(vm_name)

   def _setup_onion(vm_name: str, bridge_ip: str) -> str:
       # Call root agent to create hidden service
       result = subprocess.run(
           ["blockhost-root-agent", "tor-hidden-service-add",
            "--vm-name", vm_name, "--bridge-ip", bridge_ip, "--port", "22"],
           capture_output=True, text=True, check=True
       )
       onion = result.stdout.strip()

       # Push .onion into VM via guest-exec
       subprocess.run(
           ["blockhost-vm-guest-exec", vm_name,
            f"echo '{bridge_ip} {onion} {vm_name}' >> /etc/hosts"],
           check=True
       )
       subprocess.run(
           ["blockhost-vm-guest-exec", vm_name,
            f"sed -i 's|signing_url = .*|signing_url = \"http://{onion}:8443\"|' /etc/pam_web3/config.toml"],
           check=True
       )

       return onion

   def _teardown_onion(vm_name: str) -> None:
       subprocess.run(
           ["blockhost-root-agent", "tor-hidden-service-remove",
            "--vm-name", vm_name],
           check=True
       )
   ```

   Export `get_connection_endpoint` and `cleanup` from `blockhost/__init__.py`.

2. **Modify: `usr/share/blockhost/root-agent-actions/system.py`**

   Add two actions:

   ```python
   # tor-hidden-service-add
   # Params (via ACTIONS dict): vm_name, bridge_ip, port=22
   def _tor_hidden_service_add(params):
       vm_name = params["vm_name"]
       bridge_ip = params["bridge_ip"]
       port = params.get("port", 22)

       tor_dir = Path(f"/var/lib/tor/blockhost-{vm_name}")
       tor_dir.mkdir(parents=True, exist_ok=True)
       subprocess.run(["chown", "-R", "debian-tor:debian-tor", str(tor_dir)], check=True)

       with open("/etc/tor/torrc", "a") as f:
           f.write(f"\nHiddenServiceDir /var/lib/tor/blockhost-{vm_name}/\n")
           f.write(f"HiddenServicePort {port} {bridge_ip}:{port}\n")

       subprocess.run(["systemctl", "reload", "tor"], check=True)

       time.sleep(1)  # Tor generates the hostname file
       hostname_file = tor_dir / "hostname"
       return hostname_file.read_text().strip()

   # tor-hidden-service-remove
   def _tor_hidden_service_remove(params):
       vm_name = params["vm_name"]

       lines = []
       with open("/etc/tor/torrc") as f:
           lines = f.readlines()

       marker = f"/var/lib/tor/blockhost-{vm_name}/"
       lines = [l for l in lines if marker not in l]

       with open("/etc/tor/torrc", "w") as f:
           f.writelines(lines)

       subprocess.run(["systemctl", "reload", "tor"], check=True)
       shutil.rmtree(f"/var/lib/tor/blockhost-{vm_name}", ignore_errors=True)
       return "removed"
   ```

   Register both actions in the ACTIONS dict.

3. **Modify: `usr/lib/python3/dist-packages/blockhost/provisioner.py`**

   Add `guest-exec` to the default commands list and ensure it's resolved from
   the manifest's `commands.guest-exec` via `get_command("guest-exec")`.

## Verification
- `python3 -c "from blockhost.network_hook import get_connection_endpoint, cleanup"`
- `grep tor-hidden-service-add /usr/share/blockhost/root-agent-actions/system.py`
- Check that provisioner dispatcher resolves `guest-exec` command
```

- [ ] **Step 2: Write prompt for provisioner-libvirt**

```markdown
Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/PROVISIONER_INTERFACE.md` §2 (guest-exec section) before making changes.

---

# Provisioner-Libvirt: guest-exec CLI

## Observable problem
The provisioner has a domain-specific `update-gecos` command that knows about
/etc/passwd format. The network hook needs a generic way to run commands inside
VMs (update /etc/hosts, update signing URL, etc.).

## Target state
A generic `blockhost-vm-guest-exec <name> <command...>` command that runs a
shell command inside a running VM. The existing `update-gecos` is refactored
to delegate to `guest-exec`.

## Implementation

Use qemu-guest-agent primitives:
- `guest-file-open` to open a temp script
- `guest-file-write` to write the command
- `guest-exec` to run it (path: /bin/sh, arg: ["-c", command])
- Poll `guest-exec-status` for exit code + output

Chunk large commands (>4096 bytes) across multiple `guest-file-write` calls.

## Deliverables

1. **New file: `scripts/guest-exec.py`**

   Symlink or wrapper that calls: `virsh qemu-agent-command <domain> <json>`

   Exit with the command's exit code. Print stdout to stdout, stderr to stderr.

2. **Modify: `provisioner.json`** — add `"guest-exec": "blockhost-vm-guest-exec"` to commands
3. **Modify: `scripts/update-gecos.py`** — refactor to call `guest-exec` with a sed command
4. **Modify: `scripts/vm-create.py`** — no changes needed for guest-exec itself, but verify
   the manifest lists `guest-exec` in its commands.

   Note: `vm-create.py` currently allocates IPv6 from broker. That's fine —
   the network hook runs AFTER create, so the provisioner stays unchanged.

5. **Add `guest-exec` to the provisioner .deb packaging** (symlink/script in bin dir)

## Verification
- `blockhost-vm-guest-exec testvm "echo hello"` returns "hello"
- `blockhost-vm-guest-exec testvm "cat /etc/hostname"` returns the VM's hostname
- update-gecos still works after refactoring
```

- [ ] **Step 3: Write prompt for provisioner-proxmox**

Same as Step 2 but for Proxmox (`qm guest exec <vmid> -- <command...>`).

- [ ] **Step 4: Write prompt for engine-evm**

```markdown
Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/ENGINE_INTERFACE.md` (Network Hook Integration section) before making changes.

---

# Engine-EVM: Network Hook Integration

## Observable problem
The engine handler currently reads IPv6 from the provisioner's create result
and uses it directly for connection details. It also calls the domain-specific
`update-gecos` provisioner command.

## Target state
After `provisioner.create()`, call `network_hook.get_connection_endpoint()`
to get the subscriber-facing host. Use `guest-exec` instead of `update-gecos`.

## Changes needed

1. In the engine handler's VM creation flow (likely in `src/handler/` or the
   fund manager's `index.ts`), after the `provisioner.create()` call:

   ```
   const host = getConnectionEndpoint(vmName, createResult.ip, networkMode);
   ```

   Where `getConnectionEndpoint` is a simple Python subprocess call:
   `python3 -c "from blockhost.network_hook import get_connection_endpoint; print(get_connection_endpoint('${name}', '${ip}', '${mode}'))"`

2. Read network mode from `/etc/blockhost/network-mode` at handler start.

3. Replace `update-gecos` calls with `guest-exec`:
   `blockhost-vm-guest-exec <name> "sed -i '...' /etc/passwd"`

4. In the destroy flow, call `network_hook.cleanup(vm_name, mode)` after
   `provisioner.destroy()`.

## Deliverables

1. Modify: VM creation handler — add `getConnectionEndpoint` call after create
2. Modify: VM destroy handler — add `cleanup` call after destroy
3. Modify: GECOS update — use `guest-exec` instead of `update-gecos`
4. Test: verify broker mode still works (network_hook passes through IPv6)

## Verification
- Broker mode: connection details still contain IPv6 address
- Onion mode: connection details contain .onion address (once tor is set up)
- GECOS update still works via guest-exec
```

- [ ] **Step 5: Write prompts for engine-opnet, engine-cardano, engine-ergo**

Identical to the EVM prompt (Step 4) but adjusted for each engine's handler
file paths and language (TypeScript for all four).

- [ ] **Step 6: Commit prompt files**

```bash
git add prompts/
git commit -m "prompts: network hook, guest-exec, engine integration for onion routing"
```

---

## Verification Checklist

After all tasks and prompts are applied:

- [ ] Wizard shows three connectivity options: Broker, Manual, Onion
- [ ] Selecting Onion hides the broker registry field
- [ ] Finalization skips ipv6 and https steps in onion mode
- [ ] `/etc/blockhost/network-mode` contains "onion"
- [ ] `tor` is installed and running on the host
- [ ] `blockhost-vm-guest-exec <name> "echo hello"` works on both provisioners
- [ ] Creating a VM in onion mode creates a hidden service in `/var/lib/tor/`
- [ ] VM's `/etc/pam_web3/config.toml` has `http://{onion}:8443`
- [ ] VM's `/etc/hosts` has the onion → bridge IP mapping
- [ ] Connection details contain the `.onion` address
- [ ] Broker mode still works (no regression)
- [ ] Manual mode still works (no regression)
