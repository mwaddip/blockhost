# BlockHost - Custom Proxmox VE Image Project

## Architecture Reference (PERSISTENT RULE)

**`ARCHITECTURE.md` must be kept in sync with the codebase.** When any change affects the architecture — new routes, new config files, changed data flows, new finalization steps, session schema changes, new services, or modified submodule interfaces — update `ARCHITECTURE.md` to reflect the change. This file is LLM-optimized (dense, structured, no prose) and serves as the canonical reference for how components connect.

## Submodule Separation (CRITICAL RULE)

**You CANNOT modify files in submodules.** The following directories are submodules with their own Claude sessions:

- `libpam-web3/`
- `blockhost-common/`
- `blockhost-provisioner/`
- `blockhost-engine/`
- `blockhost-broker/`

**When changes to a submodule are needed:**
1. Do NOT attempt to edit files in submodule directories
2. Instead, provide the user with a complete prompt to send to that submodule's Claude session
3. Format the prompt clearly so the user can copy-paste it directly

## Project Structure

```
blockhost/
├── CLAUDE.md                 # This file - project rules and context
├── docs/
│   └── BUILD_GUIDE.md        # Step-by-step reproduction guide
├── installer/
│   ├── web/                  # Web-based installer (Flask)
│   └── common/               # Shared logic (OTP, detection, config)
├── packages/                 # Custom packages to be installed
├── scripts/
│   ├── build-iso.sh          # ISO build script
│   └── first-boot.sh         # First boot orchestration
```

## Architecture Overview

### First Boot Flow
1. System boots → `first-boot.service` starts
2. Check if running from ISO or HDD (detect boot medium)
3. Attempt DHCP for network configuration
4. Generate OTP code → Display on console
5. Start web installer on port 80
6. User enters OTP on web interface to authenticate
7. Web installer guides through package configuration
8. Mark first-boot complete, disable service

### Key Components
- **Detection**: `/sys/firmware` checks, mount point analysis
- **OTP**: Time-based or session-based one-time password
- **Web Installer**: Flask-based wizard with OTP authentication

## Submodule Packages

Packages built from submodules during first-boot:

| Submodule | Build Command | Package(s) | Install Location |
|-----------|---------------|------------|------------------|
| libpam-web3 | `packaging/build-deb-tools.sh` | libpam-web3-tools | Proxmox host |
| libpam-web3 | `packaging/build-deb.sh` | libpam-web3 | VM template dir |
| blockhost-common | `build.sh` | blockhost-common | Proxmox host |
| blockhost-provisioner | `build-deb.sh` | blockhost-provisioner | Proxmox host |
| blockhost-engine | `packaging/build.sh` | blockhost-engine | Proxmox host |
| blockhost-broker | `scripts/build-deb.sh` | blockhost-broker-client | Proxmox host |

**Note**: `libpam-web3` (the PAM module, not tools) is stored in `/var/lib/blockhost/template-packages/` for inclusion in VM templates, not installed on the Proxmox host.

## ISO Build & Test Cycle

When rebuilding the ISO:

1. **Rebuild .deb packages** whenever a submodule has changed: `./scripts/build-packages.sh` — the ISO build copies pre-built .debs from `packages/host/` and `packages/template/`, it does NOT rebuild them automatically.
2. **Remove the old ISO with `sudo`**: `sudo rm build/blockhost_0.1.0.iso` — the ISO is created by a root process and is owned by root.
