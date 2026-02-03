# BlockHost - Custom Proxmox VE Image Project

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

## Documentation Requirements (PERSISTENT RULE)

**Every change made in this project MUST be documented in `docs/BUILD_GUIDE.md`:**

1. **Commands**: Record every shell command executed with full context
2. **File Changes**: Include diffs or full file contents for all created/modified files
3. **Explanations**: Explain WHY each step is necessary
4. **Prerequisites**: List any dependencies or assumptions
5. **Verification**: Include commands to verify each step succeeded

A human must be able to reproduce the entire build by following the guide step-by-step.

## Project Structure

```
blockhost/
├── CLAUDE.md                 # This file - project rules and context
├── docs/
│   └── BUILD_GUIDE.md        # Step-by-step reproduction guide
├── installer/
│   ├── web/                  # Web-based installer (Flask/lightweight)
│   ├── console/              # ncurses/whiptail console fallback
│   └── common/               # Shared logic (OTP, detection, config)
├── packages/                 # Custom packages to be installed
├── scripts/
│   ├── build-iso.sh          # ISO build script
│   └── first-boot.sh         # First boot orchestration
└── vm/                       # VM testing configuration
```

## Architecture Overview

### First Boot Flow
1. System boots → `first-boot.service` starts
2. Check if running from ISO or HDD (detect boot medium)
3. Attempt DHCP for network configuration
4. If DHCP fails → Launch ncurses network wizard on console
5. Generate OTP code → Display on console
6. Start web installer on port 80
7. User enters OTP on web interface to authenticate
8. Web installer guides through package configuration
9. Mark first-boot complete, disable service

### Key Components
- **Detection**: `/sys/firmware` checks, mount point analysis
- **OTP**: Time-based or session-based one-time password
- **Web Installer**: Lightweight Python (Flask) or Go binary
- **Console Fallback**: whiptail/dialog for network config

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
