# Contributing

## Repository Structure

BlockHost is a multi-repo project. The main repo orchestrates submodules:

| Repo | Purpose |
|------|---------|
| [blockhost](https://github.com/mwaddip/blockhost) | Installer, scripts, ISO builder, admin panel |
| [blockhost-engine-evm](https://github.com/mwaddip/blockhost-engine-evm) | EVM blockchain engine |
| [blockhost-engine-opnet](https://github.com/mwaddip/blockhost-engine-opnet) | OPNet blockchain engine |
| [blockhost-provisioner-proxmox](https://github.com/mwaddip/blockhost-provisioner-proxmox) | Proxmox provisioner |
| [blockhost-provisioner-libvirt](https://github.com/mwaddip/blockhost-provisioner-libvirt) | libvirt provisioner |
| [blockhost-common](https://github.com/mwaddip/blockhost-common) | Shared library |
| [blockhost-broker](https://github.com/mwaddip/blockhost-broker) | IPv6 broker |
| [blockhost-monitor](https://github.com/mwaddip/blockhost-monitor) | Host monitor (in development) |
| [libpam-web3](https://github.com/mwaddip/libpam-web3) | PAM authentication module |
| [blockhost-facts](https://github.com/mwaddip/blockhost-facts) | Interface contracts |

## Before You Start

1. Read the relevant [interface contract](/developer/interface-contracts) for the component you're modifying
2. Understand the [architecture](/developer/architecture) and where your change fits
3. Check existing issues and discussions

## Guidelines

- **Fix the interface, never wrap the mismatch.** If two components disagree, the contract is wrong — not the code.
- **No `shell=True`.** All subprocess calls use argument lists.
- **Validate at the boundary.** Trust internal code. Validate external input.
- **Keep it simple.** Don't add abstractions for one-time operations. Three similar lines are better than a premature helper.
- **Test with the ISO.** The integration test is booting the ISO and running the wizard end-to-end. Unit tests are good; a working system is better.

## Adding a New Engine

See [Building an Engine](/developer/building-an-engine). The interface contract is in `facts/ENGINE_INTERFACE.md`.

## Adding a New Provisioner

See [Building a Provisioner](/developer/building-a-provisioner). The interface contract is in `facts/PROVISIONER_INTERFACE.md`.

## Security Issues

If you find a security vulnerability, please report it responsibly. See [Audit Status](/security/audit-status) for what's been reviewed.
