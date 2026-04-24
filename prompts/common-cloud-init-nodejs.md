# blockhost-common: Restore Node.js 22 in cloud-init template

The `nft-auth.yaml` cloud-init template had Node.js 22 installation via NodeSource added in `fe2c85e` and then reverted in `886a024` during the auth-svc migration from engine to libpam. Now that auth-svc lives permanently in libpam chain plugins, Node.js is needed on every VM — the auth-svc is a bundled JS file that runs on Node.

Without it, the auth-svc crash-loops with exit code 127 (node not found), the signing page never serves, and SSH wallet auth falls back to manual paste mode.

## Fix

In `usr/share/blockhost/cloud-init/templates/nft-auth.yaml`, add NodeSource setup and Node.js 22 installation to `runcmd`, before the `systemctl enable` lines:

```yaml
runcmd:
  # Install Node.js 22 LTS (required by libpam-web3 chain plugin auth-svc)
  - curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  - apt-get install -y nodejs

  - systemctl enable --now qemu-guest-agent
  - systemctl daemon-reload
  - systemctl enable --now web3-auth-svc
```

Node must be installed before `web3-auth-svc` is enabled, otherwise the service starts, fails to find `node`, and enters a restart loop.

## Also fix

The `systemctl enable --now web3-auth-svc` on line 86 uses a generic service name. The actual service names are chain-specific: `web3-auth-svc-cardano`, `web3-auth-svc-opnet`, `web3-auth-svc-evm`.

Replace with a glob that enables whichever auth-svc is installed:

```yaml
  - |
    for svc in /lib/systemd/system/web3-auth-svc-*.service; do
      [ -f "$svc" ] && systemctl enable --now "$(basename "$svc")" || true
    done
```
