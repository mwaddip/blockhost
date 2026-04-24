Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# Reconcile blockhost-monitor.service with EVM/OPNet canonical form

`facts/ENGINE_INTERFACE.md` §8 documents the canonical systemd unit. EVM and OPNet ship it; your engine ships a leaner variant that diverges on four lines. Bring your unit into line.

## Target unit (EVM/OPNet shape)

```ini
[Unit]
Description=Blockhost Subscriptions Event Monitor
After=network.target
Requires=blockhost-root-agent.service
After=blockhost-root-agent.service

[Service]
Type=simple
User=blockhost
Group=blockhost
Environment=HOME=/var/lib/blockhost
Environment=NODE_OPTIONS=--dns-result-order=ipv4first
EnvironmentFile=/opt/blockhost/.env
ExecStartPre=+/bin/bash -c 'chown root:blockhost /run/blockhost && chmod 2775 /run/blockhost'
ExecStart=/usr/bin/node /usr/share/blockhost/monitor.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/var/lib/blockhost /run/blockhost

[Install]
WantedBy=multi-user.target
```

## Changes from your current unit

1. **Add `Environment=NODE_OPTIONS=--dns-result-order=ipv4first`** — IPv4-first DNS resolution, matters when the broker allocates IPv6 and Node otherwise prefers AAAA records.
2. **Change `EnvironmentFile=-/etc/blockhost/blockhost-env` → `EnvironmentFile=/opt/blockhost/.env`** — canonical path per §7 of the engine interface. The `-` prefix (optional env file) is dropped because the installer is expected to have written this file by the time the service starts.
3. **Add `ExecStartPre=+/bin/bash -c 'chown root:blockhost /run/blockhost && chmod 2775 /run/blockhost'`** — ensures `/run/blockhost` exists with correct ownership before the monitor drops to the `blockhost` user. The `+` prefix runs this command as root (bypasses `User=`).
4. **Change `ReadWritePaths=/var/lib/blockhost` → `ReadWritePaths=/var/lib/blockhost /run/blockhost`** — `/run/blockhost` is where OTP and knock.active files live.

## Follow-on: verify env file consumption

Your engine code probably reads `RPC_URL` and `BLOCKHOST_CONTRACT` from wherever the monitor service's `EnvironmentFile` points. Confirm:

- If anything in `src/` (especially the monitor entrypoint or `paths.ts`) assumes `/etc/blockhost/blockhost-env`, update it to expect `/opt/blockhost/.env`.
- If the finalization step in `blockhost/engine_<chain>/wizard.py` writes the env file, update the target path to `/opt/blockhost/.env` and ensure ownership `root:blockhost` mode `0640`.
- `ENGINE_INTERFACE.md` §7 shows the schema of `.env` — just `RPC_URL` and `BLOCKHOST_CONTRACT` (chain-agnostic). Validator may also write `NFT_CONTRACT` and `DEPLOYER_KEY_FILE` for `validate_system.py`.

## What NOT to change

- Do not touch the monitor's Node entrypoint path (`/usr/share/blockhost/monitor.js`) — unchanged.
- Do not rename the service — it stays `blockhost-monitor.service`.
- Do not alter hardening directives (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`) — canonical.

## Verification

```bash
# From a fresh ISO boot or after pushing the .deb:
systemctl status blockhost-monitor
systemctl cat blockhost-monitor | grep -E 'ExecStartPre|NODE_OPTIONS|EnvironmentFile|ReadWritePaths'
ls -la /run/blockhost/    # root:blockhost, mode 2775
cat /opt/blockhost/.env   # RPC_URL=..., BLOCKHOST_CONTRACT=...
```

Single commit. Push when done; main session pulls the pointer.

## Note on facts

`facts/ENGINE_INTERFACE.md` §8 currently documents the divergence as "to be reconciled". Once all four engines ship the canonical unit, delete that caveat — but that edit is main-session work, not yours.
