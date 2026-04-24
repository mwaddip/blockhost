# libpam-web3 plugins: Move nodejs from Depends to Recommends

All chain plugins (cardano, opnet, evm) have `Depends: libpam-web3, nodejs (>= N)`. This breaks VM template builds — the template image doesn't have Node.js (it's installed later by the engine's first-boot hook via NodeSource, not from Debian repos).

- Cardano (`>= 18`) accidentally works because Debian 12 has node 18 in repos — `apt-get -f` pulls it
- OPNet (`>= 22`) fails because node 22 isn't in Debian repos — dpkg fails, plugin not installed

The Rust PAM plugin binary doesn't need Node.js. Only the auth-svc (bundled JS) needs it at runtime. The systemd unit won't start without Node — that's sufficient runtime enforcement.

## Fix

In every plugin's `packaging/build-deb.sh`, change the DEBIAN/control `Depends` line:

**Before:**
```
Depends: libpam-web3, nodejs (>= 22)
```

**After:**
```
Depends: libpam-web3
Recommends: nodejs (>= 22)
```

This applies to:
- `plugins/cardano/packaging/build-deb.sh` — change `nodejs (>= 18)` to Recommends
- `plugins/opnet/packaging/build-deb.sh` — change `nodejs (>= 22)` to Recommends
- `plugins/evm/packaging/build-deb.sh` — check and fix if same pattern

dpkg doesn't enforce Recommends. The package installs clean in the template. When Node arrives via first-boot, the auth-svc starts normally.
