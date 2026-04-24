Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# Broker: sync adapter-client package-lock.json files

## Observable problem

CI `Build Packages` fails at the broker-client build with:

```
npm error Missing: @scure/bip39@2.0.1 from lock file
npm error Missing: @scure/base@2.0.0 from lock file
npm error `npm ci` can only install packages when your package.json and package-lock.json or npm-shrinkwrap.json are in sync.
```

Affected:
- `adapters/cardano/client/package.json` declares `@scure/bip39: ^2.0.0` but `package-lock.json` doesn't contain it
- `adapters/opnet/client/package.json` declares `@scure/bip39: ^2.0.0` but `package-lock.json` doesn't contain it

Both clients also need `@scure/base` pulled through as a transitive.

## Target state

`package-lock.json` in both adapter client dirs is in sync with `package.json` such that `npm ci` succeeds.

## Fix

```bash
cd adapters/cardano/client && npm install --package-lock-only
cd ../../../adapters/opnet/client && npm install --package-lock-only
```

`--package-lock-only` regenerates the lock without touching `node_modules`. If the build also installs optional or platform-specific deps, plain `npm install` may be needed — your call.

Do NOT bump any dependency versions. The lockfile is out of sync because `package.json` was updated without running `npm install` at the time; we're just catching the lockfile up. If you see other drift, flag it but don't fix it in this change.

## Verification

Run `npm ci` in each adapter client dir and confirm zero errors:

```bash
cd adapters/cardano/client && npm ci && cd -
cd adapters/opnet/client && npm ci && cd -
```

Also run it in `adapters/ergo/client/` to confirm that one is fine (no `@scure/bip39` in its package.json, but sanity-check).

## Deliverables

1. Lockfile updates in both adapter clients
2. Single commit, no version bump, clear message like "Sync adapter client lockfiles for @scure/bip39"
3. Push to main
4. Report commit hash
