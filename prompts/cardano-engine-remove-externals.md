# Cardano Engine: Remove esbuild --external flags

All esbuild calls in `packaging/build.sh` use `--external:@stricahq/bip32ed25519` and `--external:libsodium-wrappers-sumo`. This means these packages are NOT included in the bundles — they're expected to be installed as `node_modules` on the target system. But the .deb doesn't ship `node_modules`, so they fail at runtime with `MODULE_NOT_FOUND`.

Remove both `--external` flags from every esbuild call in `packaging/build.sh`:

```
--external:@stricahq/bip32ed25519 \
--external:libsodium-wrappers-sumo \
```

Delete these two lines from all 7 esbuild invocations (monitor, bw, ab, is, bhcrypt, mint_nft, keygen).

Both packages are pure JavaScript — there's no reason to externalize them. The bundles will be larger but fully self-contained. No runtime `node_modules` needed on the VM.
