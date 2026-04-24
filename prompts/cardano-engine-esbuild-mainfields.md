# Cardano Engine: Fix libsodium ESM resolution in esbuild

After removing `--external`, esbuild now tries to bundle `libsodium-wrappers-sumo` but picks its ESM entry point (`dist/modules-sumo-esm/libsodium-wrappers.mjs`) which uses a relative `import` for a `.mjs` file that esbuild can't resolve.

The CJS entry point (`dist/modules-sumo/libsodium-wrappers.js`) works fine. Force esbuild to prefer CJS by adding this flag to every esbuild invocation in `packaging/build.sh`:

```
--main-fields=main,module
```

By listing `main` before `module`, esbuild resolves to the CJS entry point first. Add it to all 7 esbuild calls (monitor, bw, ab, is, bhcrypt, mint_nft, keygen).
