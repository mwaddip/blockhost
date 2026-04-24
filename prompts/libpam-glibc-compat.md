# libpam-web3: Fix glibc compatibility — target Debian 12

The PAM module (`libpam_web3.so`) built on the dev workstation (glibc 2.39) requires `GLIBC_2.39` at runtime. Debian 12 cloud images ship glibc 2.36. The module silently fails to load — PAM falls through to password auth, SSH shows a password prompt instead of the wallet signing flow.

This worked in v0.5.0 (max requirement was GLIBC_2.34) but broke in v0.8.0. A Rust dependency or toolchain update introduced a glibc 2.39 symbol.

## Fix: Build with musl target

Switch to `x86_64-unknown-linux-musl` for a fully static binary. No glibc dependency at all — works on any Linux.

### Setup (one time)

```bash
rustup target add x86_64-unknown-linux-musl
```

### In `packaging/build-deb.sh` (or wherever `cargo build` runs)

Change:
```bash
cargo build --release
```

To:
```bash
cargo build --release --target x86_64-unknown-linux-musl
```

The output binary moves from `target/release/libpam_web3.so` to `target/x86_64-unknown-linux-musl/release/libpam_web3.so` — update the copy path in the build script accordingly.

### Important

- musl-linked `.so` files work as PAM modules — PAM loads them via `dlopen()` which works with static binaries
- The binary will be slightly larger (statically linked libc) but has zero runtime dependencies
- Test that the PAM conversation still works — musl's DNS resolution behaves differently from glibc (shouldn't matter for a PAM module that doesn't resolve hostnames)

## Alternative: Pin glibc version with cargo-zigbuild

If musl causes issues (e.g. PAM module loading), use `cargo-zigbuild` to cross-compile against a specific glibc:

```bash
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.36
```

This produces a dynamically linked binary that only requires glibc 2.36 — compatible with Debian 12 regardless of what the build host runs.

## Also applies to the Cardano plugin

`plugins/cardano/packaging/build-deb.sh` also compiles a Rust binary. Apply the same target change there.
