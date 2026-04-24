# libpam-web3-opnet: Switch to cargo-zigbuild for glibc compatibility

Same issue as the core PAM module and Cardano plugin. The Rust binary built on glibc 2.39 (Ubuntu) requires `GLIBC_2.39` at runtime. Debian 12 VMs have glibc 2.36. The plugin silently fails to load.

In `plugins/opnet/packaging/build-deb.sh`, change:

```bash
cargo build --release
```

To:

```bash
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.36
```

The output binary moves from `target/release/` to `target/x86_64-unknown-linux-gnu/release/` — update the copy path in the build script accordingly.

Requires `cargo-zigbuild` and `zig` installed on the build host (`cargo install cargo-zigbuild`, zig via pip or system package).
