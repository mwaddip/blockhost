Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# libpam-web3: Add use_tls config option for signing URL scheme

## Observable problem
`signing_url_for()` at `src/lib.rs:292` hardcodes `https://`:
```rust
fn signing_url_for(chain: &str) -> String {
    let host = read_signing_host();
    let port = chain_port(chain);
    format!("https://{}:{}", host, port)
}
```

This is the PAM callback URL shown to the user for wallet signing — unrelated to
the `signing_url` key in `/etc/pam_web3/config.toml` (which is for the signup page).

Some network backends (Tor `.onion`, future mesh/encrypted transports) provide
their own end-to-end encryption. TLS is redundant for them. The URL must use
`http://` instead of `https://`.

## Target state
Add `use_tls` (bool, default `true`) to the `[auth]` config section.
`signing_url_for()` reads it: `true` → `https://`, `false` → `http://`.

## Expected behavior
- `use_tls = true` or absent → `https://` (current behavior, unchanged)
- `use_tls = false` → `http://`
- The network hook sets `use_tls = false` for onion mode by sed-replacing the config

## Deliverables

1. **Modify `src/config.rs` — add use_tls to AuthConfig**

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_otp_length")]
    pub otp_length: usize,
    #[serde(default = "default_otp_ttl")]
    pub otp_ttl_seconds: u64,
    /// Whether to use TLS for the signing URL (default: true).
    /// Set to false for network backends that provide their own encryption (Tor, mesh, etc.).
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,
}

fn default_use_tls() -> bool { true }
```

2. **Modify `src/lib.rs` — `signing_url_for()`**

```rust
fn signing_url_for(chain: &str) -> String {
    let host = read_signing_host();
    let port = chain_port(chain);
    let use_tls = Config::load().map(|c| c.auth.use_tls).unwrap_or(true);
    let scheme = if use_tls { "https" } else { "http" };
    format!("{}://{}:{}", scheme, host, port)
}
```

3. **Run `cargo test`** — all tests pass (default `use_tls = true` maintains current behavior)
4. **Run `cargo build --release`** — compiles

## Verification
- Config with `use_tls = false` → URL starts with `http://`
- Config with `use_tls = true` → URL starts with `https://`
- Config without `use_tls` (absent) → URL starts with `https://` (default)
- `cargo test` passes
