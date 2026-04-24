Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# libpam-web3: Read signing_url from config instead of hardcoding https://

## Observable problem
`signing_url_for()` at `src/lib.rs:292` hardcodes `https://`:
```rust
fn signing_url_for(chain: &str) -> String {
    let host = read_signing_host();
    let port = chain_port(chain);
    format!("https://{}:{}", host, port)
}
```

The cloud-init template writes `signing_url = "https://${SIGNING_HOST}:8443"` into `/etc/pam_web3/config.toml`, but the Rust config parser (`config.rs`) doesn't have a `signing_url` field in `AuthConfig` — it only has `otp_length` and `otp_ttl_seconds`. The `signing_url` TOML key is silently ignored.

In onion mode, the network hook sed-replaces `signing_url` to `http://{onion}:8443` in the config file, but libpam-web3 never reads it.

## Target state
`AuthConfig` gains an optional `signing_url` field. `signing_url_for()` reads it: if present, use it as-is (it includes scheme + host + port). If absent, fall back to the current derived behavior (`https://{signing_host}:{derived_port}`).

## Expected behavior
- Broker/manual mode: config file has `signing_url = "https://..."` → read and use directly (no change in behavior)
- Onion mode: network hook writes `signing_url = "http://abc...xyz.onion:8443"` → read and use directly (corrects the scheme)
- Config file without `signing_url` field: fall back to derived URL with `https://` (backwards compat)

## Changes

### 1. `src/config.rs` — Add signing_url to AuthConfig

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_otp_length")]
    pub otp_length: usize,
    #[serde(default = "default_otp_ttl")]
    pub otp_ttl_seconds: u64,
    /// Full signing URL including scheme, host, and port.
    /// If set, used directly. If absent, derived from hostname + port with https://.
    #[serde(default)]
    pub signing_url: Option<String>,
}
```

### 2. `src/lib.rs` — Use signing_url from config when available

```rust
fn signing_url_for(chain: &str) -> String {
    // Use config-provided URL if present (includes scheme)
    if let Ok(cfg) = Config::load() {
        if let Some(url) = cfg.auth.signing_url {
            return url;
        }
    }
    // Fallback: derive from hostname (backwards compat)
    let host = read_signing_host();
    let port = chain_port(chain);
    format!("https://{}:{}", host, port)
}
```

### 3. `src/config.rs` — Update tests

The existing tests that parse the `[auth]` section should still pass (signing_url is optional). Add a test for the new field:

```rust
#[test]
fn test_signing_url_optional() {
    let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "http://abc.onion:8443"
"#;
    let config: Config = toml::from_str(config_str).unwrap();
    assert_eq!(config.auth.signing_url, Some("http://abc.onion:8443".to_string()));
}
```

## Deliverables
1. Modify `src/config.rs` — add `signing_url: Option<String>` to `AuthConfig`
2. Modify `src/lib.rs` — read `signing_url` from config in `signing_url_for()`, with fallback
3. Run `cargo test` — all tests pass
4. Run `cargo build --release` — compiles

## Verification
- `cargo test` passes
- Config with `signing_url = "https://fqdn:8443"` → URL uses that value
- Config with `signing_url = "http://abc.onion:8443"` → URL uses http://
- Config without `signing_url` → falls back to derived `https://{host}:{port}`
