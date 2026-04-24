Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# libpam-web3: Detect .onion TLD and use http:// scheme

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

In onion mode, the signing host is a `.onion` address. Tor provides end-to-end
encryption — TLS is redundant and Let's Encrypt can't issue certs for `.onion`.
The URL must use `http://`, not `https://`.

## Target state
`signing_url_for()` detects `.onion` hosts and uses `http://`. Everything else
stays `https://`.

## Expected behavior
- Host ends with `.onion` → `http://{host}:{port}`
- Any other host → `https://{host}:{port}` (unchanged)

## Deliverables

1. **Modify `src/lib.rs` — `signing_url_for()`**

```rust
fn signing_url_for(chain: &str) -> String {
    let host = read_signing_host();
    let port = chain_port(chain);
    let scheme = if host.ends_with(".onion") { "http" } else { "https" };
    format!("{}://{}:{}", scheme, host, port)
}
```

2. **Run `cargo test`** — all tests pass
3. **Run `cargo build --release`** — compiles

## Verification
- Host `abc...xyz.onion` → URL starts with `http://`
- Host `100.blockhost.thawaras.org` → URL starts with `https://`
- Host `1.2.3.4` → URL starts with `https://`
- `cargo test` passes
