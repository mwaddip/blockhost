# blockhost-common: Cloud-Init Template Update for libpam-web3 Refactor

**Branch:** `feature/opnet` (create from current master)

**Start by reading:** `SPECIAL.md`, `CLAUDE.md` — in that order, before doing anything else.

---

## Context

libpam-web3 has been refactored (on its own `feature/opnet` branch). All blockchain communication has been removed from the PAM module and web3-auth-svc. The PAM module no longer queries any chain — it verifies signatures locally and checks wallet addresses against GECOS fields. web3-auth-svc is now HTTPS-only (serves signing page, handles callbacks) with no blockchain backend.

The cloud-init template `nft-auth.yaml` in this repo still writes the **old** config format with blockchain sections, socket paths, and chain-specific variables. It needs to match the new libpam-web3 contract.

---

## What Changes

### 1. Template variables

**Remove:** `${CHAIN_ID}`, `${NFT_CONTRACT}`, `${RPC_URL}`
**Add:** `${WALLET_ADDRESS}` (the VM owner's wallet address, any format — `0x...`, `bc1q...`, `addr1...`)
**Keep:** `${VM_NAME}`, `${SIGNING_HOST}`, `${USERNAME}`, `${NFT_TOKEN_ID}`, `${OTP_LENGTH}`, `${OTP_TTL}`, `${SECRET_KEY}`, `${SIGNING_DOMAIN}`

Update the comment header at the top of the template to reflect the new variable list.

### 2. GECOS field

**Current:** `gecos: "nft=${NFT_TOKEN_ID}"`
**New:** `gecos: "wallet=${WALLET_ADDRESS},nft=${NFT_TOKEN_ID}"`

The `wallet=ADDRESS` field is what PAM authenticates against. The `nft=TOKEN_ID` field is preserved for reconciliation processes. Both are comma-separated in the GECOS field.

### 3. PAM config (`/etc/pam_web3/config.toml`)

**Current config written by template:**
```toml
[machine]
id = "${VM_NAME}"
secret_key = "${SECRET_KEY}"

[auth]
mode = "nft"
nft_lookup = "passwd"
signing_url = "https://${SIGNING_HOST}:8443"
callback_enabled = true
callback_grace_seconds = 10
otp_length = ${OTP_LENGTH}
otp_ttl_seconds = ${OTP_TTL}

[blockchain]
socket_path = "/run/web3-auth/web3-auth.sock"
chain_id = ${CHAIN_ID}
nft_contract = "${NFT_CONTRACT}"
timeout_seconds = 10
```

**New config:**
```toml
[machine]
id = "${VM_NAME}"
secret_key = "${SECRET_KEY}"

[auth]
signing_url = "https://${SIGNING_HOST}:8443"
otp_length = ${OTP_LENGTH}
otp_ttl_seconds = ${OTP_TTL}
callback_enabled = true
callback_grace_seconds = 10
```

Removed: `mode`, `nft_lookup`, entire `[blockchain]` section. No mode selection — the PAM module detects the auth path from the `.sig` file content. No blockchain config — PAM doesn't talk to any chain.

### 4. web3-auth-svc config (`/etc/web3-auth/config.toml`)

**Current config written by template:**
```toml
socket_path = "/run/web3-auth/web3-auth.sock"
backend = "jsonrpc"
default_chain_id = ${CHAIN_ID}
default_contract = "${NFT_CONTRACT}"

[jsonrpc]
rpc_url = "${RPC_URL}"
timeout_seconds = 30

[https]
port = 8443
bind = ["::", "0.0.0.0"]
cert_path = "/etc/libpam-web3/tls/cert.pem"
key_path = "/etc/libpam-web3/tls/key.pem"
signing_page = "/usr/share/libpam-web3/signing-page/index.html"
```

**New config:**
```toml
[https]
port = 8443
bind = ["::", "0.0.0.0"]
cert_path = "/etc/libpam-web3/tls/cert.pem"
key_path = "/etc/libpam-web3/tls/key.pem"
signing_page_path = "/usr/share/libpam-web3/signing-page/index.html"
```

Removed: `socket_path`, `backend`, `default_chain_id`, `default_contract`, entire `[jsonrpc]` section. web3-auth-svc is now a pure HTTPS server — it serves the signing page and handles POST callbacks. It does NOT query any blockchain.

**Note:** The key name changed from `signing_page` to `signing_page_path` in the refactored web3-auth-svc. Use the new name.

### 5. Everything else stays

The PAM stack (`/etc/pam.d/sshd`), SSH config (`web3-only.conf`), `runcmd` section (service enable, Let's Encrypt cert upgrade), packages, and `final_message` are all unchanged.

---

## Verification

After the change:
1. Template uses exactly 8 variables: `VM_NAME`, `SIGNING_HOST`, `USERNAME`, `WALLET_ADDRESS`, `NFT_TOKEN_ID`, `OTP_LENGTH`, `OTP_TTL`, `SECRET_KEY` (plus `SIGNING_DOMAIN` in runcmd shell logic)
2. No references to `CHAIN_ID`, `NFT_CONTRACT`, `RPC_URL`, `socket_path`, `backend`, `jsonrpc`, `mode`, or `nft_lookup` remain
3. GECOS field contains both `wallet=` and `nft=`
4. PAM config has only `[machine]` and `[auth]` sections
5. web3-auth-svc config has only `[https]` section

---

## Documentation

Update README.md and DESIGN.md if they reference the cloud-init template variables or the config format written by the template.
