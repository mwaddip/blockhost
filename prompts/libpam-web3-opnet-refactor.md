# libpam-web3 Interface Simplification

**Branch:** `feature/opnet` (create from current master)

**Start by reading:** `SPECIAL.md`, `SETTINGS.md` (if present), and `CLAUDE.md` — in that order, before doing anything else.

---

## Context

BlockHost is adding support for multiple blockchain backends (EVM, OPNet, Cardano). This exposed that libpam-web3 was doing too much — blockchain queries, socket IPC, chain-specific verification — all things that belong in the engine, not the auth module.

The new architecture eliminates all blockchain communication from libpam-web3. The engine's reconciler now owns the chain relationship and syncs NFT ownership to the VM's GECOS field. libpam-web3 becomes a pure signature/credential verification module with no chain awareness.

This should result in a **significantly smaller codebase**. The two existing auth paths (wallet mode: file lookup, NFT mode: blockchain query + GECOS/LDAP) converge into **one path**: verify the user's identity, then check if their wallet address exists in a GECOS field.

**Important:** Before implementing, carefully analyze the existing code paths. Double and triple check that the two separate paths already inside the codebase (wallet signature verification against a file, and NFT ownership check on-chain) can genuinely consolidate into one single path that checks a wallet string in the GECOS field. Trace every branch, every early return, every error path. The goal is confident simplification, not hasty deletion.

---

## What Changes

### 1. Remove the socket between PAM and web3-auth-svc

The Unix socket IPC (`/run/web3-auth/web3-auth.sock`) is eliminated entirely. The PAM module and web3-auth-svc no longer communicate directly. Their only shared interface is the filesystem: `/run/libpam-web3/pending/{session_id}.sig`.

**Remove:** `src/blockchain.rs` (socket client), socket server from web3-auth-svc, all of `web3-auth-svc/src/backends/`.

### 2. web3-auth-svc becomes HTTPS-only

web3-auth-svc retains only its HTTPS server role:
- `GET /` → serve signing page
- `GET /auth/pending/{session_id}` → return session JSON
- `POST /auth/callback/{session_id}` → write `.sig` file

All blockchain backend code is removed. The service doesn't query any chain and does NOT verify NFT ownership. It's a thin HTTPS server that serves a signing page and writes callback results to disk. Nothing more.

### 3. Every auth-svc writes `/run/libpam-web3/pending/{session_id}.sig`

The `.sig` file is the interface contract between any auth-svc and the PAM module. Content determines the verification path:

**EVM (raw signature):** The file contains a hex-encoded secp256k1 signature (65 bytes, `0x`-prefixed). This is what web3-auth-svc already writes today.

**OPNet (JSON):** A future `opnet-auth-svc` (not built in this PR) will write JSON:
```json
{"otp": "847293", "machine_id": "blockhost-001", "wallet_address": "bc1q..."}
```

### 4. PAM content-based path detection

When the PAM module reads the `.sig` file (or receives terminal input), it determines the path:

- **Try JSON parse.** If it succeeds and contains `otp`, `machine_id`, `wallet_address` keys → **OPNet path**
- **Otherwise** → treat as raw signature → **EVM path** (ecrecover)

Both paths end the same way: **check if the recovered/provided wallet address exists in a user's GECOS field.** This is the single consolidated auth path.

### 5. EVM path (existing, simplified)

1. Read signature from `.sig` file (or terminal paste — manual mode stays)
2. `ecrecover` to recover wallet address from signature + OTP message
3. Look up wallet address in `/etc/passwd` GECOS fields
4. Match found → authenticate as that user

The change: step 3 replaces both the old wallet-file lookup AND the old blockchain NFT query + token-to-GECOS mapping. The GECOS field now also contains the wallet address (e.g., `wallet=0x1234...,nft=5`). The `nft=TOKEN_ID` entry stays — it takes no space and may still be useful for reconciliation processes. The engine's reconciler populates both fields.

### 6. OPNet path (new, in PAM module only)

1. Parse JSON from `.sig` file
2. Validate OTP: check HMAC, check TTL, check machine_id matches this host
3. Look up `wallet_address` in `/etc/passwd` GECOS fields
4. Match found → authenticate as that user

No signature verification in this path. The OPNet auth-svc (built separately, not part of this PR) will serve a signing page where the user connects their wallet — proving control by the act of connecting. The auth-svc does NOT check NFT ownership; it simply records the wallet address alongside the OTP and machine_id. The OTP bridges the browser session to the terminal session. The GECOS lookup confirms the wallet is authorized for this VM.

### 7. Consolidate auth modes

The current two modes (`wallet` and `nft` in config) converge. Both wallet-file lookup and blockchain NFT lookup are replaced by GECOS wallet address lookup. The `[wallet]`, `[blockchain]`, and `[ldap]` config sections are all removed.

**Remove:** `src/wallet_auth.rs`, `src/blockchain.rs`, `src/ldap.rs`

**New config format:**
```toml
[machine]
id = "server-name"
secret_key = "0x..."

[auth]
signing_url = "https://..."
otp_length = 6
otp_ttl_seconds = 300
callback_enabled = true
callback_grace_seconds = 10

# No [wallet], [blockchain], or [ldap] sections.
# No mode selection — auth path is determined by .sig file content.
```

**GECOS format change:** `wallet=ADDRESS` is added alongside the existing `nft=TOKEN_ID`. Example:
```
johndoe:x:1001:1001:wallet=0x1234abcd...,nft=5:/home/johndoe:/bin/bash
```

The `nft=TOKEN_ID` field stays — it costs nothing and may be useful for reconciliation. The PAM module authenticates against `wallet=ADDRESS` only. The address format is chain-agnostic — could be `0x...` (EVM), `bc1q...` (Bitcoin/OPNet), or `addr1...` (Cardano). The PAM module doesn't care; it's a string comparison.

### 8. GECOS lookup consolidation

`src/passwd_lookup.rs` changes:
- Currently: parses `nft=TOKEN_ID`, normalizes hex/decimal, matches against a list of token IDs from blockchain
- New: parses `wallet=ADDRESS` from GECOS, does case-insensitive string comparison against the recovered/provided wallet address
- `nft=TOKEN_ID` parsing stays (field is preserved for reconciliation), but PAM authenticates on `wallet=ADDRESS` only
- Simpler logic, no token ID normalization needed for auth

---

## What Stays

- **OTP generation and verification** (`src/otp.rs`) — unchanged
- **Callback session management** (`src/callback.rs`) — unchanged, still writes `.json`, still polls for `.sig`
- **secp256k1 ecrecover** (`src/signature.rs`) — still needed for EVM path. Note: future chains (Cardano) use Ed25519. The architecture should not make it harder to add additional signature verification methods later, but do NOT implement Ed25519 now.
- **Manual paste mode** — user can still paste signature in terminal instead of using signing page
- **HTTPS callback flow** — browser signs, POSTs to auth-svc, auth-svc writes `.sig`, PAM picks it up
- **pam_web3_tool** — keypair generation, encryption operations (unchanged)
- **Signing page** — unchanged (EVM signing page still uses MetaMask)

---

## What Gets Removed

| File/Component | Why |
|---|---|
| `src/blockchain.rs` | Socket client to web3-auth-svc — no more socket |
| `src/wallet_auth.rs` | File-based wallet lookup — replaced by GECOS |
| `src/ldap.rs` | LDAP token/revocation lookup — replaced by GECOS |
| `web3-auth-svc/src/backends/` | Blockchain query backends — no chain queries |
| Socket server in web3-auth-svc | No more IPC — file interface only |
| `[wallet]` config section | No wallet file |
| `[blockchain]` config section | No blockchain config |
| `[ldap]` config section | No LDAP |
| `mode = "wallet" \| "nft"` | No mode selection — content-based detection |
| `nft` feature flag | Single build, no conditional compilation for blockchain |

---

## Verification Checklist

After implementation, verify:

1. **EVM callback flow works:** signing page → auth-svc HTTPS → `.sig` file → PAM ecrecover → GECOS match → auth success
2. **EVM manual flow works:** paste signature in terminal → PAM ecrecover → GECOS match → auth success
3. **OPNet PAM path works:** JSON `.sig` file with valid OTP + machine_id + wallet_address in GECOS → auth success
4. **OPNet PAM path rejects:** wrong OTP, wrong machine_id, wallet_address not in GECOS → auth denied
5. **No blockchain dependencies remain:** no RPC URLs, no contract addresses, no socket paths in the PAM module or web3-auth-svc
6. **Config simplified:** only `[machine]` and `[auth]` sections needed
7. **GECOS format:** `wallet=ADDRESS,nft=TOKEN_ID` — both fields parsed, auth uses wallet only
8. **Fail-secure:** any parsing error, missing file, or invalid content → deny access
9. **Codebase is smaller:** the removal of blockchain.rs, wallet_auth.rs, ldap.rs, and the web3-auth-svc backends should result in a net reduction of code

---

## Documentation Updates

Update `CLAUDE.md` and any `PROJECT.yaml` files to reflect:
- New single auth path (GECOS wallet lookup)
- Removed blockchain dependencies
- Removed socket IPC
- New `.sig` file content contract (raw signature or JSON)
- Simplified config format
- Extended GECOS format (`wallet=ADDRESS,nft=TOKEN_ID` — auth on wallet, nft preserved)
