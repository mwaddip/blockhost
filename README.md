# BlockHost

**Autonomous VM hosting, driven by blockchain.**

BlockHost eliminates traditional hosting accounts entirely. Users purchase a subscription on-chain, receive an NFT containing their encrypted connection details, and authenticate to their VM by signing a message with their wallet. No usernames, no passwords, no control panels — just a wallet and a signature.

The entire lifecycle — from payment to VM provisioning to access credential delivery — happens without human intervention. The host operator installs from an ISO, walks through a wizard, and the system runs itself.

### What's different

- **Identity is a wallet.** No registration, no email, no 2FA. Your Ethereum wallet *is* your identity.
- **Access credentials live on-chain.** Connection details are encrypted into an NFT that only the owner's wallet can decrypt.
- **VMs provision themselves.** A blockchain event monitor detects purchases and triggers Terraform — no admin dashboard, no ticket system.
- **Authentication happens at the OS level.** A custom PAM module verifies wallet signatures at SSH login. No application-layer auth to bypass.
- **Admin access via on-chain commands.** Port knocking through blockchain transactions — no management ports exposed by default.

---

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/mwaddip/blockhost.git
cd blockhost

# Check and install build dependencies
./scripts/check-build-deps.sh --install

# Build packages and ISO
./scripts/build-iso.sh --build-deb

# Boot the ISO on bare metal or in a VM, then:
# 1. Wait for Debian auto-install + first boot (installs Proxmox VE)
# 2. Note the OTP code displayed on the console
# 3. Open the web wizard at the displayed URL
# 4. Connect your admin wallet, walk through the 7 wizard steps
# 5. Finalization deploys contracts, configures IPv6, builds VM template
# 6. System is live — send a subscription transaction to test
```

See [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) for the full build and installation reference.

---

## Admin Flow

The operator installs BlockHost once. After that, the system is autonomous.

```
                         INSTALL
                           |
                           v
                    +-------------+
                    |  Boot ISO   |
                    +------+------+
                           |
               Debian auto-install + Proxmox VE
                           |
                           v
                    +-------------+
                    | First Boot  |
                    |   Service   |
                    +------+------+
                           |
              Install packages, Foundry, Terraform
              Generate OTP, start web wizard
                           |
                           v
                    +-------------+
                    | Web Wizard  |---------> Connect admin wallet (MetaMask)
                    +------+------+
                           |
              1. Network    2. Storage     3. Blockchain
              4. Proxmox    5. IPv6        6. Admin Commands
                           7. Summary
                           |
                           v
                    +-------------+
                    | Finalization|
                    +------+------+
                           |
              Deploy contracts, configure Terraform,
              set up IPv6 tunnel, get TLS cert,
              mint admin NFT #0, build VM template
                           |
                           v
                    +-------------+
                    | System Live |
                    +-------------+
                           |
              blockhost-engine monitors the chain
              VMs auto-provision on subscription events
              Admin sends on-chain commands when needed
```

### Ongoing admin operations

```
Admin wallet                          BlockHost server
     |                                      |
     |-- send tx: knock command ----------->|
     |                                      |-- open firewall ports (temporary)
     |                                      |
     |-- SSH to management port ----------->|
     |                                      |-- verify, grant access
     |                                      |
     |-- (ports close after timeout) -------|
```

---

## User Flow

Users interact with the blockchain and their wallet. They never touch the server directly until SSH login.

```
User wallet                    Blockchain              BlockHost server
     |                              |                        |
     |-- purchase subscription ---->|                        |
     |   (send ETH + encrypted sig) |                        |
     |                              |-- SubscriptionPurchased event
     |                              |                        |
     |                              |    blockhost-engine <--|
     |                              |    detects event       |
     |                              |                        |
     |                              |    blockhost-provisioner
     |                              |    creates VM (Terraform)
     |                              |    adds IPv6 route     |
     |                              |                        |
     |                              |    encrypt connection  |
     |                              |    details with user's |
     |                              |    signature           |
     |                              |                        |
     |                              |<-- mint NFT -----------|
     |                              |    (encrypted access   |
     |                              |     credentials inside)|
     |                              |                        |
     |-- visit signup page -------->|                        |
     |   connect wallet             |                        |
     |   sign decrypt message       |                        |
     |<- receive connection details |                        |
     |   (hostname, port, user)     |                        |
     |                              |                        |
     |-- SSH to VM (IPv6) -------->-|----------------------->|
     |   sign OTP challenge         |                        |
     |<- shell access --------------|------------------------|
```

### Encryption scheme

```
Purchase:   user signs message  -->  signature sent encrypted (ECIES)
Server:     decrypts signature  -->  keccak256(signature) = AES key
            encrypts connection details with AES key
            stores ciphertext in NFT (userEncrypted field)

Decrypt:    user re-signs same message  -->  derives same AES key
            decrypts connection details from NFT
```

The server never stores plaintext credentials. The user's wallet signature is both the proof of identity and the decryption key.

---

## Infrastructure

```
+------------------------------------------------------------------+
|                        Proxmox VE Host                           |
|                                                                  |
|  +-------------------+     +-------------------+                 |
|  | blockhost-engine  |     | blockhost-        |                 |
|  | (Node.js)         |     | provisioner       |                 |
|  |                   |     | (Python)          |                 |
|  | - monitors chain  |---->| - vm-generator.py |                 |
|  | - detects events  |     | - mint_nft.py     |                 |
|  | - triggers        |     | - vm-gc.py        |                 |
|  |   provisioning    |     | - Terraform       |                 |
|  +-------------------+     +--------+----------+                 |
|           |                         |                            |
|           |  +------------------+   |   +--------------------+   |
|           |  | blockhost-common |   |   | libpam-web3-tools  |   |
|           |  | (Python)         |   |   | (Rust)             |   |
|           +->| - config loading |<--+   | - pam_web3_tool    |   |
|              | - VM database    |       | - encrypt/decrypt  |   |
|              | - shared types   |       | - signing page gen |   |
|              +------------------+       +--------------------+   |
|                                                                  |
|  +---------------------------+    +---------------------------+  |
|  | blockhost-broker-client   |    | blockhost-signup          |  |
|  | (Python)                  |    | (static HTML)             |  |
|  | - requests IPv6 prefix    |    | - served on port 443      |  |
|  | - configures WireGuard    |    | - NFT decrypt UI          |  |
|  +------------+--------------+    +---------------------------+  |
|               |                                                  |
+---------------|--------------------------------------------------+
                |
        WireGuard tunnel
                |
     +----------v-----------+         +------------------------+
     |   IPv6 Broker         |         |   Blockchain (Sepolia/ |
     |   (NDP proxy)         |         |   Mainnet/Polygon)     |
     |   - assigns /120      |         |                        |
     |   - proxies NDP       |         | - AccessCredentialNFT  |
     |   - routes traffic    |         | - BlockHostSubscription|
     +----------+------------+         +------------------------+
                |                                  ^
           IPv6 internet                           |
                |                           User wallet
         +------v------+                   (MetaMask etc.)
         |  User's VM  |
         |  (Debian)   |
         |             |
         | libpam-web3 |  <-- PAM module: verifies wallet
         |             |      signatures at SSH login
         +-------------+
```

### Data flow between components

| From | To | What |
|------|----|------|
| Blockchain | blockhost-engine | `SubscriptionPurchased` event (wallet, signature, amount) |
| blockhost-engine | blockhost-provisioner | `blockhost-vm-create --owner-wallet --user-signature --public-secret` |
| blockhost-provisioner | Terraform/Proxmox | VM definition (`.tf.json`), `terraform apply` |
| blockhost-provisioner | blockhost-common | `register_vm()` — stores VM record in database |
| blockhost-provisioner | libpam-web3-tools | `pam_web3_tool encrypt-symmetric` — encrypts connection details |
| blockhost-provisioner | Blockchain | `mint()` — NFT with encrypted data to user's wallet |
| blockhost-broker-client | IPv6 Broker | WireGuard handshake, prefix allocation |
| Proxmox host | VMs | IPv6 routing: `/128` host routes via `vmbr0` bridge |
| User browser | Blockchain | Read NFT, decrypt connection details |
| User SSH client | VM (libpam-web3) | Wallet signature verification at PAM level |

### Configuration flow

```
Web wizard  --->  /etc/blockhost/*.yaml, *.json, *.key
                         |
         +---------------+---------------+
         |               |               |
    blockhost-       blockhost-      blockhost-
    engine           provisioner     broker-client
    reads:           reads:          reads:
    - web3-defaults  - db.yaml       - broker-allocation
    - blockhost.yaml - web3-defaults - deployer.key
    - admin-commands - blockhost.yaml
```

---

## VM Lifecycle

```
SubscriptionPurchased event
         |
         v
   VM Provisioned (active)
         |
   subscription expires
         |
         v
   VM Suspended (data preserved)
         |
    +----+----+
    |         |
 grace     subscription
 period    renewed
 expires      |
    |         v
    v    VM Resumed (active)
 VM Destroyed
```

Default grace period: 7 days (configurable).

---

## Components

### blockhost-engine
Node.js service that monitors the blockchain for `SubscriptionPurchased` events. When a purchase is detected, it decrypts the user's signature (sent encrypted via ECIES), calls the provisioner to create a VM, encrypts connection details into an NFT, and mints it to the user's wallet. Also generates the signup page HTML and handles admin command processing.

### blockhost-provisioner
Python scripts for VM lifecycle management. `vm-generator.py` allocates IPs/VMIDs, generates Terraform configs, runs `terraform apply`, adds IPv6 host routes, and triggers NFT minting. `vm-gc.py` handles garbage collection of expired VMs (two-phase: suspend then destroy). Uses the bpg/proxmox Terraform provider.

### blockhost-common
Shared Python package providing config file loading (`blockhost.config`) and the VM database abstraction (`blockhost.vm_db`). All other Python components depend on this. The database tracks VM records, IP allocations, and NFT token reservations.

### libpam-web3
Two packages from one repo. **libpam-web3** is a Rust PAM module installed in VMs — it intercepts SSH login and requires a valid wallet signature instead of a password. **libpam-web3-tools** is installed on the host — provides `pam_web3_tool` (symmetric encryption/decryption) and the signing page generator used by the engine.

### blockhost-broker-client
Python client for the IPv6 tunnel broker network. Requests a `/120` prefix allocation from the broker's on-chain registry, configures a WireGuard tunnel, and persists the allocation. The broker provides NDP proxy for the assigned prefix, giving each VM a publicly routable IPv6 address.

### installer (this repo)
Flask web application that runs during first boot. Guides the operator through network, storage, blockchain, Proxmox, IPv6, and admin configuration. The finalization step deploys contracts, sets up Terraform, configures the IPv6 tunnel, gets a TLS certificate, mints the admin NFT, and builds the VM template. Includes a post-install validation module for testing.

---

## License

TBD
