# blockhost-provisioner-proxmox: Cloud-Init Variables for libpam-web3 Refactor

**Branch:** `feature/opnet` (create from current master)

**Start by reading:** `SPECIAL.md`, `CLAUDE.md` — in that order, before doing anything else.

**Pull updated facts submodule:** The interface contracts have already been updated on `feature/opnet`. Before starting work:
```bash
cd facts && git fetch origin && git checkout feature/opnet && cd ..
```

---

## Context

libpam-web3 has been refactored. The PAM module no longer queries any blockchain — it verifies signatures locally and checks wallet addresses against GECOS fields. The cloud-init template (`nft-auth.yaml` in blockhost-common) is being updated separately to match. This provisioner needs to pass the right variables to the updated template.

---

## What Changes

### 1. Cloud-init variable dict in `scripts/vm-generator.py`

**Location:** lines 478-493 (the `variables = {` dict)

**Remove these three lines:**
```python
"CHAIN_ID": str(web3_config["blockchain"]["chain_id"]),
"NFT_CONTRACT": web3_config["blockchain"]["nft_contract"],
"RPC_URL": web3_config["blockchain"]["rpc_url"],
```

**Add this line:**
```python
"WALLET_ADDRESS": args.owner_wallet,
```

The template no longer needs blockchain config — the PAM module doesn't talk to any chain. The wallet address is now written to the VM's GECOS field by cloud-init.

**Keep:** `NFT_TOKEN_ID` (still in GECOS for reconciliation), and everything else.

### 2. Remove hardcoded EVM address validation

**Location:** line 338

```python
if args.owner_wallet and not re.match(r'^0x[0-9a-fA-F]{40}$', args.owner_wallet):
    parser.error("--owner-wallet must be a valid Ethereum address (0x followed by 40 hex characters)")
```

Remove this validation entirely. Wallet addresses are now chain-agnostic — could be `0x...` (EVM), `bc1q...` (Bitcoin/OPNet), or `addr1...` (Cardano). The provisioner should not validate address format. If the engine manifest provides `constraints.address_pattern`, the caller (engine monitor) has already validated it. The provisioner just passes it through.

### 3. New provisioner verb: `update-gecos`

The engine reconciler now detects NFT ownership transfers and needs to update the VM's GECOS field when the owner changes. This requires a new provisioner command.

**Add to `provisioner.json`:**
```json
"update-gecos": "blockhost-vm-update-gecos"
```

**New script: `scripts/vm-update-gecos.sh`** (or `.py`)

```
blockhost-vm-update-gecos <vm-name> <wallet-address> --nft-id <token_id>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `vm-name` | yes | VM name (e.g., `blockhost-001`) |
| `wallet-address` | yes | New owner's wallet address |
| `--nft-id` | yes | NFT token ID (integer) |

**What it does:**
1. Look up the VM in the database to get the VMID and username
2. Construct the new GECOS string: `wallet=<wallet-address>,nft=<nft_id>`
3. Execute `usermod -c "<gecos>" <username>` on the VM via QEMU guest agent (`qm guest exec <vmid>`)
4. Exit 0 on success, 1 on failure

**Important:**
- The VM must be running and the QEMU guest agent must be responsive
- If the VM is stopped/suspended, exit 1 with a clear error — the reconciler will retry next cycle
- The username is always the one set during VM creation (stored in vms.json or derivable from the cloud-init config)
- This command goes through the root agent since `qm guest exec` requires root

**Root agent action:** You may need a new root agent action in `root-agent-actions/qm.py` for guest exec, or use the existing `virt-customize` action pattern. Check what's available before implementing.

### 4. No other changes

The rest of vm-generator.py stays the same. The `--owner-wallet` argument, NFT token reservation, database registration, and JSON output are all unchanged.

---

## Verification

After the change:
1. The variables dict has `WALLET_ADDRESS` and does NOT have `CHAIN_ID`, `NFT_CONTRACT`, or `RPC_URL`
2. No hardcoded `0x[0-9a-fA-F]{40}` pattern remains
3. `NFT_TOKEN_ID` is still present in the variables dict
4. The script still reads `web3_config["auth"]` for OTP settings — that stays
5. `provisioner.json` has the `update-gecos` verb
6. `blockhost-vm-update-gecos <vm-name> <wallet>` works on a running VM with guest agent

---

## Documentation

Update `PROJECT.yaml` and `CLAUDE.md` if they reference the removed blockchain variables or the EVM address validation. Add the new `update-gecos` verb to the command documentation.
