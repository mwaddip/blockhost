# blockhost-provisioner-libvirt: Cloud-Init Variables for libpam-web3 Refactor

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

### 1. Cloud-init variable dict in `scripts/vm-create.py`

**Location:** lines 441-456 (the `variables = {` dict)

**Remove these three lines:**
```python
"CHAIN_ID": str(blockchain.get("chain_id", "")),
"NFT_CONTRACT": blockchain.get("nft_contract", ""),
"RPC_URL": blockchain.get("rpc_url", ""),
```

**Add this line:**
```python
"WALLET_ADDRESS": args.owner_wallet,
```

The template no longer needs blockchain config — the PAM module doesn't talk to any chain. The wallet address is now written to the VM's GECOS field by cloud-init.

**Keep:** `NFT_TOKEN_ID` (still in GECOS for reconciliation), and everything else.

### 2. Clean up blockchain config loading if now unused

The `blockchain = web3_config.get("blockchain", {})` variable (and its extraction from `web3_config`) was used solely to populate those three removed template variables. If nothing else in the script uses `blockchain`, the variable can be removed. Check before deleting — the `auth` section (`web3_config["auth"]`) is still needed for OTP settings.

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
1. Look up the VM in the database to get the domain name and username
2. Construct the new GECOS string: `wallet=<wallet-address>,nft=<nft_id>`
3. Execute `usermod -c "<gecos>" <username>` on the VM via QEMU guest agent (`virsh qemu-agent-command`)
4. Exit 0 on success, 1 on failure

**Important:**
- The VM must be running and the QEMU guest agent must be responsive
- If the VM is stopped/suspended, exit 1 with a clear error — the reconciler will retry next cycle
- The username is always the one set during VM creation (stored in vms.json or derivable from the cloud-init config)
- This command goes through the root agent since `virsh` commands require appropriate permissions

**Root agent action:** You may need a new root agent action in `root-agent-actions/virsh.py` for guest exec. Check what's available before implementing.

### 4. No other changes

The rest of vm-create.py stays the same. The `--owner-wallet` argument, NFT token reservation, database registration, and everything else are unchanged.

---

## Verification

After the change:
1. The variables dict has `WALLET_ADDRESS` and does NOT have `CHAIN_ID`, `NFT_CONTRACT`, or `RPC_URL`
2. `NFT_TOKEN_ID` is still present in the variables dict
3. The script still reads `web3_config["auth"]` for OTP settings — that stays
4. No dangling references to the `blockchain` dict remain (unless used elsewhere)
5. `provisioner.json` has the `update-gecos` verb
6. `blockhost-vm-update-gecos <vm-name> <wallet>` works on a running VM with guest agent

---

## Documentation

Update `PROJECT.yaml` and `CLAUDE.md` if they reference the removed blockchain variables. Add the new `update-gecos` verb to the command documentation.
