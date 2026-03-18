# Accessing Your VM

## Decrypting your credentials

After purchasing a subscription, your NFT contains encrypted SSH credentials. To decrypt:

1. Visit the operator's signup page
2. Connect the same wallet that holds the NFT
3. Sign the same message you signed during purchase
4. Your decrypted connection details appear: IP address, username, and password

## Connecting via SSH

```bash
ssh user@<your-vm-ipv6-address>
```

On first connection, the VM presents a signing page in your browser. This is the wallet authentication step:

1. Your SSH client connects
2. The PAM module on the VM prompts for authentication
3. A signing page opens at `https://<vm-ip>:8443`
4. Connect your wallet and sign — the page auto-fills the session details
5. SSH session is authenticated

**No passwords to remember.** Your wallet signature is your login credential. The PAM module verifies it against the wallet address in the VM's GECOS field.

## What if I transfer my NFT?

If you transfer the NFT to another wallet:
- The system detects the ownership change automatically
- The VM's authentication is updated to accept the new wallet
- The previous owner can no longer log in
- The new owner signs in with their wallet

This is how VM access is transferred — no admin intervention, no ticket system. The NFT is the key.

## Troubleshooting

**"Wallet not recognized"** — make sure you're connecting with the wallet that holds the NFT. The PAM module checks the GECOS field, which contains the NFT owner's address.

**Signing page doesn't load** — the auth service runs on port 8443 with a self-signed certificate. Your browser may show a security warning — accept it (the connection is encrypted, the cert is just not from a public CA).

**Connection refused** — the VM may be suspended (subscription expired). Check the signup page for your subscription status.
