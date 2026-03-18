---
layout: home
hero:
  name: BlockHost
  text: Autonomous VM hosting, driven by blockchain.
  tagline: Boot an ISO. Walk through a wizard. The system runs itself.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/what-is-blockhost
    - theme: alt
      text: View on GitHub
      link: https://github.com/mwaddip/blockhost
features:
  - title: No Accounts
    details: Your crypto wallet is your identity. No registration, no email, no 2FA. Works with Ethereum, OPNet (Bitcoin L1), and Cardano.
  - title: No Control Panels
    details: Subscriptions, credentials, and admin commands all live on-chain. The server watches the blockchain and acts on what it sees.
  - title: No Manual Provisioning
    details: New purchase detected on-chain → VM spins up → NFT minted with encrypted credentials → user connects. Fully automated.
  - title: OS-Level Auth
    details: A custom PAM module verifies wallet signatures at SSH login. Not an app-layer wrapper — it's in the authentication stack itself.
  - title: Pluggable Everything
    details: Swap the blockchain engine (EVM, OPNet, Cardano) or the hypervisor (Proxmox, libvirt) without changing anything else.
  - title: One ISO
    details: Boots on bare metal, auto-installs Debian, deploys packages, launches a setup wizard. From hardware to live system in under 10 minutes.
---
