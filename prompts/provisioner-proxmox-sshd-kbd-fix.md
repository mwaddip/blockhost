# Proxmox Provisioner: Fix KbdInteractiveAuthentication in VM template

Same issue as the libvirt provisioner. Newer Debian 12 cloud images have `KbdInteractiveAuthentication no` uncommented in the main `/etc/ssh/sshd_config`. This overrides the `sshd_config.d/` snippets if OpenSSH processes the main file first (first-match-wins).

In `scripts/build-template.sh`, add a `virt-customize` step that comments out the conflicting line:

```bash
--run-command 'sed -i "s/^KbdInteractiveAuthentication no/#KbdInteractiveAuthentication no  # overridden by sshd_config.d/" /etc/ssh/sshd_config'
```

Also ensure the Include directive exists at the top:

```bash
--run-command 'grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config'
```

Add these alongside the existing virt-customize arguments for SSH configuration.
