# Libvirt Provisioner: Fix KbdInteractiveAuthentication in VM template

Newer Debian 12 cloud images have `KbdInteractiveAuthentication no` uncommented at line 62 of `/etc/ssh/sshd_config`. OpenSSH uses first-match-wins — if the `Include /etc/ssh/sshd_config.d/*.conf` directive is at the top of the file, the `.d/` files should win. But if the cloud image moved or removed the `Include`, the main config's `no` takes precedence and PAM-based web3 auth never works (SSH shows password prompt instead of wallet signing prompt).

In `scripts/build-template.sh`, add a `virt-customize` step that comments out the conflicting line in the main `sshd_config`:

```bash
--run-command 'sed -i "s/^KbdInteractiveAuthentication no/#KbdInteractiveAuthentication no  # overridden by sshd_config.d/" /etc/ssh/sshd_config'
```

Add this alongside the existing `--write` for `50-blockhost.conf`. Belt and suspenders — the `.d/` file sets it correctly, and the main config can't override it.

Also ensure the `Include /etc/ssh/sshd_config.d/*.conf` line exists at the top of `sshd_config`:

```bash
--run-command 'grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config'
```
