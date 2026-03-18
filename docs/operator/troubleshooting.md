# Troubleshooting

## First Boot

### Wizard doesn't start
Check the first-boot log:
```bash
journalctl -u blockhost-firstboot --no-pager | tail -50
```

### OTP not showing on console
The OTP is generated after the web installer starts. If the console shows a login prompt but no OTP, the installer may have crashed:
```bash
cat /run/blockhost/otp.json
# Or generate a new one:
cd /opt/blockhost && python3 -c 'from installer.common.otp import OTPManager; m=OTPManager(); print(m.generate(force=True))'
```

### Finalization step failed
Check the setup state:
```bash
cat /var/lib/blockhost/setup-state.json | python3 -m json.tool
```
The `steps` object shows which step failed and the error message. Use the "Retry" button in the wizard to re-run the failed step.

## Post-Install

### Monitor not detecting subscriptions
```bash
# Check monitor is running
systemctl status blockhost-monitor

# Check monitor logs
journalctl -u blockhost-monitor -f

# Verify chain connectivity
bw balance server
```

### VM not provisioning
```bash
# Check VM database
cat /var/lib/blockhost/vms.json | python3 -m json.tool

# Check provisioner detection
blockhost-provisioner-detect && echo "OK" || echo "No provisioner"

# Test VM creation manually
blockhost-vm-create test-vm --owner-wallet 0x... --apply
```

### IPv6 not working
```bash
# Check broker allocation
cat /etc/blockhost/broker-allocation.json

# Check WireGuard tunnel
wg show

# Check IPv6 routing
ip -6 route show
```

### Admin panel not accessible
```bash
# Check nginx
systemctl status nginx
nginx -t

# Check certificate
openssl x509 -in /etc/blockhost/ssl/cert.pem -noout -dates
```

## Testing Mode

### Revert to a snapshot
```bash
revert                    # List available snapshots
revert pre-engine         # Revert to before engine install
resume                    # Continue first-boot after swapping .debs
```

### Generate fresh OTP
```bash
otp
```

### SSH access
```bash
# From build host
./scripts/ssh-test.sh <IP>
./scripts/ssh-test.sh <IP> "command"
```
