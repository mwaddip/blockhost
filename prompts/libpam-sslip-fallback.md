# Signing URL: DNS-based FQDN fallback to sslip.io

## Context

The PAM module derives the signing URL from the VM's FQDN (`hostname -f`) and the deterministic port. If the FQDN is a real internet domain, this works. But if it's a local hostname like `blockhost.local` or a bare name without DNS, the signing URL won't resolve from the user's browser and wallet auth fails silently.

## Change

When constructing the signing URL, check if the FQDN actually resolves in DNS. If it doesn't, fall back to `<ip>.sslip.io` which always resolves to the embedded IP address.

### Logic

```
fqdn = hostname -f
if dig +short "$fqdn" | grep -q .; then
    host = fqdn
else
    # Prefer public IPv6 (broker-allocated), fall back to IPv4
    ipv6 = first global-scope IPv6 address (not fe80::, not fd::)
    if ipv6 exists:
        host = "<ipv6>.sslip.io"    # dashes for colons: 2001-db8--1.sslip.io
    else:
        ipv4 = primary IPv4 address
        host = "<ipv4>.sslip.io"    # dots as-is: 192.168.1.1.sslip.io
    fi
fi
signing_url = https://{host}:{port}/sign
```

The `dig +short "$fqdn" | grep -q .` pattern is the entire condition — if DNS returns anything, the domain is real. If it returns nothing, fall back. No TLD lists, no regex, no assumptions. DNS is the authority.

The IPv4 fallback makes this work on non-BlockHost instances too — any VM with a public IPv4 and no FQDN gets a working signing URL via sslip.io without any DNS configuration.

### Implementation notes

- This logic lives wherever the signing URL is currently constructed (PAM module or auth-svc — you know best)
- If it's in Rust, you can shell out to `dig` or use a native DNS resolution attempt — whatever's simpler. The check only runs once per auth attempt so performance doesn't matter
- `dig` is in the `dnsutils` package — if it's not guaranteed to be on the VM, a native DNS resolution attempt that returns NXDOMAIN works the same way
- sslip.io formats: IPv4 dotted (`192.168.1.1.sslip.io`), IPv6 dashed (`2001-db8--1.sslip.io`)
- This only affects the URL shown to / used by the user's browser. The PAM module itself still talks to auth-svc on localhost
