# Audit Status

BlockHost has not been formally audited by a third-party security firm.

## Internal Review

A comprehensive security review was conducted across the full codebase (main repo + all submodules) in March 2026. Findings were identified and fixed:

| Finding | Severity | Status |
|---------|----------|--------|
| SSRF via unvalidated RPC URL (OPNet engine) | High | Fixed |
| SSRF via weakly validated RPC URL (EVM engine) | Medium | Fixed |
| Symlink path traversal in virt-customize | High | Fixed |
| Symlink path traversal in qm importdisk | Medium | Fixed |
| Deployer secrets in setup-state.json | High | Fixed |

## Positive Findings

- No `shell=True` in any subprocess call across the entire codebase
- No `eval()`, `exec()`, `pickle`, or unsafe YAML loading
- Jinja2 templates use `render_template()` throughout (no `render_template_string()`)
- OTP system has proper entropy, timing, lockout, and one-time-use semantics
- Root agent socket permissions are correct (0660 root:blockhost)
- Admin panel uses strict regex validation and one-time challenge codes

## Recommendation

Review the code before deploying with real assets. The security architecture is sound (privilege separation, encrypted credentials, wallet auth), but no code is proven secure without independent verification.

If you'd like to contribute a security review, see [Contributing](/developer/contributing).
