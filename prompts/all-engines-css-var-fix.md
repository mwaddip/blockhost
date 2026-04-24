Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# Fix undefined CSS variables in blockchain.html

The installer's `base.html` palette defines: `--primary`, `--primary-dark`, `--secondary`, `--success`, `--error`, `--warning`, `--bg`, `--bg-card`, `--bg-input`, `--text`, `--text-muted`, `--border`.

Your `blockchain.html` uses four CSS variables that are NOT defined in this palette. They render as the CSS fallback (often transparent), which is a real visual bug:

| Used (wrong) | Should be |
|--------------|-----------|
| `var(--danger)` | `var(--error)` |
| `var(--bg-secondary)` | `var(--bg-input)` |
| `var(--text-primary)` | `var(--text)` |
| `var(--border-color)` | `var(--border)` |

Find every occurrence in `blockhost/engine_<chain>/templates/engine_<chain>/blockchain.html` (and any other template you ship) and replace with the correct variable from the palette above.

Also check inline `style="..."` attributes — most of these bugs hide there, e.g. `style="color: var(--danger);"` and `style="background: var(--bg-secondary);"`.

Single commit, no version bump. Push when done; main session will pull the pointer.

Verification: `grep -rE 'var\(--(danger|bg-secondary|text-primary|border-color)' blockhost/` should return zero matches afterwards.
