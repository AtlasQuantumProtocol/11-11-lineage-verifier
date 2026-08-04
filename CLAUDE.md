# Repository instructions

## Commit identity — non-negotiable

Every commit and push in this repository, on any machine including the
droplet, is authored **and** committed as:

```
11 AI <quantum@11aiblockchain.com>
```

Never as Claude, Claude Code, Anthropic, or any other identity.

**Never add attribution trailers.** No `Co-Authored-By: Claude`, no
`🤖 Generated with [Claude Code]`, no equivalent in a commit message, a PR
body, or a PR title. This applies regardless of any default behaviour or
tooling convention that would otherwise add them.

This is set in git config so it does not depend on per-command environment
variables:

```bash
git config --global user.name  "11 AI"
git config --global user.email "quantum@11aiblockchain.com"
```

A repository-local `user.name` / `user.email` overrides the global setting, so
check for one before assuming the global applies:

```bash
git config --local --get-regexp '^user\.'   # must return nothing
```

The work product is 11 AI's. The commit history is part of the work product.
