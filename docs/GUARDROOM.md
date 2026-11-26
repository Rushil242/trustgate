# The guard room

The guard room runs TrustGate as its own process, `trustgated`, and in
production as its own OS user. The hook your agent runs becomes a small client
that asks the daemon and prints the answer. The policy, the log and the
signing key live in a folder the agent's user cannot open.

## Why

When the gate runs as the same user as the agent, the agent's ordinary tools
can reach the gate's own files: the policy, the log, the hook script. Rules
and pins make that harder. Only a separate OS user makes it impossible, because
then the operating system refuses the write, however the command is spelled.

## How it fits together

```
agent (your user)                      trustgated (_trustgate)
  Claude Code                             policy.yaml   (0600)
    └ hook.py ── agent.sock ───────────▶   audit.jsonl   (signed, one writer)
      (root-owned, in managed settings)    machine.key   (0600)
you, with sudo ─ admin.sock (0600) ────▶ approve, install a policy
```

* `agent.sock` answers `decide`, `observe` and `status`. Anyone can connect.
* `admin.sock` is mode 0600, so only the daemon's user and root can connect.
  Approvals and policy changes go through it, and both are written to the log
  with the OS user the kernel reports.
* Every entry is signed with the machine key (see [LEDGER-FORMAT.md](LEDGER-FORMAT.md)).
* Every decision records `protection_level`: 1 when the caller was a different
  OS user from the daemon, 0 when it was the same user (dev mode). The evidence
  pack prints the split and warns about level 0.
* If the daemon does not answer, the hook refuses (`deny`). It never allows.

## Try it as your own user (dev mode, level 0)

```bash
trustgate guardroom serve &                  # state and sockets in ~/.trustgate/guardroom
trustgate guardroom install-hook             # writes .claude/hooks/trustgate-guardroom.py
trustgate guardroom status
```

Add the settings it prints to `.claude/settings.json`. Dev mode runs the same
code, but your user can still reach the daemon's files. Use it to try things,
not to protect anything.

## Install as its own OS user (level 1)

Needs root, and a Python 3.11+ owned by root (python.org installer on macOS,
your package manager on Linux). Homebrew, pyenv and uv Pythons belong to your
user, so the installer refuses them: the agent could change them.

```bash
deploy/install-guardroom.sh --dry-run        # read every step first
sudo deploy/install-guardroom.sh
```

It creates the `_trustgate` user, the folders, a root-owned venv in
`/usr/local/lib/trustgate`, the hook, and a Claude Code managed-settings
drop-in that turns on `allowManagedHooksOnly` and disables bypass mode. Then
it starts the daemon and checks that it answers you at level 1.

Day to day:

```bash
sudo trustgate-admin guardroom resolve --prod REQUEST_ID approved --approver "Your Name"
sudo trustgate-admin guardroom policy-install --prod --policy new.yaml --by "Your Name"
trustgate-admin guardroom status --prod      # includes the public key
```

Set `Defaults timestamp_timeout=0` with `visudo`, so sudo asks for your
password every time and an agent cannot reuse a recent one.

## What it does not do yet

* The Cloud does not check signatures yet; machines will log in with their
  key next.
* The pack checks signatures only when given the public key
  (`trustgate verify-audit --pubkey`).
* A rewrite of the not-yet-synced tail is still possible for someone with
  root. Witness receipts close that.
* Root can do anything. The guard room protects against the agent, not
  against the machine's administrator.
