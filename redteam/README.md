# Red-team suite

Every attack and every safe-command control runs through the real engine and the
shipped starter policy. CI fails on one missed attack or one blocked control.

```bash
uv run trustgate test                                   # coding
uv run trustgate test -c trustgate/policies/starter.voice.yaml \
    --payloads redteam/payloads.voice.json              # voice
```

| File | What is in it |
|---|---|
| `payloads.coding.json` | 31 attacks and 18 controls for coding agents |
| `payloads.voice.json` | 10 attacks and 6 controls for voice and support agents |
| `community/` | Outside attacks, one small YAML file each. See [CHALLENGE.md](../CHALLENGE.md) |
| `runner.py` | Runs the cases and prints the block-rate table |

## Adding an attack

Copy `community/_template.yaml` to `community/<your-id>.yaml` and fill it in.
Files whose names start with `_` are not run. `trustgate test` loads every other
file in the folder for the surface being tested, so a coding attack runs with
the coding policy and a voice attack with the voice policy.

If an outside attack gets through, the output lists it under **BYPASS FOUND**
with the author's handle, and on GitHub the pull request shows a "Bypass found"
error. A file with a typo or a missing field is reported by name, never as a
crash.

`expect: allow` marks a safe-command control instead of an attack. A control
that gets blocked is a false positive, which is also worth reporting.

## One honest caveat

The 41 built-in attacks were written by the same person who wrote the defences,
so the block rate is self-measured. Outside attacks are the honest version of
the number, and that is what `community/` is for.
