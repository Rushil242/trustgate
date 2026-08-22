## What this changes

<!-- And why. The reasoning is the part a future reader cannot reconstruct. -->

## Checks

- [ ] `uv run pytest`
- [ ] `uv run ruff check .`
- [ ] `uv run trustgate test` — zero missed attacks, zero false positives

## If this adds or tightens a rule

- [ ] Added an **attack payload** it catches
- [ ] Added a **control payload** — a legitimate command a naive version of this
      rule would wrongly flag

## If this fixes a bypass

- [ ] The bypass is now a permanent regression case in `redteam/`
- [ ] Reported privately first (see [SECURITY.md](../SECURITY.md))
