"""The evidence pack: the ledger turned into something you can hand someone.

A hash-chained JSONL file is the right way to *store* what an agent did. It is
the wrong thing to send to a customer's security team, who want to know which
controls were in force, what got stopped, who approved the rest, and whether
the record can be trusted. This module answers those four questions from the
data already on disk.

Two rules govern what goes in.

**Nothing is computed that the ledger does not already contain.** No estimates,
no "approximately", no inferred coverage. Everything here is a count or a quote
from a line that was written when the action happened.

**The pack states its own limits.** A report that only lists what went well is
not evidence, it is marketing, and any reviewer worth the name will treat it
that way. Unanswered escalations, outcomes we could not classify and a broken
hash chain are all reported at the top rather than left out.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from trustgate.core.audit import AuditLedger, entry_time
from trustgate.core.constitution import Constitution

# What a reviewer's questionnaire tends to ask, and the part of the ledger that
# answers it. Deliberately conservative: each row claims only what the data
# supports, and rows we cannot evidence are marked as such rather than dropped.
QUESTION_MAP: tuple[tuple[str, str, str], ...] = (
    (
        "What prevents the AI system from taking unauthorised actions?",
        "partial",
        "Every action is checked against the written policy before it runs, outside "
        "the model. Actions that match a rule are stopped or sent to a person, and "
        "are listed in this pack. An action spelled in a way no rule matches is "
        "allowed, so this is evidenced for actions that matched a rule.",
    ),
    (
        "Are AI actions logged, and for how long?",
        "evidenced",
        "Every decision is logged, including the allowed ones. Retention is set by "
        "wherever the ledger file is kept, and is stated in the summary.",
    ),
    (
        "Is there human approval for high-risk actions?",
        "evidenced",
        "Actions matching a rule that requires approval are escalated. Each "
        "escalation and its answer, including who answered, is listed in this pack.",
    ),
    (
        "Can you prove the log has not been altered?",
        "evidenced",
        "Each entry carries the hash of the one before it. Editing or removing a "
        "past entry breaks every hash after it. The check result is in the summary.",
    ),
    (
        "How do you stop the AI reading credentials or secrets?",
        "evidenced",
        "A dedicated check inspects the action for secret file paths and literal "
        "credentials, and nothing reaches the log unredacted.",
    ),
    (
        "How do you handle prompt injection?",
        "partial",
        "Content the agent ingests is inspected, and a suspicious result routes to "
        "a human rather than being blocked outright. This reduces the risk; it does "
        "not eliminate it, and no honest vendor claims otherwise.",
    ),
    (
        "Who can change the policy, and is that change recorded?",
        "partial",
        "Every decision records the hash of the policy file it was made under, so "
        "a change shows up in the policy history table with its time. This pack "
        "does not show who made the change.",
    ),
)

NO_POLICY_CHANGES = '<tr><td colspan="6">No recorded policy changes in this period.</td></tr>'
NOTHING_BLOCKED = '<tr><td colspan="4">Nothing was blocked in this period.</td></tr>'
NOTHING_ESCALATED = '<tr><td colspan="6">Nothing was escalated in this period.</td></tr>'

# What this pack does not prove. Printed inside the document, not in a footnote.
LIMITS: tuple[str, ...] = (
    "This covers actions that were routed through TrustGate. An agent path with "
    "no adapter installed is not represented here at all.",
    "The log is tamper evident, not tamper proof. It detects modification and "
    "reordering. It cannot stop someone with disk access deleting the file, and a "
    "file that was truncated at the end still verifies.",
    "Approvals marked 'recorded afterwards' were made by a reviewer after the "
    "action had already run. They are a judgment, not an authorisation.",
    "Outcomes marked 'unknown' are escalations where the surface did not tell us "
    "clearly what the human decided. They are reported rather than assumed.",
    "In a pack made from one machine's own ledger, every name in it was written by "
    "that machine. Only a fleet pack from TrustGate Cloud shows a reviewer's name "
    "that the machine did not write itself.",
)


@dataclass
class EvidencePack:
    """Everything the report needs, already counted."""

    generated_at: float
    period_from: float | None
    period_to: float | None
    ledger_path: str

    chain_ok: bool = False
    chain_detail: str = ""
    chain_entries: int = 0

    constitution_name: str = ""
    principles: list[dict[str, str]] = field(default_factory=list)

    decisions: int = 0
    effects: Counter = field(default_factory=Counter)
    surfaces: Counter = field(default_factory=Counter)

    blocked: list[dict[str, Any]] = field(default_factory=list)
    escalations: list[dict[str, Any]] = field(default_factory=list)

    report_policy_digest: str = ""
    """Hash of the policy file loaded when the report was made."""

    policy_history: list[dict[str, Any]] = field(default_factory=list)
    """Each distinct policy the decisions in this period were made under, in
    the order it first appeared: digest, first and last time, decision count."""

    warnings: list[str] = field(default_factory=list)
    """Plain sentences printed at the top under "Read this first"."""

    policy_changes: list[dict[str, Any]] = field(default_factory=list)
    """`policy_change` entries in the period: when, old and new hash, who."""

    protection: Counter = field(default_factory=Counter)
    """Decisions by protection level: 1 separate OS user, 0 same user, None unknown."""

    @property
    def policy_matches_report(self) -> bool:
        """True when every decision was made under the policy shown below."""
        used = {p["digest"] for p in self.policy_history}
        return bool(self.report_policy_digest) and used == {self.report_policy_digest}

    @property
    def policy_heading(self) -> str:
        if self.policy_matches_report:
            return "Controls in force"
        return "Policy file at report time"

    @property
    def answered(self) -> int:
        return sum(1 for e in self.escalations if e.get("resolution"))

    @property
    def open_escalations(self) -> list[dict[str, Any]]:
        return [e for e in self.escalations if not e.get("resolution")]

    @property
    def unclear(self) -> list[dict[str, Any]]:
        return [
            e
            for e in self.escalations
            if (e.get("resolution") or {}).get("outcome") == "unknown"
        ]


def _in_period(ts: float, start: float | None, end: float | None) -> bool:
    if start is not None and ts < start:
        return False
    if end is not None and ts > end:
        return False
    return True


def build(
    ledger: AuditLedger,
    constitution: Constitution | None = None,
    start: float | None = None,
    end: float | None = None,
) -> EvidencePack:
    """Read one local ledger once and count everything the report needs."""
    verify = ledger.verify()
    return build_from_entries(
        ledger.read_all(),
        chain_ok=bool(verify.ok),
        chain_detail=verify.detail,
        chain_entries=verify.entries_checked,
        source=str(ledger.path),
        constitution=constitution,
        start=start,
        end=end,
    )


def build_from_entries(
    entries: list[dict],
    *,
    chain_ok: bool,
    chain_detail: str,
    chain_entries: int,
    source: str,
    constitution: Constitution | None = None,
    start: float | None = None,
    end: float | None = None,
    cloud: bool = False,
) -> EvidencePack:
    """Count a pack from entries that may come from many machines.

    With `cloud=True`, resolutions marked `"_source": "cloud"` are the Cloud's
    own record of a named reviewer's answer, and every other resolution is a
    line a machine wrote about itself. A machine is the party being audited,
    so its line can never put a reviewer's name in the pack: the Cloud's answer
    always wins, a machine-only answer is labelled as the machine's own claim,
    and any disagreement is printed at the top. See `_cloud_resolution`.

    The caller is responsible for the chain verdict, because only the caller
    knows how the entries were verified: one local file re-hashed on the spot,
    or many machines' chains each checked by the cloud as they arrived.

    Resolutions are matched to their decision regardless of period. An answer
    given on Tuesday to a Monday escalation belongs with the Monday action, and
    dropping it because it fell outside the window would turn an answered
    escalation into an apparently abandoned one. Where a request has more than
    one resolution, one that held the action wins over one recorded afterwards.
    """
    pack = EvidencePack(
        generated_at=datetime.now(tz=UTC).timestamp(),
        period_from=start,
        period_to=end,
        ledger_path=source,
        chain_ok=chain_ok,
        chain_detail=chain_detail,
        chain_entries=chain_entries,
    )

    if constitution is not None:
        pack.constitution_name = constitution.metadata.name
        pack.report_policy_digest = getattr(constitution, "digest", "")
        pack.principles = [
            {
                "id": p.id,
                "statement": p.statement,
                "enforcement": p.enforcement.value,
                "severity": p.severity.value,
                "effect": p.effect.value,
            }
            for p in constitution.principles
        ]

    resolutions: dict[str, dict] = {}
    if cloud:
        resolutions = _cloud_resolutions(entries, pack)
    else:
        for entry in entries:
            if entry.get("kind") != "resolution":
                continue
            rid = entry.get("request_id", "")
            current = resolutions.get(rid)
            if current is None or (entry.get("gated") and not current.get("gated")):
                resolutions[rid] = entry

    for entry in entries:
        kind = entry.get("kind", "decision")
        if kind == "policy_change" and _in_period(entry_time(entry), start, end):
            pack.policy_changes.append(entry)
        if kind != "decision":
            continue
        if not _in_period(entry_time(entry), start, end):
            continue

        pack.decisions += 1
        pack.protection[entry.get("protection_level")] += 1
        _note_policy(pack, entry)
        effect = entry.get("effect", "")
        pack.effects[effect] += 1
        pack.surfaces[entry.get("surface", "unknown")] += 1

        if effect == "block":
            pack.blocked.append(entry)
        elif effect == "escalate":
            pack.escalations.append(
                {**entry, "resolution": resolutions.get(entry.get("request_id", ""))}
            )

    _policy_warnings(pack)
    return pack


CLOUD_METHOD_PREFIX = "cloud console"


def _cloud_resolutions(entries: list[dict], pack: EvidencePack) -> dict[str, dict]:
    """Pick one answer per request, where only the Cloud can name a reviewer."""
    from_cloud: dict[str, dict] = {}
    from_machines: dict[str, list[dict]] = {}
    for entry in entries:
        if entry.get("kind") != "resolution":
            continue
        rid = entry.get("request_id", "")
        if entry.get("_source") == "cloud":
            from_cloud[rid] = entry
        else:
            from_machines.setdefault(rid, []).append(entry)

    chosen: dict[str, dict] = {}
    for rid in set(from_cloud) | set(from_machines):
        answer = from_cloud.get(rid)
        claims = from_machines.get(rid, [])
        if answer is not None:
            chosen[rid] = _with_machine_report(answer, claims, pack, rid)
        else:
            chosen[rid] = _machine_claim(claims, pack, rid)
    return chosen


def _who(entry: dict) -> str:
    return str((entry.get("approver") or {}).get("id", ""))


def _with_machine_report(answer: dict, claims: list[dict], pack, rid: str) -> dict:
    """The Cloud's answer, plus whether the machine says it was held waiting."""
    out = dict(answer)
    out["gated"] = False
    for claim in claims:
        agrees = claim.get("outcome") == answer.get("outcome") and _who(claim) == _who(answer)
        if agrees and claim.get("gated"):
            out["gated"] = True
            out["gated_reported_by"] = claim.get("machine", "the machine")
        elif not agrees and claim.get("outcome") in ("approved", "denied"):
            pack.warnings.append(
                f"Request {rid}: the machine's own record says {claim.get('outcome')} by "
                f"{_who(claim) or 'nobody'}, but the Cloud records {answer.get('outcome')} by "
                f"{_who(answer)}. The Cloud record is shown."
            )
    return out


def _machine_claim(claims: list[dict], pack, rid: str) -> dict:
    """No Cloud answer exists: show the machine's line as its own claim."""
    best = next((c for c in claims if c.get("gated")), claims[0])
    out = dict(best)
    out["machine_claim"] = best.get("machine", "the machine")
    method = str((best.get("approver") or {}).get("method", ""))
    if method.startswith(CLOUD_METHOD_PREFIX) and best.get("outcome") in ("approved", "denied"):
        pack.warnings.append(
            f"Request {rid}: machine {out['machine_claim']} says a Cloud reviewer "
            f"({_who(best)}) answered, but the Cloud has no such answer."
        )
    return out


def _note_policy(pack: EvidencePack, entry: dict) -> None:
    digest = str(entry.get("policy_digest", ""))
    ts = entry_time(entry)
    for row in pack.policy_history:
        if row["digest"] == digest:
            row["last"] = max(row["last"], ts)
            row["first"] = min(row["first"], ts)
            row["decisions"] += 1
            return
    pack.policy_history.append({"digest": digest, "first": ts, "last": ts, "decisions": 1})


def _policy_warnings(pack: EvidencePack) -> None:
    """Say plainly when the rules shown are not the rules that were applied."""
    known = [p for p in pack.policy_history if p["digest"]]
    unknown = [p for p in pack.policy_history if not p["digest"]]
    recorded = {c.get("new_digest") for c in pack.policy_changes}
    unexplained = [p for p in known[1:] if p["digest"] not in recorded]
    if len(known) > 1 and unexplained:
        pack.warnings.append(
            f"The policy changed during this period: decisions were made under "
            f"{len(known)} different policy files, and {len(unexplained)} of those "
            "changes has no recorded policy change. See the policy history table."
        )
    level0 = pack.protection.get(0, 0)
    if level0:
        pack.warnings.append(
            f"{level0} decision(s) were made by a gate running as the same OS user as "
            "the agent (protection level 0, dev mode). For those, the agent could have "
            "reached the gate's own files."
        )
    if unknown:
        n = sum(p["decisions"] for p in unknown)
        tail = (
            " For those, the rules shown below are only the file at report time."
            if pack.report_policy_digest
            else ""
        )
        pack.warnings.append(
            f"{n} decision(s) do not record which policy they were made under "
            f"(written by an older version).{tail}"
        )
    if pack.report_policy_digest and known and not pack.policy_matches_report:
        if all(p["digest"] != pack.report_policy_digest for p in known):
            pack.warnings.append(
                "The policy file at report time was not used for any decision in "
                "this period. The rules listed below are not the ones that were applied."
            )


def questions(pack: EvidencePack) -> list[tuple[str, str, str]]:
    """The review questions, with answers that depend on what this pack holds."""
    out = []
    for question, status, answer in QUESTION_MAP:
        if question.startswith("Who can change the policy") and pack.policy_changes:
            status = "evidenced"
            answer = (
                "The policy is held by the guard room and can only be replaced through its "
                "admin socket. Every change is in the log with the old and new hash, the "
                "name given and the OS user, listed under Policy changes."
            )
        out.append((question, status, answer))
    return out


def _protection_text(pack: EvidencePack) -> str:
    names = {1: "separate OS user (level 1)", 0: "same OS user, dev mode (level 0)",
             None: "not recorded"}
    parts = [f"{names.get(k, k)}: {n}" for k, n in sorted(
        pack.protection.items(), key=lambda kv: (kv[0] is None, -(kv[0] or 0)))]
    return "; ".join(parts) or "no decisions"


def _short(digest: str) -> str:
    return digest.removeprefix("sha256:")[:12] if digest else "not recorded"


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _when(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%d %b %Y, %H:%M UTC")


def _period(pack: EvidencePack) -> str:
    """Say what the pack covers in words.

    "Period — to —" is worse than useless on a document going to a reviewer: it
    looks like two fields somebody forgot to fill in, which is exactly the
    impression this whole artifact exists to avoid.
    """
    if pack.period_from and pack.period_to:
        return f"Period: {_when(pack.period_from)} to {_when(pack.period_to)}"
    if pack.period_from:
        return f"Period: everything from {_when(pack.period_from)} onward"
    if pack.period_to:
        return f"Period: everything up to {_when(pack.period_to)}"
    return "Period: all recorded activity, no date filter applied"


def _rule_of(entry: dict) -> str:
    reasons = entry.get("reasons") or []
    return reasons[0].get("rule_id", "") if reasons else ""


def _reason_of(entry: dict) -> str:
    reasons = entry.get("reasons") or []
    return reasons[0].get("message", "") if reasons else ""


def _authority(resolution: dict | None) -> str:
    if not resolution:
        return "no answer recorded"
    if resolution.get("machine_claim"):
        return f"machine's own record ({resolution['machine_claim']}), not checked by the Cloud"
    if resolution.get("gated_reported_by"):
        return f"held the action (as reported by {resolution['gated_reported_by']})"
    return "held the action" if resolution.get("gated") else "recorded afterwards"


def _who_cell(resolution: dict) -> str:
    who = (resolution.get("approver") or {}).get("id", "—")
    if resolution.get("machine_claim"):
        return f"{who} (claimed by {resolution['machine_claim']})"
    return str(who)


def to_markdown(pack: EvidencePack) -> str:
    """Plain text version, for pasting straight into a questionnaire reply."""
    out: list[str] = []
    w = out.append

    w("# AI agent activity: control and audit evidence\n")
    w(f"Generated {_when(pack.generated_at)}")
    w(_period(pack) + "\n")

    w("## Summary\n")
    w(f"- Actions checked: **{pack.decisions}**")
    labels = {"allow": "Allowed", "block": "Blocked", "escalate": "Escalated",
              "modify": "Modified"}
    for name, label in labels.items():
        if pack.effects.get(name):
            w(f"- {label}: {pack.effects[name]}")
    w(f"- Escalations answered by a person: {pack.answered} of {len(pack.escalations)}")
    w(
        f"- Record integrity: **{'intact' if pack.chain_ok else 'FAILED'}** "
        f"({pack.chain_entries} entries checked, {pack.chain_detail})"
    )
    if pack.open_escalations:
        w(f"- **Open, never answered: {len(pack.open_escalations)}**")
    if pack.unclear:
        w(f"- **Answer could not be established: {len(pack.unclear)}**")
    w(f"- Gate isolation: {_protection_text(pack)}")
    w("")

    if pack.warnings:
        w("## Read this first\n")
        for warning in pack.warnings:
            w(f"- **{warning}**")
        w("")

    if pack.principles:
        w(f"## {pack.policy_heading}: {pack.constitution_name}\n")
        w(f"Policy file hash: `{_short(pack.report_policy_digest)}`\n")
        w("| Rule | What it says | How it is enforced |")
        w("|---|---|---|")
        for p in pack.principles:
            w(f"| `{p['id']}` | {p['statement']} | {p['enforcement']} ({p['effect']}) |")
        w("")

    if pack.policy_history:
        w("## Policy history\n")
        w("| Policy hash | First used | Last used | Decisions |")
        w("|---|---|---|---|")
        for p in pack.policy_history:
            w(f"| `{_short(p['digest'])}` | {_when(p['first'])} | {_when(p['last'])} | "
              f"{p['decisions']} |")
        w("")

    if pack.policy_changes:
        w("## Policy changes\n")
        w("| When | From | To | By | OS user | Note |")
        w("|---|---|---|---|---|---|")
        for c in pack.policy_changes:
            w(f"| {_when(entry_time(c))} | `{_short(c.get('old_digest', ''))}` | "
              f"`{_short(c.get('new_digest', ''))}` | {c.get('by', '')} | "
              f"{c.get('os_uid', '')} | {c.get('note', '')} |")
        w("")

    if pack.blocked:
        w("## Actions that were stopped\n")
        w("| When | Action | Rule |")
        w("|---|---|---|")
        for e in pack.blocked:
            w(f"| {_when(entry_time(e))} | `{e.get('action_redacted','')}` | {_rule_of(e)} |")
        w("")

    if pack.escalations:
        w("## Actions sent to a person\n")
        w("| When | Action | Rule | Answer | By whom | Authority |")
        w("|---|---|---|---|---|---|")
        for e in pack.escalations:
            r = e.get("resolution") or {}
            who = _who_cell(r) if r else "—"
            w(
                f"| {_when(entry_time(e))} | `{e.get('action_redacted','')}` | "
                f"{_rule_of(e)} | {r.get('outcome', 'open')} | {who} | {_authority(r)} |"
            )
        w("")

    w("## Common review questions\n")
    w("| Question | Status | Answer |")
    w("|---|---|---|")
    for question, status, answer in questions(pack):
        w(f"| {question} | {status} | {answer} |")
    w("")

    w("## What this does not prove\n")
    for limit in LIMITS:
        w(f"- {limit}")
    w("")

    return "\n".join(out)


def to_html(pack: EvidencePack) -> str:
    """Self-contained page. Print to PDF from any browser.

    No external stylesheet, font or script, because this document gets emailed
    to a security team and forwarded onward. Anything it fetches at open time is
    something that can fail, leak a request, or get blocked.
    """
    e = html.escape

    def rows(items, cells):
        return "\n".join(
            "<tr>" + "".join(f"<td>{c}</td>" for c in cells(i)) + "</tr>" for i in items
        )

    chain_class = "ok" if pack.chain_ok else "bad"
    chain_word = "Intact" if pack.chain_ok else "FAILED"

    flags = []
    if pack.open_escalations:
        flags.append(
            f"<li><strong>{len(pack.open_escalations)}</strong> escalation(s) were "
            "never answered by anyone.</li>"
        )
    if pack.unclear:
        flags.append(
            f"<li><strong>{len(pack.unclear)}</strong> escalation(s) have an answer we "
            "could not establish, recorded as unknown rather than assumed.</li>"
        )
    for warning in pack.warnings:
        flags.append(f"<li><strong>{e(warning)}</strong></li>")
    if not pack.chain_ok:
        flags.append(
            f"<li><strong>The record failed its integrity check.</strong> "
            f"{e(pack.chain_detail)}</li>"
        )
    flags_block = (
        f'<div class="flags"><h3>Read this first</h3><ul>{"".join(flags)}</ul></div>'
        if flags
        else ""
    )

    principles = rows(
        pack.principles,
        lambda p: (
            f"<code>{e(p['id'])}</code>",
            e(p["statement"]),
            f"{e(p['enforcement'])} &middot; {e(p['effect'])}",
        ),
    )
    blocked = rows(
        pack.blocked,
        lambda b: (
            _when(entry_time(b)),
            f"<code>{e(str(b.get('action_redacted','')))}</code>",
            f"<code>{e(_rule_of(b))}</code>",
            e(_reason_of(b)),
        ),
    )

    def esc_cells(x):
        r = x.get("resolution") or {}
        who = _who_cell(r) if r else "—"
        outcome = r.get("outcome", "open")
        return (
            _when(entry_time(x)),
            f"<code>{e(str(x.get('action_redacted','')))}</code>",
            f"<code>{e(_rule_of(x))}</code>",
            f'<span class="pill {e(outcome)}">{e(outcome)}</span>',
            e(str(who)),
            e(_authority(r)),
        )

    escalations = rows(pack.escalations, esc_cells)
    history = rows(
        pack.policy_history,
        lambda p: (
            f"<code>{e(_short(p['digest']))}</code>",
            _when(p["first"]),
            _when(p["last"]),
            str(p["decisions"]),
        ),
    )
    changes = rows(
        pack.policy_changes,
        lambda c: (
            _when(entry_time(c)),
            f"<code>{e(_short(c.get('old_digest', '')))}</code>",
            f"<code>{e(_short(c.get('new_digest', '')))}</code>",
            e(str(c.get("by", ""))),
            e(str(c.get("os_uid", ""))),
            e(str(c.get("note", ""))),
        ),
    )
    question_rows = rows(
        questions(pack),
        lambda q: (e(q[0]), f'<span class="pill {q[1].split()[0]}">{e(q[1])}</span>', e(q[2])),
    )
    limits = "".join(f"<li>{e(x)}</li>" for x in LIMITS)

    counts = "".join(
        f'<div class="stat"><span class="v">{pack.effects.get(k, 0)}</span>'
        f'<span class="l">{k}</span></div>'
        for k in ("allow", "block", "escalate", "modify")
        if pack.effects.get(k)
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI agent control and audit evidence</title>
<style>
  :root{{--ink:#12171b;--muted:#5c646b;--faint:#868d93;--rule:#d8dbd6;--paper:#fff;
        --sunk:#f2f3ef;--ok:#2c6740;--bad:#8e2f26;--warn:#8a5712;--accent:#17505c}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 -apple-system,
       BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
  .page{{max-width:960px;margin:0 auto;padding:44px 34px 90px}}
  h1{{font-size:1.9rem;line-height:1.15;margin:0 0 6px;letter-spacing:-.01em}}
  .sub{{color:var(--muted);margin:0 0 4px;font-size:14px}}
  h2{{font-size:1.15rem;margin:38px 0 12px;padding-top:14px;border-top:2px solid var(--ink)}}
  h3{{font-size:1rem;margin:0 0 8px}}
  p{{max-width:70ch}}
  table{{border-collapse:collapse;width:100%;font-size:13.4px;margin:0 0 8px}}
  th,td{{text-align:left;padding:9px 11px;border-bottom:1px solid var(--rule);vertical-align:top}}
  thead th{{background:var(--sunk);font-size:10.5px;letter-spacing:.08em;
           text-transform:uppercase;color:var(--muted);white-space:nowrap}}
  code{{font:12.4px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--sunk);
       padding:1px 5px;border-radius:3px}}
  .strip{{display:flex;flex-wrap:wrap;gap:1px;background:var(--rule);
         border:1px solid var(--rule);margin:18px 0}}
  .stat{{background:var(--paper);padding:12px 18px;min-width:104px;flex:1}}
  .stat .v{{display:block;font-size:1.5rem;font-weight:600;font-variant-numeric:tabular-nums}}
  .stat .l{{display:block;font-size:10.5px;letter-spacing:.08em;
           text-transform:uppercase;color:var(--faint)}}
  .chain{{padding:12px 16px;border-left:4px solid var(--ok);background:#f2f8f4;
         margin:16px 0;font-size:14px}}
  .chain.bad{{border-left-color:var(--bad);background:#fdf2f0}}
  .chain strong{{color:var(--ok)}} .chain.bad strong{{color:var(--bad)}}
  .flags{{border:1px solid var(--warn);background:#fdf7ec;padding:14px 18px;
         margin:18px 0;border-radius:4px}}
  .flags ul{{margin:0;padding-left:18px}} .flags li{{margin:4px 0;font-size:14px}}
  .pill{{font:11px/1.4 ui-monospace,Menlo,monospace;padding:2px 7px;border-radius:3px;
        background:var(--sunk);color:var(--muted);white-space:nowrap}}
  .pill.approved,.pill.evidenced{{background:#e4f0e8;color:var(--ok)}}
  .pill.denied{{background:#fbe6e2;color:var(--bad)}}
  .pill.open,.pill.partial,.pill.expired{{background:#f8eeda;color:var(--warn)}}
  .limits{{background:var(--sunk);padding:16px 20px;border-radius:4px}}
  .limits ul{{margin:0;padding-left:18px}} .limits li{{margin:6px 0;max-width:78ch}}
  .foot{{margin-top:40px;padding-top:14px;border-top:1px solid var(--rule);
        color:var(--faint);font-size:12px}}
  @media print{{
    .page{{max-width:none;padding:0}}
    h2{{page-break-after:avoid}} tr{{page-break-inside:avoid}}
    body{{font-size:11.5pt}}
  }}
</style></head>
<body><div class="page">

<h1>AI agent activity: control and audit evidence</h1>
<p class="sub">{_period(pack)}</p>
<p class="sub">Generated {_when(pack.generated_at)} from <code>{e(pack.ledger_path)}</code></p>

{flags_block}

<div class="strip">
  <div class="stat"><span class="v">{pack.decisions}</span><span class="l">checked</span></div>
  {counts}
  <div class="stat"><span class="v">{pack.answered}/{len(pack.escalations)}</span>
    <span class="l">answered</span></div>
</div>

<div class="chain {chain_class}">
  Record integrity: <strong>{chain_word}</strong>.
  {pack.chain_entries} entries checked. {e(pack.chain_detail)}.
  Each entry carries the hash of the entry before it, so altering or reordering
  any past line breaks every line after it.
  <br>Gate isolation: {e(_protection_text(pack))}.
</div>

<h2>{e(pack.policy_heading)}</h2>
<p class="sub">{e(pack.constitution_name)} &middot; policy file hash
<code>{e(_short(pack.report_policy_digest))}</code></p>
<table><thead><tr><th>Rule</th><th>What it says</th><th>Enforcement</th></tr></thead>
<tbody>{principles or '<tr><td colspan="3">No policy loaded.</td></tr>'}</tbody></table>

<h2>Policy history</h2>
<table><thead><tr><th>Policy hash</th><th>First used</th><th>Last used</th>
<th>Decisions</th></tr></thead>
<tbody>{history or '<tr><td colspan="4">No decisions in this period.</td></tr>'}</tbody></table>

<h2>Policy changes</h2>
<table><thead><tr><th>When</th><th>From</th><th>To</th><th>By</th><th>OS user</th>
<th>Note</th></tr></thead>
<tbody>{changes or NO_POLICY_CHANGES}</tbody></table>

<h2>Actions that were stopped</h2>
<table><thead><tr><th>When</th><th>Action</th><th>Rule</th><th>Why</th></tr></thead>
<tbody>{blocked or NOTHING_BLOCKED}</tbody></table>

<h2>Actions sent to a person</h2>
<table><thead><tr><th>When</th><th>Action</th><th>Rule</th><th>Answer</th>
<th>By whom</th><th>Authority</th></tr></thead>
<tbody>{escalations or NOTHING_ESCALATED}</tbody></table>

<h2>Common review questions</h2>
<table><thead><tr><th>Question</th><th>Status</th><th>Answer</th></tr></thead>
<tbody>{question_rows}</tbody></table>

<h2>What this does not prove</h2>
<div class="limits"><ul>{limits}</ul></div>

<p class="foot">
  Produced by TrustGate from a hash-chained decision log. Every figure above is a
  count of entries written at the moment each action was proposed. Nothing here is
  estimated or reconstructed after the fact.
</p>

</div></body></html>"""


def write(
    pack: EvidencePack, path: str | Path, fmt: str = "html"
) -> Path:
    """Render and save. Returns the path written."""
    destination = Path(path)
    body = to_markdown(pack) if fmt == "md" else to_html(pack)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body, encoding="utf-8")
    return destination


def to_json(pack: EvidencePack) -> str:
    """Machine-readable form, for a reviewer who wants the raw counts."""
    return json.dumps(
        {
            "generated_at": pack.generated_at,
            "period": {"from": pack.period_from, "to": pack.period_to},
            "chain": {
                "ok": pack.chain_ok,
                "entries_checked": pack.chain_entries,
                "detail": pack.chain_detail,
            },
            "constitution": pack.constitution_name,
            "report_policy_digest": pack.report_policy_digest,
            "policy_history": pack.policy_history,
            "warnings": pack.warnings,
            "policy_changes": pack.policy_changes,
            "protection_levels": {str(k): v for k, v in pack.protection.items()},
            "decisions": pack.decisions,
            "effects": dict(pack.effects),
            "surfaces": dict(pack.surfaces),
            "escalations": {
                "total": len(pack.escalations),
                "answered": pack.answered,
                "open": len(pack.open_escalations),
                "unclear": len(pack.unclear),
            },
        },
        indent=2,
    )
