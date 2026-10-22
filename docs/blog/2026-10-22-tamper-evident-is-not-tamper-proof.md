---
layout: post
title: "Tamper-evident is not tamper-proof: what a hash chain proves about your AI agent's log"
description: "I edited, cut and rebuilt my own AI agent's audit log to see what a hash chain catches. It caught the edit. It missed the other two. Here is the real terminal output, and what actually fixes it."
date: 2026-10-22
author: Rushil CV
canonical_url: https://trustgate.rushil-cv26.workers.dev/blog/tamper-evident-is-not-tamper-proof
---

*First published on the [TrustGate blog](https://trustgate.rushil-cv26.workers.dev/blog/tamper-evident-is-not-tamper-proof).*


When an AI agent touches real systems, sooner or later someone asks for its log. A customer's security team, an auditor, or you at 2 am after something went wrong. The log is only useful if people can trust it was not changed after the fact.

The common answer is a hash chain. I use one in TrustGate, the open source control layer I build for AI agents. I wanted to know exactly what it protects against, so I attacked my own log three ways. This post shows the real terminal output from each one.

## What a hash chain is, in one paragraph

Every entry in the log stores two things: a hash of its own contents (`entry_hash`) and the hash of the entry before it (`prev_hash`). Change anything in an entry, and its hash no longer matches. Each entry points at the one before it, so you cannot quietly change the middle of the log without breaking every link after it.

Here is one real entry from the run below, trimmed:

```json
{
  "seq": 1,
  "action_redacted": "cat .env",
  "effect": "block",
  "reasons": [{"rule_id": "protect-secrets", "severity": "critical"}],
  "prev_hash": "3a45285e08b7...",
  "entry_hash": "39adad887e89..."
}
```

## The setup

A coding agent proposes three shell commands. TrustGate checks each one against its default rules before it runs and writes every decision to the log, the allowed ones too:

```text
$ agent: npm test             ->  allow
$ agent: cat .env             ->  block  (protect-secrets)
$ agent: rm -rf node_modules  ->  allow

$ trustgate verify-audit
OK  chain intact — 3 entries verified
```

Three decisions, one of them a block. That block is the entry someone might later want to hide.

## Attack 1: edit an entry

Change the blocked decision to say it was allowed:

```text
$ sed -i '2s/"block"/"allow"/' audit.jsonl
$ trustgate verify-audit
FAIL  chain broken at seq 1
      line 2: entry contents do not match entry_hash (this entry was modified after it was written)
      1 entries verified before the break
```

Caught, and it says exactly where. The command also exits with code 2, so a CI job or a script fails loudly instead of carrying on. This is what a hash chain is good at.

## Attack 2: cut entries off the end

Keep only the first entry and throw away the rest, including the block:

```text
$ head -1 audit.jsonl > truncated.jsonl
$ trustgate verify-audit -a truncated.jsonl
OK  chain intact — 1 entries verified
```

Not caught. Every remaining link is still valid. The chain proves the entries you have fit together. It cannot prove nothing came after them.

## Attack 3: wipe the log and replay a clean history

Delete the file and let the agent run again, this time without the command that got blocked:

```text
$ rm audit.jsonl
$ (run "npm test" and "rm -rf node_modules" again)
$ trustgate verify-audit
OK  chain intact — 2 entries verified
```

Not caught. This is a brand new chain, and it is perfectly consistent with itself. The blocked `cat .env` is simply gone, and the log looks cleaner than the truth.

## So what does a hash chain actually prove?

| Someone with write access to the log... | Caught by the chain? |
|---|---|
| Edits an entry in the middle | Yes |
| Cuts entries off the end | No |
| Deletes the log and writes a new one | No |

A hash chain proves the log was **not edited**. It does not prove the log was **not deleted, shortened or replaced**. That is the difference between tamper-evident and tamper-proof.

For your own debugging, that difference rarely matters. For an agent, it matters a lot, because the person who can rewrite the log is usually the same team whose agent is being reviewed. A reviewer deciding whether to trust your record is asking exactly the question the chain cannot answer.

## What actually fixes it

All of these share one idea: the proof has to live somewhere the person being audited cannot write to.

1. **Anchor the latest hash somewhere else.** Every so often, copy the hash of the last entry to a place you cannot quietly change: a git commit in another repo, a message to a shared channel, an email to someone else. Free, and enough to catch a truncated or replaced log after that point.
2. **Write-once storage.** Ship entries to storage that refuses changes and deletes for a set period, such as object storage with a retention lock. Strong, but you have to set it up and pay for it.
3. **A copy held by someone else that checks the chain on arrival.** A second service receives every entry as it is written, re-checks each hash, and refuses any history that does not continue from what it already holds. A wiped and replayed log then fails there, even though it passes on your own machine.

The third one is what TrustGate Cloud does. I have built it and tested exactly this case: the wiped and replayed log above passes `verify-audit` locally, and the cloud copy refuses it. It runs locally today and is in early access, set up directly with each team. It is not a public hosted service yet, and I would rather say so than let you assume it is.

## What it does not fix

Stated plainly:

- If someone controls the machine before the entry is written, they can stop the agent's action from ever being logged. The chain protects what was written, not what never was.
- A copy held elsewhere only covers entries after it starts receiving them.
- None of this proves the agent behaved well. It proves the record of what it did was not changed later. Those are different questions, and a good review asks both.

## Try it yourself

Everything above runs offline with no API key. The open source version, including the hash-chained log and `verify-audit`, is free under the MIT licence:

```bash
git clone https://github.com/Rushil242/trustgate.git
cd trustgate && ./scripts/dev-setup.sh
uv run trustgate test
```

The code is at [github.com/Rushil242/trustgate](https://github.com/Rushil242/trustgate). If your team has to prove what an AI agent did to someone outside your company, [tell me about it](https://trustgate.rushil-cv26.workers.dev/contact).

Rushil CV
