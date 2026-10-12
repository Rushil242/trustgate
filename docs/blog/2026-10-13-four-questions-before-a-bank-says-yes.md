---
layout: post
title: "The four questions your AI agent has to answer before a bank says yes"
description: "Security reviews of AI products now ask what the agent may do, what it did, who approved the risky parts, and whether the record is real. Here is what a good answer looks like, and what TrustGate is built to prove."
date: 2026-10-13
author: Rushil CV
canonical_url: https://trustgate.rushil-cv26.workers.dev/blog/four-questions-before-a-bank-says-yes
---

*First published on the [TrustGate blog](https://trustgate.rushil-cv26.workers.dev/blog/four-questions-before-a-bank-says-yes).*


A small AI company builds an agent that works. It reads documents, calls tools, updates records, sometimes moves money. A bank, a hospital or an insurer wants to buy it.

Then the security questionnaire arrives. Most of it is familiar: encryption, access control, SOC 2. But newer versions have a section about the AI itself, and that section is where deals slow down. It rarely asks about the model. It asks about the agent's behaviour, and it wants proof.

I build TrustGate, an open source control and audit layer for AI agents, around exactly this moment. This post walks through the four questions that section keeps coming back to, the answer that does not work, and the answer that does.

## Why "it's in the system prompt" is not an answer

The first instinct is to point at the system prompt. "The agent is instructed never to touch production." "It is told to ask before refunds over $100."

A reviewer reads that as a preference, not a control. The model can misread the instruction, be talked out of it by text it reads in a document, or simply skip it on step forty of a long task. A control has to sit outside the model, run every time, and leave a record that it ran.

That is the shape of every good answer below.

## Question 1: What is your agent allowed to do?

A good answer is a rulebook a non-engineer can read, checked before every action, outside the model.

In TrustGate the rules are written as plain-English statements with a precise match underneath. For example:

```yaml
- id: refund-limit
  statement: "Refunds over $100 need a named person to approve."
  match:
    tool: [issue_refund]
    param_gt: { amount: 100 }
  effect: escalate
```

Every proposed action gets one of four verdicts: allow, block, modify (for example, remove a secret and then run), or escalate to a human. When rules disagree, the strictest wins.

The part nobody demos is false positives. A gate that blocks routine work gets switched off within a week, and a switched-off gate is worse than none, because everyone thinks it is still there. So the rules judge what a command targets, not how it looks. `rm -rf /` is denied. `rm -rf node_modules` is allowed. Early on, a careless match on the word `prod` was escalating `npm run build:production`. That was a bug, not caution, and I treat it as a security bug.

## Question 2: What did it actually do?

A good answer is a record of every action the agent proposed, including the allowed ones, written when the decision was made. Not a dashboard that summarises, not a log you assemble afterwards from three systems.

TrustGate writes every decision to a ledger: what the agent tried, which rule matched, the verdict, and the reason. Secrets are removed before anything is written, so the audit log does not become the leak.

From that ledger, one command builds an evidence pack: a self-contained report you can hand to a reviewer, with the rules in force, every blocked action, every escalation and its answer, and whether the record checks out.

```bash
trustgate evidence --since 2026-09-01 --out pack.html
```

The pack lists its own failures first. Unanswered escalations, outcomes that could not be established, a broken chain. A report with only good news is not evidence, and reviewers know it.

## Question 3: Who approved the risky parts?

This is the question that exposes most "human in the loop" setups.

Asking a human is easy. Recording the answer properly is not. In most agent logs you can prove a person was asked, but not what they said, who they were, or when. I found that out the hard way. I wrote a classifier to work out from a tool's output whether a person had approved or refused, and "permission denied" was on its list of refusals. It then filed `EACCES: permission denied`, a filesystem error, as a human saying no. It invented a decision nobody made. Now a denial only counts as human if it names the user, and anything unclear is recorded as unknown.

Three details make an approval record worth trusting:

1. **A named approver.** Not "someone clicked yes". A person, under their own identity.
2. **Whether the action waited.** An approval that holds the action is a control. An approval recorded after the action already ran is a comment. In most logs they look identical, so TrustGate stores which one it was.
3. **What silence means.** If nobody answers in time, the request is recorded as expired and the action is denied. Silence is never approval.

There was a quieter failure here too. Claude Code stops a hook when it reaches the hook's timeout. My approval window was longer than the hook timeout, so a slow reviewer meant the hook was killed and the agent fell back to the normal prompt, with no warning. The setup now sets the hook timeout above the approval window.

## Question 4: How do we know the record is real?

This is the question most teams cannot answer at all, and the one I find most interesting.

TrustGate chains each ledger entry to the one before it with a hash. Change one entry and verification fails from that point on. That proves the log was not edited.

It does not prove the log was not deleted. I tested it on my own ledger: wipe the file, replay a clean history, and it still verifies on the same machine, because the new chain is internally consistent. Tamper-evident is not tamper-proof.

The fix is a second copy that the person being audited cannot reach. It receives every entry as it is written and refuses any history that disagrees with what it already holds. That copy is the honest reason a paid version of TrustGate exists.

## What TrustGate is built for

| | Free and open source (MIT) | TrustGate Pro (early access) |
|---|---|---|
| Rules checked before every action | Yes | Yes |
| Named approvals, silence means no | Yes, per machine | One approval inbox for every agent |
| Ledger and evidence pack | Yes, per machine | One evidence pack across every agent |
| Detects a wiped and rebuilt log | No, this is the limit | Yes, a copy your team cannot change |
| Help writing your rules and questionnaire answers | Docs | Set up with you in two weeks |

The line between them is one question: can it run on your own machine and help one person? If yes, it is free, and that includes the evidence pack.

## What it does not do

Stated plainly, because a security tool that is vague about its limits is worse than one with narrow, honest ones.

- It only governs actions that are routed through it. An agent path with no adapter is ungoverned.
- The red-team result, 41 of 41 attacks handled with 0 of 24 false positives, is self-measured. I wrote both the attacks and the defences.
- Someone who controls the host can change the code, the rules or the log. The local log is tamper-evident, not tamper-proof.
- It is v0.2.0, built by one person, with 389 tests, and nobody runs it in production yet. TrustGate Pro is in early access and set up directly with each team.

## Try it, or talk to me

If your agent is about to meet a security review, the open source version runs offline with no API key:

```bash
git clone https://github.com/Rushil242/trustgate.git
cd trustgate && ./scripts/dev-setup.sh
uv run trustgate test
```

The code is at [github.com/Rushil242/trustgate](https://github.com/Rushil242/trustgate). If you have a deal waiting on the AI section of a questionnaire, [tell me about it](https://trustgate.rushil-cv26.workers.dev/contact). I am happy to look at the questions with you.

Rushil CV
