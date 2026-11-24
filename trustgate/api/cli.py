"""The `trustgate` command line.

`trustgate check` is the hot path: the coding hook shells out to it on every
tool call, so it must start fast. That is why this module uses argparse from the
standard library rather than a CLI framework, and why server and judge imports
happen inside the subcommands that need them — importing FastAPI on a `check`
would add tens of milliseconds to every single agent action.

Spec: Master Build Document v3.0, Part G.2.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC
from pathlib import Path
from typing import Any

from trustgate import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED = 2
"""`check` exits 2 when the action is not allowed, so shell callers can branch
on the exit code without parsing JSON."""


def _load_engine(args: argparse.Namespace):
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config
    from trustgate.core.constitution import Constitution
    from trustgate.core.engine import Engine

    cfg = Config.load()
    if getattr(args, "constitution", None):
        cfg.constitution_path = args.constitution
    if getattr(args, "audit", None):
        cfg.audit_path = args.audit

    constitution = Constitution.from_file(cfg.constitution_path)

    judge = None
    if cfg.judge.active:
        from trustgate.core.guards.constitution_llm import ConstitutionGuard
        from trustgate.core.llm import build_llm

        judge = ConstitutionGuard(constitution, build_llm(cfg.judge))

    return Engine(constitution=constitution, audit=AuditLedger(cfg.audit_path), judge=judge), cfg


def cmd_check(args: argparse.Namespace) -> int:
    """Read an ActionRequest as JSON on stdin, print a Decision as JSON."""
    from pydantic import ValidationError

    from trustgate.core.constitution import ConstitutionError
    from trustgate.core.models import ActionRequest

    try:
        payload: dict[str, Any] = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"stdin is not valid JSON: {exc}"}), file=sys.stderr)
        return EXIT_ERROR

    payload.setdefault("surface", args.surface)

    try:
        req = ActionRequest.model_validate(payload)
    except ValidationError as exc:
        print(json.dumps({"error": f"invalid ActionRequest: {exc}"}), file=sys.stderr)
        return EXIT_ERROR

    try:
        engine, _ = _load_engine(args)
    except ConstitutionError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return EXIT_ERROR

    decision = engine.decide(req)
    print(decision.model_dump_json())
    return EXIT_OK if decision.effect.value == "allow" else EXIT_DENIED


def cmd_verify_audit(args: argparse.Namespace) -> int:
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config

    cfg = Config.load()
    path = args.audit or cfg.audit_path
    keys = None
    if args.pubkey:
        # `key_id=base64` pairs, or a bare base64 key (its id is computed).
        from trustgate.core.signing import key_id_for

        keys = {}
        for item in args.pubkey:
            if "=" in item and item.startswith("ed25519:"):
                key_id, public = item.split("=", 1)
            else:
                import base64

                public = item
                key_id = key_id_for(base64.b64decode(item))
            keys[key_id] = public
    result = AuditLedger(path).verify(public_keys=keys)

    if result.ok:
        print(f"OK  {result.detail}: {result.entries_checked} entries verified ({path})")
        return EXIT_OK

    print(f"FAIL  chain broken at seq {result.broken_seq} ({path})", file=sys.stderr)
    print(f"      {result.detail}", file=sys.stderr)
    print(f"      {result.entries_checked} entries verified before the break", file=sys.stderr)
    return EXIT_DENIED


def cmd_pending(args: argparse.Namespace) -> int:
    """List escalations nobody has answered.

    Exits non-zero when any are open. An escalation left hanging means the
    system asked for a human decision and never got one, which is a finding in
    its own right and worth failing a check over.
    """
    import time

    from trustgate.core.audit import AuditLedger, entry_time
    from trustgate.core.config import Config

    cfg = Config.load()
    path = args.audit or cfg.audit_path
    open_items = AuditLedger(path).open_escalations()

    if not open_items:
        print(f"OK  no escalations awaiting a decision ({path})")
        return EXIT_OK

    now = time.time()
    print(f"{len(open_items)} escalation(s) awaiting a decision ({path})\n")
    for entry in open_items:
        age = now - (entry_time(entry) or now)
        rule = ""
        reasons = entry.get("reasons") or []
        if reasons:
            rule = reasons[0].get("rule_id", "")
        print(f"  seq {entry.get('seq')}  {_age(age):>8} ago  [{rule}]")
        print(f"      {entry.get('action_redacted', '')}")
    return EXIT_DENIED


def _age(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 5400:
        return f"{int(seconds // 60)}m"
    if seconds < 172800:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


def cmd_evidence(args: argparse.Namespace) -> int:
    """Turn the ledger into a document you can hand to a reviewer.

    Exits non-zero when the record failed its integrity check. A pack whose own
    chain is broken should not be quietly emailed to a customer, so the command
    still writes the file (it says so, prominently) and then fails loudly.
    """
    from datetime import datetime

    from trustgate.core import evidence
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config
    from trustgate.core.constitution import Constitution, ConstitutionError

    cfg = Config.load()
    ledger = AuditLedger(args.audit or cfg.audit_path)

    constitution = None
    try:
        constitution = Constitution.from_file(args.constitution or cfg.constitution_path)
    except (ConstitutionError, OSError) as exc:
        # Worth continuing. The activity record is the bulk of the value, and a
        # pack that lists what happened without the rule text is still useful.
        print(f"warning: could not load the policy ({exc}); "
              "the pack will omit the rules section", file=sys.stderr)

    def parse_day(value: str | None, end_of_day: bool) -> float | None:
        if not value:
            return None
        try:
            day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            print(f"error: --{'to' if end_of_day else 'from'} must look like "
                  f"2026-09-01 (got {value!r})", file=sys.stderr)
            raise SystemExit(EXIT_ERROR) from None
        if end_of_day:
            day = day.replace(hour=23, minute=59, second=59)
        return day.timestamp()

    pack = evidence.build(
        ledger,
        constitution,
        start=parse_day(args.since, False),
        end=parse_day(args.until, True),
    )

    if args.format == "json":
        print(evidence.to_json(pack))
        return EXIT_OK if pack.chain_ok else EXIT_DENIED

    written = evidence.write(pack, args.out, args.format)

    print(f"Wrote {written}")
    print(f"  {pack.decisions} actions checked, "
          f"{pack.effects.get('block', 0)} blocked, {len(pack.escalations)} escalated")
    print(f"  {pack.answered} of {len(pack.escalations)} escalations answered by a person")
    if pack.open_escalations:
        print(f"  {len(pack.open_escalations)} never answered — disclosed in the pack")
    if pack.unclear:
        print(f"  {len(pack.unclear)} answer(s) could not be established")

    if not pack.chain_ok:
        print(f"\nFAIL  the record did not verify: {pack.chain_detail}", file=sys.stderr)
        print("      the pack says so at the top; do not send it until this is "
              "explained", file=sys.stderr)
        return EXIT_DENIED

    print(f"  record intact, {pack.chain_entries} entries verified")
    return EXIT_OK


def cmd_sync(args: argparse.Namespace) -> int:
    """Ship this machine's ledger to TrustGate Cloud.

    Safe to run as often as you like, from cron or a loop: it only sends what
    the cloud does not have yet. Exits 2 if the cloud refused the history,
    which is not a network problem and should not be retried blindly.
    """
    import time

    from trustgate.core import sync
    from trustgate.core.audit import AuditLedger
    from trustgate.core.config import Config

    cfg = Config.load()
    if args.audit:
        cfg.audit_path = args.audit
    if not cfg.cloud.url:
        print("error: no cloud configured. Set TRUSTGATE_CLOUD_URL, or [cloud] url "
              "in ~/.trustgate/config.toml", file=sys.stderr)
        return EXIT_ERROR
    if not cfg.cloud.api_key:
        print("error: no API key. Set TRUSTGATE_CLOUD_KEY in the environment "
              "(keys are never read from the config file)", file=sys.stderr)
        return EXIT_ERROR

    ledger = AuditLedger(cfg.audit_path)
    while True:
        res = sync.push(ledger, cfg.cloud.url, cfg.cloud.api_key, cfg.cloud.machine_id,
                        cfg.cloud.batch_size, cfg.cloud.timeout)
        if res.rejected:
            print(f"REFUSED  {res.error}", file=sys.stderr)
            print("         the cloud holds lines this machine's ledger no longer "
                  "agrees with. Investigate before doing anything else.", file=sys.stderr)
            return EXIT_DENIED
        if res.error:
            print(f"warning: {res.error} (will retry)", file=sys.stderr)
        elif res.sent:
            print(f"sent {res.sent} entr{'y' if res.sent == 1 else 'ies'}, "
                  f"cloud is up to seq {res.up_to_seq} for {cfg.cloud.machine_id}")
        elif not args.watch:
            print(f"OK  nothing new, cloud is up to seq {res.up_to_seq}")
        if not args.watch:
            return EXIT_OK if res.ok else EXIT_ERROR
        time.sleep(args.watch)


def cmd_serve(args: argparse.Namespace) -> int:
    from pathlib import Path

    from trustgate.api.server import serve
    from trustgate.core.config import Config

    cfg = Config.load()
    if args.constitution:
        cfg.constitution_path = args.constitution

    dashboard_dir = Path(__file__).resolve().parents[1] / ".." / "dashboard"
    if dashboard_dir.resolve().is_dir():
        print(f"dashboard: http://{args.host}:{args.port}/")
    print(f"decision API: http://{args.host}:{args.port}/v1/decide")

    serve(host=args.host, port=args.port, config=cfg)
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    """Parse a constitution and report what it contains."""
    from trustgate.core.constitution import Constitution, ConstitutionError

    try:
        c = Constitution.from_file(args.path)
    except ConstitutionError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    print(f"OK  {args.path}")
    print(f"    name:          {c.metadata.name}")
    print(f"    surface:       {c.metadata.surface or 'any'}")
    print(f"    principles:    {len(c.principles)}")
    print(f"      deterministic: {len(c.deterministic_principles)}")
    print(f"      reasoning:     {len(c.reasoning_principles)}")
    return EXIT_OK


def cmd_pin_policy(args: argparse.Namespace) -> int:
    """Approve the exact bytes of a policy file, so the hook will trust it."""
    from trustgate.core.config import Config
    from trustgate.core.constitution import Constitution, ConstitutionError
    from trustgate.core.pins import is_trusted, load_pins, pin, pins_path

    if args.list:
        pins = load_pins()
        if not pins:
            print(f"no pinned policies in {pins_path()}")
        for digest, info in pins.items():
            print(f"{digest}  {info.get('path', '')}")
        return EXIT_OK

    path = Path(args.path or Config.load().constitution_path)
    try:
        constitution = Constitution.from_file(path)
    except ConstitutionError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    if is_trusted(constitution.digest):
        print(f"already trusted: {path}\n  {constitution.digest}")
        return EXIT_OK

    print(f"policy:     {path}")
    print(f"name:       {constitution.metadata.name}")
    print(f"principles: {len(constitution.principles)}")
    print(f"hash:       {constitution.digest}")
    if not args.yes:
        print("Read the file first. Pin these exact bytes? [y/N] ", end="", flush=True)
        if sys.stdin.readline().strip().lower() not in ("y", "yes"):
            print("not pinned")
            return EXIT_DENIED
    pin(path, note=args.note or "")
    print(f"pinned in {pins_path()}")
    return EXIT_OK


DEV_GUARDROOM = Path.home() / ".trustgate" / "guardroom"
PROD_STATE, PROD_RUN = Path("/var/lib/trustgate"), Path("/var/run/trustgate")


def _guardroom_dirs(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.prod:
        return Path(args.state or PROD_STATE), Path(args.run or PROD_RUN)
    return Path(args.state or DEV_GUARDROOM / "state"), Path(args.run or DEV_GUARDROOM / "run")


def cmd_guardroom(args: argparse.Namespace) -> int:
    """Run or talk to the guard room daemon."""
    from trustgate.guardroom import daemon

    state, run = _guardroom_dirs(args)
    if args.action == "serve":
        import signal
        import threading

        from trustgate.core.config import Config

        daemon.serve(state, run, Config.load())
        print(f"trustgated: state {state}, sockets in {run}", file=sys.stderr)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        try:
            stop.wait()
        except KeyboardInterrupt:
            pass
        return EXIT_OK

    if args.action == "install-hook":
        return _install_thin_hook(args, run)

    sock = run / ("admin.sock" if args.action == "resolve" else "agent.sock")
    message = {"op": "status"}
    if args.action == "resolve":
        message = {"op": "resolve", "request_id": args.request_id, "outcome": args.outcome,
                   "approver": args.approver, "note": args.note or ""}
    try:
        reply = daemon.request(sock, message)
    except OSError as exc:
        print(f"cannot reach the guard room at {sock}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(reply, indent=2))
    return EXIT_OK if reply.get("ok") else EXIT_DENIED


def _install_thin_hook(args: argparse.Namespace, run: Path) -> int:
    """Copy the thin hook with its socket path and fallback baked in."""
    from trustgate.guardroom import hook as thin

    source = Path(thin.__file__).read_text(encoding="utf-8")
    fallback = "deny" if args.prod else "ask"
    text = source.replace(
        'SOCKET = "/var/run/trustgate/agent.sock"', f"SOCKET = {str(run / 'agent.sock')!r}"
    ).replace('FALLBACK = "deny"', f"FALLBACK = {fallback!r}")
    dest = Path(args.dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    dest.chmod(0o755)
    py = args.python or "/usr/bin/python3"
    snippet = {
        "hooks": {
            "PreToolUse": [{"hooks": [{"type": "command",
                                       "command": f"{py} -I {dest} pretooluse",
                                       "timeout": 200}]}],
            **{event: [{"hooks": [{"type": "command",
                                   "command": f"{py} -I {dest} observe", "timeout": 15}]}]
               for event in ("PostToolUse", "PostToolUseFailure", "PermissionDenied")},
        }
    }
    print(f"wrote {dest} (socket {run / 'agent.sock'}, fallback {fallback})")
    print("Add this to your Claude Code settings"
          + (" (managed settings, owned by root)" if args.prod else "") + ":")
    print(json.dumps(snippet, indent=2))
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    """Install the agent hook and a starter constitution into a project."""
    from trustgate.adapters.coding.install import install, next_steps

    try:
        result = install(
            project_root=args.project or Path.cwd(),
            surface=args.surface,
            force=args.force,
        )
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"init failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(next_steps(result))
    return EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    """Record the current hook/MCP configuration as reviewed."""
    from trustgate.core.guards.supply_chain import (
        collect_extension_files,
        diff_against_manifest,
        write_manifest,
    )

    root = Path(args.project) if args.project else Path.cwd()
    problems = diff_against_manifest(root)
    digests = collect_extension_files(root)

    if not digests:
        print(f"no hook, skill, or MCP configuration found under {root}")
        return EXIT_OK

    if not problems and not args.force:
        print(f"already approved — {len(digests)} extension file(s) unchanged")
        return EXIT_OK

    print("These files decide what runs automatically in every future session:")
    for rel, why in problems:
        print(f"  {rel}  ({why})")
    if not problems:
        for rel in sorted(digests):
            print(f"  {rel}")

    if not args.yes:
        # Approving unreviewed executable configuration is exactly the action
        # this guard exists to slow down, so it is confirmed by default.
        answer = input("\nApprove these as reviewed? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("not approved")
            return EXIT_DENIED

    path = write_manifest(root, digests)
    print(f"approved {len(digests)} file(s) — manifest written to {path}")
    return EXIT_OK


def cmd_test(args: argparse.Namespace) -> int:
    """Run the red-team suite and print the block-rate table."""
    from trustgate.core.config import Config
    from trustgate.core.constitution import ConstitutionError

    runner = _load_runner()
    if runner is None:
        print(
            "red-team suite not found. It lives in redteam/ in the source tree "
            "and is not shipped in the installed package; run this from a clone.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    cfg = Config.load()
    constitution_path = args.constitution or cfg.constitution_path
    if not Path(constitution_path).is_file():
        constitution_path = str(_packaged_policy("starter.coding.yaml"))

    payloads = args.payloads or str(runner.DEFAULT_PAYLOADS)

    community_dir = None if args.no_community else (args.community_dir or runner.COMMUNITY_DIR)

    try:
        results = runner.run(
            constitution_path, payloads, audit_path=args.audit, community_dir=community_dir
        )
    except (ConstitutionError, OSError, runner.CommunityFileError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    print(f"constitution: {constitution_path}")
    print(f"payloads:     {payloads}")
    n_community, bypasses = runner.community_counts(results)
    if community_dir is not None:
        print(f"community:    {n_community} case(s) from {community_dir}")
    print(runner.format_table(results))

    if os.environ.get("GITHUB_ACTIONS") == "true":
        annotations = runner.github_annotations(results)
        for line in annotations:
            print(line)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary and annotations:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write("## Break TrustGate: bypass found\n\n")
                for line in annotations:
                    fh.write(f"- {line.split('::', 2)[-1]}\n")
                fh.write("\nSee CHALLENGE.md for what happens next.\n")

    missed, false_positives = runner.summarize(results)
    if bypasses:
        print(f"BYPASS FOUND  {bypasses} outside attack(s) got through", file=sys.stderr)
    if missed or false_positives:
        print(
            f"FAIL  {missed} missed attack(s), {false_positives} false positive(s)",
            file=sys.stderr,
        )
        return EXIT_DENIED

    print("PASS  every attack handled, zero false positives")
    return EXIT_OK


def _load_runner():
    """Import redteam.runner from the source tree, which is not packaged."""
    import importlib.util

    candidate = Path(__file__).resolve().parents[2] / "redteam" / "runner.py"
    if not candidate.is_file():
        return None
    name = "trustgate_redteam_runner"
    spec = importlib.util.spec_from_file_location(name, candidate)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    # Register before executing: @dataclass resolves annotations via
    # sys.modules[cls.__module__], which fails on an unregistered module.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _packaged_policy(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "policies" / name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustgate",
        description="A control and audit layer for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"trustgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-c", "--constitution", help="path to the constitution YAML")
        p.add_argument("-a", "--audit", help="path to the audit ledger JSONL")

    p_check = sub.add_parser("check", help="decide on one ActionRequest read from stdin")
    p_check.add_argument("--surface", default="coding", help="default surface if absent")
    add_common(p_check)
    p_check.set_defaults(func=cmd_check)

    p_verify = sub.add_parser("verify-audit", help="verify the audit hash chain")
    p_verify.add_argument("-a", "--audit", help="path to the audit ledger JSONL")
    p_verify.add_argument("--pubkey", action="append",
                          help="machine public key (base64) to check signatures; repeatable")
    p_verify.set_defaults(func=cmd_verify_audit)

    p_evidence = sub.add_parser(
        "evidence", help="build a control and audit evidence pack from the ledger"
    )
    p_evidence.add_argument("-a", "--audit", help="path to the audit ledger JSONL")
    p_evidence.add_argument("-c", "--constitution", help="path to the policy YAML")
    p_evidence.add_argument("--since", metavar="YYYY-MM-DD", help="start of the period")
    p_evidence.add_argument("--until", metavar="YYYY-MM-DD", help="end of the period")
    p_evidence.add_argument(
        "-f", "--format", default="html", choices=["html", "md", "json"]
    )
    p_evidence.add_argument(
        "-o", "--out", default="trustgate-evidence.html", help="file to write"
    )
    p_evidence.set_defaults(func=cmd_evidence)

    p_sync = sub.add_parser("sync", help="ship this machine's ledger to TrustGate Cloud")
    p_sync.add_argument("-a", "--audit", help="path to the audit ledger JSONL")
    p_sync.add_argument("--watch", type=float, metavar="SECONDS",
                        help="keep running, syncing every N seconds")
    p_sync.set_defaults(func=cmd_sync)

    p_pending = sub.add_parser(
        "pending", help="list escalations that no human has answered"
    )
    p_pending.add_argument("-a", "--audit", help="path to the audit ledger JSONL")
    p_pending.set_defaults(func=cmd_pending)

    p_serve = sub.add_parser("serve", help="run the HTTP Decision API")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    add_common(p_serve)
    p_serve.set_defaults(func=cmd_serve)

    p_validate = sub.add_parser("validate", help="parse and summarize a constitution")
    p_validate.add_argument("path", help="path to the constitution YAML")
    p_validate.set_defaults(func=cmd_validate)

    p_init = sub.add_parser("init", help="install the agent hook and a starter constitution")
    p_init.add_argument("--surface", default="coding", choices=["coding", "voice"])
    p_init.add_argument("--project", help="project root (default: current directory)")
    p_init.add_argument(
        "--force", action="store_true", help="overwrite an existing constitution"
    )
    p_init.set_defaults(func=cmd_init)

    p_pin = sub.add_parser(
        "pin-policy", help="approve the exact bytes of a policy file so the hook trusts it"
    )
    p_pin.add_argument("path", nargs="?", help="policy file (default: the configured one)")
    p_pin.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    p_pin.add_argument("--note", help="why this change was made")
    p_pin.add_argument("--list", action="store_true", help="show pinned policies")
    p_pin.set_defaults(func=cmd_pin_policy)

    p_gr = sub.add_parser("guardroom", help="run or talk to the guard room daemon")
    p_gr.add_argument("action", choices=["serve", "status", "resolve", "install-hook"])
    p_gr.add_argument("request_id", nargs="?", help="resolve: the escalation's request id")
    p_gr.add_argument("outcome", nargs="?", choices=["approved", "denied"])
    p_gr.add_argument("--approver", default="", help="resolve: your name")
    p_gr.add_argument("--note", help="resolve: a note kept with the answer")
    p_gr.add_argument("--prod", action="store_true",
                      help="use /var/lib/trustgate and /var/run/trustgate (own OS user)")
    p_gr.add_argument("--state", help="state folder (policy, log, key)")
    p_gr.add_argument("--run", help="socket folder")
    p_gr.add_argument("--dest", default=".claude/hooks/trustgate-guardroom.py",
                      help="install-hook: where to write the thin hook")
    p_gr.add_argument("--python", help="install-hook: python to run it with")
    p_gr.set_defaults(func=cmd_guardroom)

    p_approve = sub.add_parser(
        "approve", help="record the current hook/MCP configuration as reviewed"
    )
    p_approve.add_argument("--project", help="project root (default: current directory)")
    p_approve.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    p_approve.add_argument(
        "--force", action="store_true", help="rewrite the manifest even if unchanged"
    )
    p_approve.set_defaults(func=cmd_approve)

    p_test = sub.add_parser("test", help="run the red-team suite and print block rates")
    p_test.add_argument("--payloads", help="path to a payloads JSON file")
    p_test.add_argument(
        "--community-dir", help="folder of one-file community attacks (default: redteam/community)"
    )
    p_test.add_argument(
        "--no-community", action="store_true", help="run only the built-in payloads"
    )
    add_common(p_test)
    p_test.set_defaults(func=cmd_test)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
