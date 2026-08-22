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
import sys
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
    if cfg.judge.enabled:
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
    result = AuditLedger(path).verify()

    if result.ok:
        print(f"OK  chain intact — {result.entries_checked} entries verified ({path})")
        return EXIT_OK

    print(f"FAIL  chain broken at seq {result.broken_seq} ({path})", file=sys.stderr)
    print(f"      {result.detail}", file=sys.stderr)
    print(f"      {result.entries_checked} entries verified before the break", file=sys.stderr)
    return EXIT_DENIED


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

    try:
        results = runner.run(constitution_path, payloads, audit_path=args.audit)
    except (ConstitutionError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    print(f"constitution: {constitution_path}")
    print(f"payloads:     {payloads}")
    print(runner.format_table(results))

    missed, false_positives = runner.summarize(results)
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
    p_verify.set_defaults(func=cmd_verify_audit)

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
    add_common(p_test)
    p_test.set_defaults(func=cmd_test)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
