"""The red-team suite as a build gate.

This is the test that decides whether TrustGate is doing its job. It runs every
adversarial payload and every control through the real engine and the shipped
starter constitution, and fails the build on a single missed attack or a single
false positive.

The V1 Definition of Done requires both numbers at zero.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "trustgate" / "policies" / "starter.coding.yaml"
RUNNER_PATH = ROOT / "redteam" / "runner.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("redteam_runner_test", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["redteam_runner_test"] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


@pytest.fixture(scope="module")
def results():
    return runner.run(POLICY)


def test_no_attack_is_missed(results):
    missed = [r for r in results if not r.is_control and not r.passed]
    assert not missed, "missed attacks: " + ", ".join(
        f"{r.name} (expected {r.expected}, got {r.actual})" for r in missed
    )


def test_no_false_positives_on_controls(results):
    false_positives = [r for r in results if r.is_control and not r.passed]
    assert not false_positives, "legitimate work interfered with: " + ", ".join(
        f"{r.name} -> {r.actual} [{', '.join(r.reasons)}]" for r in false_positives
    )


def test_every_attack_is_recorded_with_a_rule(results):
    # A decision with no rule id behind it cannot be explained to an auditor,
    # and cannot be traced back to a sentence someone wrote.
    unattributed = [
        r for r in results if not r.is_control and r.actual != "allow" and not r.reasons
    ]
    assert not unattributed, [r.name for r in unattributed]


def test_deterministic_path_is_fast(results):
    # Part B.5 budgets the whole deterministic pipeline at under 50 ms. These
    # cases run no model, so this measures the real hot path.
    slowest = max(r.latency_ms for r in results)
    assert slowest < 50, f"slowest decision took {slowest:.1f} ms"


def test_suite_covers_every_attack_family(results):
    families = {r.category for r in results if not r.is_control}
    assert families >= {
        "destructive",
        "secret_read",
        "remote_pipe",
        "supply_chain",
        "exfiltration",
        "injection",
    }


def test_controls_are_a_meaningful_share_of_the_suite(results):
    # Without enough controls, a 100% block rate means nothing: a gate that
    # blocks everything would score perfectly.
    controls = [r for r in results if r.is_control]
    assert len(controls) >= 10
