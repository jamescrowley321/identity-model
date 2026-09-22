"""Self-test for the cross-language vector-coverage gate (tools/spec_coverage_gate.py).

The gate is the only thing standing between ``spec/vectors`` and a parity claim
nobody checks: if it passes vacuously, every language can silently stop
executing a vector while ``spec/`` still advertises cross-language coverage.
That is not hypothetical — ``id-token.json`` carried executable vectors that all
three languages ran and *no* language was gated on, because the capability was
invisible to the gate.

So the failure paths are pinned here, not just the green one. Each test drives
``check_reports`` against a synthetic ``spec/vectors`` tree and a synthetic
report directory, which is the same pair of inputs CI gives it.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_DRIVER = _REPO_ROOT / "tools" / "spec_coverage_gate.py"
_spec = importlib.util.spec_from_file_location("spec_coverage_gate", _DRIVER)
assert _spec is not None
assert _spec.loader is not None
spec_coverage_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(spec_coverage_gate)

check_reports = spec_coverage_gate.check_reports
report_name = spec_coverage_gate.report_name
spec_inventory = spec_coverage_gate.spec_inventory

LANGUAGES = ["python", "go", "rust"]

GATE_PASSED = 0
GATE_FAILED = 1


def _capability(
    name: str,
    case_ids: list[str],
    vectors_per_case: int = 1,
    **extra: object,
) -> dict[str, object]:
    """A vector file with one executable case per id, each carrying N vectors."""
    return {
        "capability": name,
        "tests": [
            {
                "id": case_id,
                "vectors": [
                    {"name": f"{case_id} vector {i}"} for i in range(vectors_per_case)
                ],
            }
            for case_id in case_ids
        ],
        **extra,
    }


@pytest.fixture
def gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the gate at a synthetic spec dir + report dir it fully controls."""
    spec_dir = tmp_path / "spec" / "vectors"
    spec_dir.mkdir(parents=True)
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    monkeypatch.setattr(spec_coverage_gate, "SPEC_DIR", spec_dir)
    monkeypatch.setattr(spec_coverage_gate, "LANGUAGES", LANGUAGES)
    # UNVECTORED describes the real spec/ tree, like OPTED_OUT. A synthetic tree
    # must not be judged against it — the live constant is guarded separately by
    # test_the_unvectored_list_matches_the_real_spec_tree.
    monkeypatch.setattr(spec_coverage_gate, "UNVECTORED", {})

    class Gate:
        def __init__(self) -> None:
            self.spec_dir = spec_dir
            self.report_dir = report_dir

        def write_capability(
            self,
            name: str,
            case_ids: list[str],
            vectors_per_case: int = 1,
            **extra: object,
        ) -> None:
            (spec_dir / f"{name}.json").write_text(
                json.dumps(_capability(name, case_ids, vectors_per_case, **extra))
            )

        def configure_runners(self, pairs: list[tuple[str, str]]) -> None:
            monkeypatch.setattr(
                spec_coverage_gate,
                "RUNNERS",
                [(lang, cap, Path("."), ["true"]) for lang, cap in pairs],
            )

        def write_report(
            self,
            language: str,
            capability: str,
            executed: list[str],
            vectors_per_case: int = 1,
            **extra: object,
        ) -> None:
            # Reports must declare how many vectors each case ran, so the default
            # mirrors the default capability shape: one vector per case.
            body: dict[str, object] = {
                "language": language,
                "capability": capability,
                "executed": executed,
                "executed_vectors": {c: vectors_per_case for c in executed},
                "native": {},
            }
            body.update(extra)
            (report_dir / report_name(language, capability)).write_text(
                json.dumps(body)
            )

        def write_raw_report(self, language: str, capability: str, body: str) -> None:
            (report_dir / report_name(language, capability)).write_text(body)

        def run(self) -> int:
            return check_reports(report_dir)

    return Gate()


def _all_green(gate, capability: str, case_ids: list[str]) -> None:
    gate.write_capability(capability, case_ids)
    gate.configure_runners([(lang, capability) for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, capability, case_ids)


def test_every_language_executed_every_case_passes(gate, capsys) -> None:
    _all_green(gate, "validation", ["V-001", "V-002"])

    assert gate.run() == GATE_PASSED
    assert "GATE PASSED" in capsys.readouterr().out


def test_two_capabilities_are_gated_independently(gate, capsys) -> None:
    """The per-(language, capability) split: both capabilities must be named."""
    gate.write_capability("validation", ["V-001"])
    gate.write_capability("id-token", ["IDT-001"])
    gate.configure_runners(
        [(lang, cap) for cap in ("validation", "id-token") for lang in LANGUAGES]
    )
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"])
        gate.write_report(lang, "id-token", ["IDT-001"])

    assert gate.run() == GATE_PASSED
    out = capsys.readouterr().out
    assert "GATE PASSED" in out
    assert "id-token (1 vector), validation (1 vector)" in out


def test_one_language_skipping_one_case_fails_by_name(gate, capsys) -> None:
    _all_green(gate, "id-token", ["IDT-001", "IDT-004"])
    gate.write_report("go", "id-token", ["IDT-001"])  # IDT-004 dropped

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "GATE FAILED" in out
    assert "(go, id-token, IDT-004): vector case not executed" in out
    assert "IDT-001" not in out.split("GATE FAILED")[1]


def test_capability_with_no_runner_fails_for_every_language(gate, capsys) -> None:
    """A vector file nobody runs is worse than none — it looks covered."""
    gate.write_capability("validation", ["V-001"])
    gate.write_capability("tmp-probe", ["P-001"])
    gate.configure_runners([(lang, "validation") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"])

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "capabilities with no runner" in out
    for lang in LANGUAGES:
        assert f"({lang}, tmp-probe)" in out


def test_missing_report_file_fails_by_name(gate, capsys) -> None:
    _all_green(gate, "id-token", ["IDT-001"])
    (gate.report_dir / report_name("rust", "id-token")).unlink()

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "(rust, id-token): no coverage report produced" in out


def test_malformed_report_is_a_named_failure_not_a_traceback(gate, capsys) -> None:
    """One truncated report must not hide the other languages' real gaps.

    ``json.loads`` on a half-written report raises JSONDecodeError; uncaught,
    that aborts check_reports mid-loop and every not-yet-checked pair goes
    unreported behind a stack trace.
    """
    _all_green(gate, "id-token", ["IDT-001", "IDT-004"])
    gate.write_raw_report("python", "id-token", '{"language": "python", "exec')
    gate.write_report("go", "id-token", ["IDT-001"])  # real gap, checked later

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "(python, id-token): coverage report" in out
    assert "unreadable or malformed" in out
    # The point of not raising: the Go gap is still reported in the same run.
    assert "(go, id-token, IDT-004): vector case not executed" in out


def test_report_without_a_capability_key_is_a_named_failure(gate, capsys) -> None:
    _all_green(gate, "id-token", ["IDT-001"])
    gate.write_raw_report("rust", "id-token", json.dumps({"executed": ["IDT-001"]}))

    assert gate.run() == GATE_FAILED
    assert "not a report object with a 'capability' key" in capsys.readouterr().out


def test_report_declaring_the_wrong_capability_fails(gate, capsys) -> None:
    _all_green(gate, "id-token", ["IDT-001"])
    gate.write_raw_report(
        "go",
        "id-token",
        json.dumps(
            {"language": "go", "capability": "validation", "executed": ["IDT-001"]}
        ),
    )

    assert gate.run() == GATE_FAILED
    assert "runner and gate disagree" in capsys.readouterr().out


def test_native_case_without_an_anchor_fails(gate, capsys) -> None:
    (gate.spec_dir / "validation.json").write_text(
        json.dumps(
            {
                "capability": "validation",
                "tests": [
                    {"id": "V-001", "vectors": [{"name": "v"}]},
                    {"id": "V-NAT", "vectors": [{"name": "n"}], "execution": "native"},
                ],
            }
        )
    )
    gate.configure_runners([(lang, "validation") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"])

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "(python, validation, V-NAT): native case has no native-test anchor" in out


def test_opted_out_capability_stays_out_of_the_gate(gate, capsys, monkeypatch) -> None:
    """The opt-out is honoured — and does not trip the no-runner check."""
    monkeypatch.setattr(spec_coverage_gate, "OPTED_OUT", frozenset({"dpop"}))
    gate.write_capability("validation", ["V-001"])
    gate.write_capability("dpop", ["DPOP-001"])
    gate.configure_runners([(lang, "validation") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"])

    assert gate.run() == GATE_PASSED
    out = capsys.readouterr().out
    assert "dpop" not in out
    assert "GATE PASSED" in out


def test_a_vector_file_cannot_exempt_itself_from_the_gate(gate, capsys) -> None:
    """The old in-file marker is data the gate reads, so it must not be honoured.

    A capability that could exempt itself by editing its own vector file left the
    gate printing GATE PASSED over a capability nobody ran: the no-runner check
    iterates the same inventory the marker emptied, so it could not see the
    exclusion either. Opting out is now a diff to the gate, not to the data.
    """
    gate.write_capability("validation", ["V-001"])
    gate.write_capability("dpop", ["DPOP-001"], cross_language_coverage_gate="pending")
    gate.configure_runners([(lang, "validation") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"])

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "capabilities with no runner" in out
    assert "dpop" in out


def test_a_case_that_runs_fewer_vectors_than_the_spec_carries_fails(
    gate, capsys
) -> None:
    """Executing one of a case's five vectors is not executing the case.

    The gate verified case ids only, so four of IDT-003's five vectors could be
    deleted and every language still reported the case executed.
    """
    gate.write_capability("validation", ["V-001"], vectors_per_case=5)
    gate.configure_runners([(lang, "validation") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"], vectors_per_case=5)
    gate.write_report("go", "validation", ["V-001"], vectors_per_case=1)

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "(go, validation, V-001): ran 1 of 5 vectors" in out


def test_a_non_integer_vector_count_is_a_named_failure(gate, capsys) -> None:
    """A bad count must not crash the stats arithmetic and abort the whole check.

    `min()` and `sum()` run over these counts, so a string count raises TypeError
    there and every not-yet-checked pair goes unreported behind a traceback — the
    same failure mode the malformed-JSON guard exists to prevent.
    """
    _all_green(gate, "id-token", ["IDT-001", "IDT-004"])
    gate.write_raw_report(
        "python",
        "id-token",
        json.dumps(
            {
                "language": "python",
                "capability": "id-token",
                "executed": ["IDT-001", "IDT-004"],
                "executed_vectors": {"IDT-001": "one", "IDT-004": 1},
                "native": {},
            }
        ),
    )
    gate.write_report(
        "go",
        "id-token",
        ["IDT-001"],
        executed_vectors={"IDT-001": 1},
    )  # real gap, checked after python

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "(python, id-token): 'executed_vectors' has non-integer" in out
    assert "IDT-001" in out
    # The point of not raising: the Go gap is still reported in the same run.
    assert "(go, id-token, IDT-004): vector case not executed" in out


def test_a_boolean_vector_count_is_rejected(gate, capsys) -> None:
    """bool is an int in Python; True must not be counted as one vector."""
    _all_green(gate, "id-token", ["IDT-001"])
    gate.write_raw_report(
        "rust",
        "id-token",
        json.dumps(
            {
                "language": "rust",
                "capability": "id-token",
                "executed": ["IDT-001"],
                "executed_vectors": {"IDT-001": True},
                "native": {},
            }
        ),
    )

    assert gate.run() == GATE_FAILED
    assert (
        "(rust, id-token): 'executed_vectors' has non-integer"
        in capsys.readouterr().out
    )


def test_a_report_without_vector_counts_fails(gate, capsys) -> None:
    """A runner that reports only case ids cannot prove it ran every vector."""
    gate.write_capability("validation", ["V-001"])
    gate.configure_runners([(lang, "validation") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-001"])
    gate.write_raw_report(
        "rust",
        "validation",
        json.dumps(
            {
                "language": "rust",
                "capability": "validation",
                "executed": ["V-001"],
                "native": {},
            }
        ),
    )

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "(rust, validation): report has no 'executed_vectors'" in out


def test_malformed_vector_file_names_itself(gate) -> None:
    (gate.spec_dir / "broken.json").write_text("{not json")

    with pytest.raises(SystemExit) as excinfo:
        spec_inventory()
    assert "broken.json is not valid JSON" in str(excinfo.value)


def test_no_capability_is_currently_opted_out_of_the_gate() -> None:
    """Guards the live constant: OPTED_OUT is a debt register, not a setting.

    Every entry is a capability nobody gates. Adding one has to be a deliberate,
    reviewed change to this file — which is the whole reason the opt-out moved
    here out of the vector files, where a capability could exempt itself.
    """
    assert spec_coverage_gate.OPTED_OUT == frozenset(), (
        f"capabilities outside the cross-language gate: "
        f"{sorted(spec_coverage_gate.OPTED_OUT)} — each one is a coverage claim "
        f"nothing checks"
    )


def test_the_unvectored_list_matches_the_real_spec_tree() -> None:
    """Guards the live constant against the spec tree it describes.

    UNVECTORED is a debt register, and a register that drifts is worse than
    none: a capability could drop its vectors and be covered by a stale entry,
    or gain them and stay exempt. Both directions are asserted against the real
    spec/ so the list can only be wrong in a way this fails on.
    """
    inventory, unvectored = spec_coverage_gate.spec_inventory()
    declared = set(spec_coverage_gate.UNVECTORED)

    assert unvectored - declared - spec_coverage_gate.OPTED_OUT == set(), (
        "capabilities carry no executable vectors and are named in neither "
        f"UNVECTORED nor OPTED_OUT: {sorted(unvectored - declared)} — nothing "
        "gates them and nothing says so"
    )
    assert declared & set(inventory) == set(), (
        f"capabilities listed in UNVECTORED now carry executable vectors: "
        f"{sorted(declared & set(inventory))} — remove the entry so the gate "
        "enforces them"
    )
    assert declared - unvectored == set(), (
        f"UNVECTORED names capabilities that are not in spec/: "
        f"{sorted(declared - unvectored)}"
    )


def test_a_capability_cannot_leave_the_gate_by_dropping_its_vectors(
    gate, capsys
) -> None:
    """The self-exemption the module's own docstring forbids.

    A vector file that empties its `vectors` arrays used to disappear from the
    inventory, and the no-runner check iterated that same emptied inventory --
    so the gate printed GATE PASSED having inspected nothing. The capability
    left enforcement by editing the data the gate reads, which is precisely
    what moving the opt-out into this module was meant to make impossible.
    """
    # Two capabilities, as the real tree has: stripping one must not merely
    # empty the inventory (which already fails closed) but be caught while
    # another capability still reports coverage -- the live shape, where two of
    # twelve carried vectors and the gate passed for all twelve.
    gate.write_capability("validation", ["V-1", "V-2"])
    gate.write_capability("id-token", ["I-1"])
    gate.configure_runners(
        [(lang, cap) for lang in LANGUAGES for cap in ("validation", "id-token")]
    )
    for lang in LANGUAGES:
        gate.write_report(lang, "validation", ["V-1", "V-2"])
        gate.write_report(lang, "id-token", ["I-1"])
    assert gate.run() == GATE_PASSED

    path = gate.spec_dir / "id-token.json"
    capability = json.loads(path.read_text())
    for case in capability["tests"]:
        case.pop("vectors", None)
    path.write_text(json.dumps(capability))

    assert gate.run() == GATE_FAILED
    assert "carries no executable `vectors`" in capsys.readouterr().out


def _write_native_only(gate, name: str, case_ids: list[str]) -> None:
    """A capability whose cases are ALL `execution: "native"` — no vectors."""
    (gate.spec_dir / f"{name}.json").write_text(
        json.dumps(
            {
                "capability": name,
                "tests": [{"id": c, "execution": "native"} for c in case_ids],
            }
        )
    )


def test_a_native_only_capability_stays_in_the_gate(gate, capsys) -> None:
    """It carries no `vectors`, but it is not unvectored.

    Keyed on executable vectors alone, a capability whose cases are all
    `execution: "native"` fell through to `unvectored` and its `native` set was
    discarded, so its per-language anchors were never checked. It must instead
    require runners like any other gated capability.
    """
    _write_native_only(gate, "dpop", ["N-1", "N-2"])
    gate.configure_runners([])

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "no runner" in out
    # The message must not claim executable vectors it does not have.
    assert "2 native cases" in out
    assert "executable vectors" not in out


def test_a_native_only_capability_fails_when_its_anchors_are_missing(
    gate, capsys
) -> None:
    """The check that was being dropped, now reachable."""
    _write_native_only(gate, "dpop", ["N-1", "N-2"])
    gate.configure_runners([(lang, "dpop") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "dpop", [], native={"N-1": "tests::n1"})

    assert gate.run() == GATE_FAILED
    out = capsys.readouterr().out
    assert "N-2): native case has no native-test anchor" in out


def test_a_native_only_capability_passes_when_every_anchor_is_present(
    gate, capsys
) -> None:
    _write_native_only(gate, "dpop", ["N-1", "N-2"])
    gate.configure_runners([(lang, "dpop") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(
            lang, "dpop", [], native={"N-1": "tests::n1", "N-2": "tests::n2"}
        )

    assert gate.run() == GATE_PASSED


def test_a_capability_cannot_leave_the_gate_by_going_all_native(
    gate, capsys, monkeypatch
) -> None:
    """The exemption route the failure message used to steer you into.

    A native-only capability landed in `unvectored`, so the gate failed asking
    for it to be named in UNVECTORED — and naming it there made the gate pass
    while its native anchors went unchecked in every language, permanently.
    Declaring it unvectored must now be rejected instead, because it IS gated.
    """
    _write_native_only(gate, "dpop", ["N-1", "N-2"])
    gate.configure_runners([(lang, "dpop") for lang in LANGUAGES])
    for lang in LANGUAGES:
        gate.write_report(lang, "dpop", [], native={})

    monkeypatch.setattr(spec_coverage_gate, "UNVECTORED", {"dpop": 2})
    assert gate.run() == GATE_FAILED
    assert "still listed in UNVECTORED" in capsys.readouterr().out


def test_the_real_spec_tree_has_a_runner_for_every_gated_capability() -> None:
    """Guards the live config, not a fixture: RUNNERS must cover spec/vectors."""
    inventory, _ = spec_coverage_gate.spec_inventory()
    configured = {(lang, cap) for lang, cap, _, _ in spec_coverage_gate.RUNNERS}
    missing = [
        (lang, cap)
        for cap in sorted(inventory)
        for lang in spec_coverage_gate.LANGUAGES
        if (lang, cap) not in configured
    ]
    assert not missing, f"spec/vectors capabilities with no runner: {missing}"
