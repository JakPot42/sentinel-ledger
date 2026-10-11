"""docs/SPEC.md section 8.3: plant a bug in the recorder and show a check turns red.

Each case builds the recorder with one deliberate bug, runs the scenario that exercises
it, and requires a non-zero exit code from the check named, with the finding named. The
same scenarios pass with the clean recorder in test_scenarios.py, so a red result here
comes from the bug and nothing else.

At the end is one planted bug in the gate that needs no robot: the gate without its check
of a record's canonical form. The gate's other planted bugs need the simulated robot and
are in test_ros2.py.
"""
import json
import os
import subprocess
import sys

import pytest

import run_scenarios
from test_gate import SPACED, in_another_encoding

# feature, scenario, the exit code that must turn red, the finding that must appear
CASES = [
    ("planted-bug-no-heartbeat", 1, "verifier_exit", "HEARTBEAT_GAP"),
    ("planted-bug-clamp-bound", 2, "verifier_exit", "RULE_MISMATCH"),
    ("planted-bug-skip-block", 3, "verifier_exit", "RULE_MISMATCH"),
    ("planted-bug-stale-in-force", 4, "verifier_exit", "IN_FORCE_MISMATCH"),
    ("planted-bug-forward-first", 5, "verifier_exit", "GATE_HEAD_NOT_IN_JOURNAL"),
]


@pytest.mark.parametrize("feature,number,exit_key,finding", CASES)
def test_planted_bug_is_caught(feature, number, exit_key, finding, planted, tmp_path):
    observed = run_scenarios.run_scenario(number, planted(feature), str(tmp_path))
    assert observed[exit_key] == 2, observed
    assert finding in observed["findings"], observed
    assert {k: observed.get(k) for k in run_scenarios.EXPECTED[number]} != run_scenarios.EXPECTED[number]


def test_forward_first_is_caught_by_the_gate_and_not_by_the_actuators_log(planted, tmp_path):
    """A recorder that forwards before it records, and then fails to record.

    What the gate can and cannot do, measured:
      - it cannot stop that one command. The record it was shown was well formed and
        extended the chain; the gate has no way to know it never reached the disk;
      - its head is then a record the journal does not hold, and the verifier, given
        only the gate's state file and the journal, exits 2;
      - when the recorder is restarted its first record does not follow the gate's
        head, so the gate refuses it and every record after it. The machine gets the
        safe state and nothing else until someone resolves the difference.
    Nothing here reads the demo actuator's own log to decide pass or fail."""
    observed = run_scenarios.run_scenario(5, planted("planted-bug-forward-first"), str(tmp_path))
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["GATE_HEAD_NOT_IN_JOURNAL"]
    assert observed["gate_exit_after_restart"] == 2
    assert observed["commands_recorded"] is None  # the verifier stopped at level 1
    # Shown for the record, not used as the test's verdict: the unrecorded command did
    # reach the actuator, and after the restart only safe-state actions did.
    assert observed["sent"][2] == ("applied", 900)
    assert ("applied", 400) not in observed["sent"]
    assert observed["sent"][-3:] == [("gate_refused", 0)] * 3


def test_the_gate_alone_does_not_bound_unrecorded_commands_to_one(planted, tmp_path):
    """A worse recorder: it forwards first, ignores the failed write and keeps its chain in
    memory. The gate sees records that follow each other and passes both commands. Neither
    is in the journal. The bound of one in the test above belongs to a recorder that stops
    on a failed write, not to the gate. What still holds: the gate's head is not in the
    journal, so the verifier exits 2, and the restarted recorder is refused."""
    observed = run_scenarios.run_scenario(5, planted("planted-bug-forward-and-ignore-failed-write"), str(tmp_path))
    assert observed["sent"][2:4] == [("applied", 900), ("applied", 300)]
    assert observed["gate_exit"] == 0
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["GATE_HEAD_NOT_IN_JOURNAL"]
    assert observed["gate_exit_after_restart"] == 2
    assert ("applied", 400) not in observed["sent"]


# --- a planted bug in the gate, on the file path -----------------------------------------

def a_copy_in_another_encoding_arrives_first(recorder, out, gate_program):
    """The recorder as shipped records four commands and stops. Before the gate runs, a
    copy of the third command's message in another encoding is put on the link in front of
    the genuine one, as a node with no key that got there first would put it. Then the
    gate program given is run over the link, and the verifier over the journal. Returns
    what was observed."""
    w = run_scenarios.Workspace(str(out), "another_encoding_first", recorder)
    ops = "".join(json.dumps(run_scenarios.command(speed)) + "\n" for speed in (200, 400, 600, 800))
    recorded = subprocess.run(w.run_args("2026-10-01T08:00:00Z"), input=ops, capture_output=True, text=True)
    root = [json.loads(text) for text in recorded.stdout.splitlines() if text.strip()][-1]["root"]
    with open(w.link, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    messages = [json.loads(text) for text in lines]
    third = [i for i, m in enumerate(messages) if json.loads(m["record"])["kind"] == "command"][2]
    genuine = messages[third]
    copy = in_another_encoding(genuine, SPACED)
    with open(w.link, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(text + "\n" for text in lines[:third] + [json.dumps(copy)] + lines[third:]))

    gate = subprocess.run([sys.executable, gate_program, "--link", w.link, "--state", w.gate_state,
                           "--actuator", w.actuator, "--safe-state", run_scenarios.SAFE_STATE,
                           "--public-key", w.public_key], capture_output=True, text=True)
    with open(w.gate_state, encoding="utf-8") as fh:
        head = json.load(fh)
    code, report = w.verify(root=root, witness=False)
    return {"recorder_exit": recorded.returncode, "gate_exit": gate.returncode, "gate_said": gate.stdout,
            "sent": w.sent(), "head": (head["n"], head["hash"]), "genuine": (genuine["n"], genuine["hash"]),
            "copy": (copy["n"], copy["hash"]), "last_record": (messages[-1]["n"], messages[-1]["hash"]),
            "verifier_exit": code, "findings": run_scenarios.kinds(report),
            "commands": report.get("counts", {}).get("commands"),
            "verifier_exit_without_the_gates_state": w.verify(root=root, witness=False, gate=False)[0]}


AS_RECORDED = [("applied", 200), ("applied", 400), ("gate_refused", 0), ("applied", 600), ("applied", 800)]


def test_a_copy_in_another_encoding_sent_first_is_refused_and_the_journal_still_verifies(recorder, tmp_path):
    """The gate refuses the copy for its form and sends the safe state, as for any refusal.
    Its head does not move, so the genuine record still follows it and is carried out, and
    so is every record after it. The verifier, given the gate's state, finds the gate's
    head in the journal and has no findings."""
    seen = a_copy_in_another_encoding_arrives_first(recorder, tmp_path, run_scenarios.GATE)
    assert seen["recorder_exit"] == 0
    assert seen["gate_exit"] == 2 and seen["gate_said"].count("REFUSED") == 1
    assert "REFUSED: the record is not in canonical form" in seen["gate_said"]
    assert seen["sent"] == AS_RECORDED
    assert seen["head"] == seen["last_record"]
    assert (seen["verifier_exit"], seen["findings"], seen["commands"]) == (0, [], 4)


def test_planted_bug_gate_does_not_check_a_records_canonical_form(recorder, tmp_path):
    """The gate with its check of the canonical form removed, which is the gate as it was.
    It checks the signature over a re-serialisation of the record, so the copy passes: the
    command in it is carried out, and the gate's head becomes the hash of the copy's text,
    which is in no journal. The genuine record, arriving second, is refused for its place
    in the chain, and so is every record the recorder sends after it. The journal on its
    own is clean. Beside the gate's state the verifier exits 2: a false alarm against an
    honest recorder, raised by a node that holds no key.

    Planted the same way as the gate's bugs in test_ros2.py: a copy of the gate with one
    line changed, after proving the line was there to change. Here the copy is run as the
    file demo's gate program, so no robot is needed."""
    broken = tmp_path / "gate_without_the_form_check"
    broken.mkdir()
    with open(run_scenarios.GATE, encoding="utf-8") as fh:
        source = fh.read()
    check = "    if not in_canonical_form(raw, record):"
    assert source.count(check) == 1
    (broken / "actuator_gate.py").write_text(source.replace(check, "    if False:"), encoding="utf-8")

    seen = a_copy_in_another_encoding_arrives_first(recorder, tmp_path / "broken",
                                                    os.path.join(str(broken), "actuator_gate.py"))
    assert seen["sent"] == [("applied", 200), ("applied", 400), ("applied", 600)] + [("gate_refused", 0)] * 3
    assert seen["gate_exit"] == 2 and seen["gate_said"].count("REFUSED: does not extend the chain") == 3
    assert seen["head"] == seen["copy"] and seen["head"] != seen["genuine"]
    assert seen["verifier_exit_without_the_gates_state"] == 0
    assert (seen["verifier_exit"], seen["findings"]) == (2, ["GATE_HEAD_NOT_IN_JOURNAL"])

    # The same with the real gate, in the same test, so the difference is the one line.
    seen = a_copy_in_another_encoding_arrives_first(recorder, tmp_path / "real", run_scenarios.GATE)
    assert seen["sent"] == AS_RECORDED and seen["head"] == seen["last_record"]
    assert (seen["verifier_exit"], seen["findings"]) == (0, [])
