"""docs/SPEC.md section 8.3: plant a bug in the recorder and show a check turns red.

Each case builds the recorder with one deliberate bug, runs the scenario that exercises
it, and requires a non-zero exit code from the check named, with the finding named. The
same scenarios pass with the clean recorder in test_scenarios.py, so a red result here
comes from the bug and nothing else.
"""
import pytest

import run_scenarios

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
