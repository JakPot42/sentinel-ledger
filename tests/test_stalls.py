"""Storage stalls and anchors that lag.

A storage stall: the disk took longer than twice the heartbeat interval to confirm a
write, and the recorder said so in a `storage_stall` record once it could. The verifier
reports that as STORAGE_STALL. It is still a finding and the exit code is still 2. What
changes is that the gap has a stated cause, with a measured duration, in a signed record.

Anchors: the ROS node writes anchor statements off the recorder's lock, so an anchor can
arrive late, and if the disk fails it can be missing. These tests show what that can and
cannot do to verification.
"""
import datetime
import json
import os

import pytest

import run_scenarios
from test_tamper import ALONE, attach, findings, forge, state_root

FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def later(at, seconds):
    return (datetime.datetime.strptime(at, FORMAT) + datetime.timedelta(seconds=seconds)).strftime(FORMAT)


@pytest.fixture()
def run2(recorder, tmp_path):
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    return w, state_root(w)


def a_gap_after_record_3(seconds, stall=None):
    """Push every record after record 3 later by `seconds`, and optionally put a
    storage_stall record first among them. The demo conveyor's heartbeat is 60 s, so
    anything over 120 s is a gap."""
    def change(records):
        for rec in records[4:]:
            rec["at"] = later(rec["at"], seconds)
        if stall is not None:
            record = dict({"schema": records[3]["schema"], "kind": "storage_stall", "at": records[4]["at"]}, **stall)
            records.insert(4, record)
        return records
    return change


def verify_alone(w, change):
    root = forge(w, change)
    return w.verify(root=root, **ALONE)


def test_a_gap_with_nothing_said_about_it_is_a_heartbeat_gap(run2):
    w, _ = run2
    code, report = verify_alone(w, a_gap_after_record_3(200))
    assert (code, findings(report)) == (2, ["HEARTBEAT_GAP"])


def test_a_gap_the_recorder_accounts_for_is_reported_as_a_storage_stall(run2):
    w, _ = run2
    stall = {"step": "journal_write", "of_record": 3, "stalled_ms": 199000}
    code, report = verify_alone(w, a_gap_after_record_3(200, stall))
    # Still a finding, still a nonzero exit. Not an unexplained gap.
    assert (code, findings(report)) == (2, ["STORAGE_STALL"])
    found = report["findings"][0]
    assert (found["n"], found["of_record"], found["stalled_ms"], found["step"]) == (4, 3, 199000, "journal_write")
    assert report["counts"]["storage_stalls"] == 1


def test_a_stall_too_short_to_account_for_the_gap_leaves_the_gap_unexplained(run2):
    """A 10-second stall does not explain 200 seconds of silence. The threshold is the
    same as for any gap: what the stall leaves over must be within twice the heartbeat."""
    w, _ = run2
    stall = {"step": "journal_write", "of_record": 3, "stalled_ms": 10000}
    code, report = verify_alone(w, a_gap_after_record_3(200, stall))
    assert (code, findings(report)) == (2, ["HEARTBEAT_GAP", "STORAGE_STALL"])


def test_the_threshold_for_a_gap_is_not_moved_by_a_stall_record(run2):
    """Exactly at the edge: 320 s of silence, 200 s of it stated. The 120 s left over is
    twice the heartbeat, which is allowed. One second more and it is a gap again."""
    w, _ = run2
    stall = {"step": "journal_write", "of_record": 3, "stalled_ms": 200000}
    # Records 3 and 4 were one second apart to begin with.
    assert findings(verify_alone(w, a_gap_after_record_3(319, stall))[1]) == ["STORAGE_STALL"]


def test_one_second_past_the_threshold_is_a_gap_again(run2):
    w, _ = run2
    stall = {"step": "journal_write", "of_record": 3, "stalled_ms": 200000}
    assert findings(verify_alone(w, a_gap_after_record_3(320, stall))[1]) == ["HEARTBEAT_GAP", "STORAGE_STALL"]


def test_a_stall_record_is_a_finding_even_when_it_left_no_gap(run2):
    w, _ = run2
    stall = {"step": "journal_write", "of_record": 3, "stalled_ms": 121000}
    code, report = verify_alone(w, a_gap_after_record_3(0, stall))
    assert (code, findings(report)) == (2, ["STORAGE_STALL"])


@pytest.mark.parametrize("stall", [
    {"step": "journal_write", "of_record": 3},
    {"step": "journal_write", "of_record": 3, "stalled_ms": "long"},
    {"step": "journal_write", "of_record": 3, "stalled_ms": 0},
    {"of_record": 3, "stalled_ms": 199000},
])
def test_a_stall_record_without_usable_numbers_explains_nothing(run2, stall):
    w, _ = run2
    code, report = verify_alone(w, a_gap_after_record_3(200, stall))
    assert (code, findings(report)) == (2, ["HEARTBEAT_GAP", "RECORD_MALFORMED"])


def test_an_outsider_cannot_explain_a_gap_away(run2):
    """Someone who can write to the journal but not read the key inserts a stall record to
    cover a gap. It is not signed by the recorder, and that is found."""
    w, _ = run2
    stall = {"step": "journal_write", "of_record": 3, "stalled_ms": 199000}
    root = forge(w, a_gap_after_record_3(200, stall), with_the_key=False)
    code, report = w.verify(root=root, **ALONE)
    assert code == 2 and ("SIGNATURE_MISSING" in findings(report) or "SIGNATURE_INVALID" in findings(report))


# --- anchors that lag or are missing ------------------------------------------------------

def witness_keeps(w, keep):
    """Cut the witness's store down to the anchors `keep` says yes to: what the witness
    would hold if later anchors were still on their way, or never arrived."""
    with open(w.witness_store, encoding="utf-8") as fh:
        lines = [line for line in fh if line.strip()]
    kept = [line for line in lines if keep(json.loads(line)["entry_count"])]
    with open(w.witness_store, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(kept)
    return len(lines), len(kept)


def rewrite_record_3(records):
    """What test_tamper.py's operator does: the clamped command never asked for 1800."""
    records[3].update({"requested": {"speed_mm_s": 1400}, "applied": {"speed_mm_s": 1400},
                       "outcome": "unchanged", "rules_acted": []})
    records[3]["reported"] = {"applied": {"speed_mm_s": 1400}, "outcome": "unchanged", "rules_acted": []}


def rewrite_the_last_command(records):
    """The same kind of rewrite, of the last command in the journal: a record that only
    the last anchor covers."""
    n = max(i for i, r in enumerate(records) if r["kind"] == "command")
    assert n >= 4
    was = records[n]["applied"]["speed_mm_s"]
    records[n].update({"requested": {"speed_mm_s": was - 100}, "applied": {"speed_mm_s": was - 100},
                       "outcome": "unchanged", "rules_acted": []})
    records[n]["reported"] = {"applied": {"speed_mm_s": was - 100}, "outcome": "unchanged", "rules_acted": []}


def test_the_witness_holds_an_anchor_at_4_and_one_at_7(run2):
    w, _ = run2
    assert witness_keeps(w, lambda count: True) == (2, 2)
    assert w.verify(gate=False)[1]["anchors"][0]["records_after_last_anchor"] == 0


@pytest.mark.parametrize("keep,name", [(lambda c: True, "both anchors arrived"),
                                       (lambda c: c <= 4, "the last anchor has not arrived"),
                                       (lambda c: False, "no anchor arrived")])
def test_a_rewrite_of_an_anchored_record_never_verifies_whatever_anchors_are_missing(run2, keep, name):
    """The operator, with the key, rewrites record 3 and repairs everything they can reach.
    The verifier is given the witness and nothing else. However many of the later anchors
    are missing, the result is never a pass:
      - any anchor that did arrive covers record 3 and no longer matches;
      - with no anchor at all there is nothing to check the journal against, and the
        verifier says that as a finding. A missing anchor is never taken as agreement."""
    w, _ = run2
    forge(w, rewrite_record_3)
    _, kept = witness_keeps(w, keep)
    code, report = w.verify(gate=False)
    assert code == 2, name
    assert findings(report) == (["ANCHOR_MISMATCH"] if kept else ["NO_ANCHOR_FOR_JOURNAL"])


def test_an_untouched_journal_whose_last_anchor_is_late_still_verifies_and_says_how_far_behind(run2):
    """Lag on its own is not a finding. It is reported as a number."""
    w, _ = run2
    witness_keeps(w, lambda count: count <= 4)
    code, report = w.verify(gate=False)
    assert code == 0 and report["anchors"][0]["records_after_last_anchor"] == 3


def test_an_untouched_journal_with_no_anchor_at_all_does_not_verify_against_the_witness(run2):
    w, _ = run2
    witness_keeps(w, lambda count: False)
    code, report = w.verify(gate=False)
    assert (code, findings(report)) == (2, ["NO_ANCHOR_FOR_JOURNAL"])


def test_records_after_the_last_anchor_that_arrived_are_not_protected_by_anchors(run2):
    """The limit, shown and not hidden, and the reason an anchor's lag is reported.

    The operator rewrites a record that only the last anchor covered, and that anchor
    never reached the witness. With the witness as the only outside evidence, this
    verifies: exit 0. No anchor was wrong, because none covered that record. The report
    says three records come after the last anchor, and those three are exactly the ones
    nothing outside the journal vouches for.

    This was true before anchors were written off the lock. A late anchor makes the
    unprotected stretch longer, by however many records were written while it waited."""
    w, _ = run2
    forge(w, rewrite_the_last_command)
    witness_keeps(w, lambda count: count <= 4)
    code, report = w.verify(gate=False)
    assert code == 0
    assert report["anchors"][0] == {"source": "the witness", "anchors_checked": 1, "records_after_last_anchor": 3}


def test_the_same_rewrite_is_caught_by_the_gates_head_and_by_the_anchor_once_it_arrives(run2):
    w, _ = run2
    with open(w.witness_store, encoding="utf-8") as fh:
        whole_store = fh.read()
    forge(w, rewrite_the_last_command)
    witness_keeps(w, lambda count: count <= 4)
    # The gate on the actuator's side holds the hash of the last record it accepted.
    code, report = w.verify()
    assert (code, findings(report)) == (2, ["GATE_HEAD_NOT_IN_JOURNAL"])
    # And when the late anchor does reach the witness, it no longer matches.
    with open(w.witness_store, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(whole_store)
    code, report = w.verify(gate=False)
    assert (code, findings(report)) == (2, ["ANCHOR_MISMATCH"])


def test_an_anchor_statement_still_being_written_is_never_read_as_a_statement(run2):
    """Statements are written under a temporary name and renamed when complete. The
    verifier reads only files named like a finished statement."""
    w, published = run2
    anchors = os.path.join(w.data, "anchors")
    with open(os.path.join(anchors, "00000099.json.tmp"), "w", encoding="utf-8") as fh:
        fh.write('{"schema":"sentinel-ledger/anchor/0","journal_id":"')
    code, report = w.verify("--anchors", anchors, root=published, **ALONE)
    assert code == 0 and report["anchors"][0]["anchors_checked"] == 2


# --- an anchor statement the recorder could not write -------------------------------------

def an_anchor_failure_after_record_3(fields):
    def change(records):
        record = dict({"schema": records[3]["schema"], "kind": "anchor_failed", "at": records[4]["at"]}, **fields)
        records.insert(4, record)
        return records
    return change


def test_an_anchor_the_recorder_says_it_could_not_write_is_a_finding(run2):
    w, _ = run2
    stated = {"entry_count": 4, "detail": "cannot write anchors/00000004.json: Permission denied"}
    code, report = verify_alone(w, an_anchor_failure_after_record_3(stated))
    assert (code, findings(report)) == (2, ["ANCHOR_FAILED"])
    found = report["findings"][0]
    assert (found["n"], found["entry_count"]) == (4, 4) and "Permission denied" in found["detail"]
    assert report["counts"]["anchors_failed"] == 1


def test_an_anchor_failure_record_without_its_fields_is_malformed(run2):
    w, _ = run2
    code, report = verify_alone(w, an_anchor_failure_after_record_3({"detail": "x"}))
    assert (code, findings(report)) == (2, ["RECORD_MALFORMED"])


def test_every_command_record_says_when_the_command_was_received(run2):
    """The gate measures a command's age from this. In the file demo the recorder's clock
    is fixed, so the value is that clock's."""
    w, _ = run2
    with open(w.journal, encoding="utf-8") as fh:
        records = [json.loads(json.loads(line)["raw"]) for line in fh]
    commands = [r for r in records if r["kind"] == "command"]
    assert commands and all(type(r["received_ms"]) is int for r in commands)
    at = datetime.datetime.strptime(commands[0]["at"], FORMAT).replace(tzinfo=datetime.timezone.utc)
    assert commands[0]["received_ms"] == int(at.timestamp()) * 1000


def test_a_received_time_that_is_not_a_whole_number_is_malformed(run2):
    w, _ = run2

    def change(records):
        records[3]["received_ms"] = "yesterday"
    code, report = verify_alone(w, change)
    assert (code, findings(report)) == (2, ["RECORD_MALFORMED"])
