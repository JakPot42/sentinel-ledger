"""Exporting a journal to RFC 5424 syslog and CEF, and checking the exported file offline.
docs/EXPORT.md.

The journals are the real recorder's (scenario 4, the recorder with the real gate from
tests/test_receipts.py, and the same with the feedback reporter from tests/test_feedback.py),
except where a test needs text no recorder would write, which is signed here with the
demo's pure-Python Ed25519. A ROS scenario 13 journal is exported in tests/test_ros2.py.
"""
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

import check_export
import export_journal
import pure_ed25519 as ed
import run_scenarios
import verify_journal as vj
from test_feedback import BLOCKED, FEEDBACK_PUBLIC, FEEDBACK_SEED, FedMachine
from test_receipts import GATE_PUBLIC, GATE_SEED, Machine
from test_tamper import forge

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPORTER = os.path.join(REPO, "export", "export_journal.py")
CHECKER = os.path.join(REPO, "export", "check_export.py")
FORMATS = ("syslog", "cef")
SEED = bytes(range(32))
PUBLIC = ed.public_key(SEED).hex()
OTHER_SEED = bytes(range(1, 33))


# --- helpers ---------------------------------------------------------------------------

def export(journal, fmt, out, *extra):
    done = subprocess.run([sys.executable, EXPORTER, journal, "--format", fmt, "--out", out, *extra],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done


def check(path, *extra):
    """Run the checker. Returns (exit code, its JSON report or {})."""
    done = subprocess.run([sys.executable, CHECKER, path, "--json", *extra], capture_output=True, text=True)
    try:
        return done.returncode, json.loads(done.stdout)
    except ValueError:
        return done.returncode, {}


def found(report):
    return sorted({f["finding"] for f in report["findings"]})


def lines_of(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read().splitlines(True)


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(lines))


def journal_raws(journal):
    with open(journal, encoding="utf-8") as fh:
        return [json.loads(line)["raw"] for line in fh if line.strip()]


def exported_raws(path, fmt):
    parse = check_export.FORMATS[fmt][0]
    out = []
    for line in lines_of(path):
        parsed = parse(line.rstrip("\r\n"))
        if parsed["type"] == "record":
            out.append(parsed["raw"])
    return out


def state_root(w):
    with open(os.path.join(w.data, "logchain.state"), encoding="utf-8") as fh:
        return json.load(fh)["merkle_root"]


def synthetic_journal(path, seed, bodies):
    """A journal of the given record bodies, numbered, chained and signed with `seed`."""
    public = ed.public_key(seed).hex()
    prev, out = "", []
    for n, body in enumerate(bodies):
        rec = dict(body, schema=vj.SCHEMA, n=n, prev=prev)
        if rec["kind"] == "genesis":
            rec["settings"] = dict(rec.get("settings", {}), recorder_public_key=public)
        raw = vj.canonical(ed.sign_record(seed, rec))
        prev = vj.leaf_hash(raw.encode("utf-8")).hex()
        out.append(json.dumps({"seq": n, "ingested_at": rec["at"], "raw": raw, "hash": prev}) + "\n")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(out))
    return path


AWKWARD = 'ticket=42 | path\\to ] "quoted" \n second line é pipe|equals= back\\slash'


def awkward_bodies():
    return [
        {"kind": "genesis", "at": "2026-10-01T08:00:00Z", "machine": "test bench", "state": {},
         "settings": {"heartbeat_seconds": 60}},
        {"kind": "recorder_start", "at": "2026-10-01T08:00:00Z"},
        {"kind": "intervention_declared", "at": "2026-10-01T08:00:05Z", "target": "ruleset", "old": "a" * 64,
         "new": "b" * 64, "operator": "op = | ]", "reference": AWKWARD, "authorisation": None},
        {"kind": "heartbeat", "at": "2026-10-01T08:01:00Z"},
        {"kind": "recorder_stop", "at": "2026-10-01T08:01:30Z"},
    ]


# --- journals from the real recorder ----------------------------------------------------

@pytest.fixture(scope="module")
def scenario4(recorder, tmp_path_factory):
    """Scenario 4's journal: commands, both kinds of intervention, decision data, restarts."""
    out = str(tmp_path_factory.mktemp("export_s4"))
    run_scenarios.run_scenario(4, recorder, out)
    w = run_scenarios.Workspace(out, "scenario_4", recorder, fresh=False)
    return w, state_root(w)


@pytest.fixture(scope="module")
def with_receipts(recorder, tmp_path_factory):
    """The recorder and the real gate: an applied, a changed, a blocked command, a refusal
    for age, a deadman trip, and a refusal of a message another party sent."""
    m = Machine(tmp_path_factory.mktemp("export_receipts"), recorder, age_limit=1000, deadman=4)
    try:
        m.command(400)
        m.command(1800)
        m.command(500, {"light_curtain_clear": 0})
        m.command(600, late_ms=6000)
        assert m.silence(5.0)["why"] == "deadman"
        m.rogue({"type": "record", "n": 99, "action": {"speed_mm_s": 1500}})
        m.command(300)
        m.stop()
    finally:
        if m.proc.poll() is None:
            m.proc.kill()
    return m


def stop_machine(m):
    if m.proc.poll() is None:
        m.proc.kill()
        m.proc.wait()


@pytest.fixture(scope="module")
def with_feedback(recorder, tmp_path_factory):
    """The recorder, the real gate and the feedback reporter: an applied, a changed, a
    blocked command, one refused for its age, and one more applied. Each has a report."""
    m = FedMachine(tmp_path_factory.mktemp("export_feedback"), recorder, age_limit=1000, clock=False)
    try:
        m.command(400)
        m.command(1800)
        m.command(500, BLOCKED)
        m.command(600, late_ms=6000)
        m.command(300)
        m.stop()
    finally:
        stop_machine(m)
    return m


def bump_measured(line):
    """The line with the first measured value inside a feedback report raised by 100."""
    return re.sub(r'"measured":\{"(\w+)":(-?\d+)', lambda g: '"measured":{"%s":%d' % (g.group(1), int(g.group(2)) + 100),
                  line, count=1)


@pytest.fixture()
def exported(scenario4, tmp_path):
    """export(fmt): scenario 4 exported to a fresh file. Returns its path."""
    w, _ = scenario4

    def make(fmt):
        path = str(tmp_path / ("s4." + fmt))
        export(w.journal, fmt, path)
        return path
    return make


# --- what an untouched export shows -----------------------------------------------------

@pytest.mark.parametrize("fmt", FORMATS)
def test_an_export_checks_clean_and_carries_every_record_byte_for_byte(scenario4, exported, fmt):
    w, root = scenario4
    path = exported(fmt)
    code, report = check(path, "--root", root, "--public-key", w.public_key)
    assert (code, report["findings"]) == (0, [])
    assert report["root_recomputed"] == root                      # the recorder's own root
    raws = journal_raws(w.journal)
    assert exported_raws(path, fmt) == raws
    assert report["counts"]["records"] == report["counts"]["signatures_checked"] == len(raws)
    assert len(lines_of(path)) == len(raws) + 1                   # and the end line
    kinds = {json.loads(r)["kind"] for r in raws}
    assert {"genesis", "command", "intervention_declared", "intervention_detected", "recorder_stop"} <= kinds


@pytest.mark.parametrize("fmt", FORMATS)
def test_gate_receipts_are_checked_against_the_gates_key(with_receipts, tmp_path, fmt):
    m = with_receipts
    path = str(tmp_path / ("r." + fmt))
    export(m.w.journal, fmt, path)
    code, report = check(path, "--root", m.root, "--public-key", m.w.public_key, "--gate-public-key", GATE_PUBLIC)
    assert (code, report["findings"]) == (0, [])
    held = [json.loads(r) for r in journal_raws(m.w.journal)]
    receipts = [r["receipt"] for r in held if r["kind"] == "gate_receipt"]
    assert report["counts"]["receipts_checked"] == len(receipts)
    assert {r["decision"] for r in receipts} == {"applied", "blocked", "refused", "deadman"}
    assert {r["outcome"] for r in held if r["kind"] == "command"} == {"unchanged", "changed", "blocked"}


@pytest.mark.parametrize("fmt", FORMATS)
def test_actuator_feedback_exports_and_is_checked_against_the_feedback_key(with_feedback, tmp_path, fmt):
    """Before the export tools knew the record kind, every report here was RECORD_MALFORMED
    and its signature went unchecked."""
    m = with_feedback
    path = str(tmp_path / ("f." + fmt))
    export(m.w.journal, fmt, path)
    held = [json.loads(r) for r in journal_raws(m.w.journal)]
    reports = [r for r in held if r["kind"] == "actuator_feedback"]
    assert len(reports) == 5 and reports[0]["feedback"]["sig"]
    code, report = check(path, "--root", m.root, "--public-key", m.w.public_key, "--gate-public-key", GATE_PUBLIC,
                         "--feedback-public-key", FEEDBACK_PUBLIC)
    assert (code, report["findings"]) == (0, [])
    assert report["counts"]["feedback_checked"] == len(reports)
    assert report["counts"]["records"] == report["counts"]["signatures_checked"] == len(held)
    assert exported_raws(path, fmt) == journal_raws(m.w.journal)
    code, report = check(path)                                     # the keys the genesis record names
    assert (code, report["findings"], report["counts"]["feedback_checked"]) == (0, [], 5)
    first = next(i for i, r in enumerate(held) if r["kind"] == "actuator_feedback")
    if fmt == "syslog":
        assert lines_of(path)[first].startswith("<110>1 ")          # facility 13, severity 6
    else:
        assert lines_of(path)[first].startswith("CEF:0|Sentinel Ledger|journal export|1|actuator_feedback|"
                                                "actuator feedback|2|externalId=%d " % first)


@pytest.mark.parametrize("fmt", FORMATS)
def test_an_altered_feedback_report_is_found(with_feedback, tmp_path, fmt):
    """Someone changes what a report says the actuator did, in the exported file."""
    m = with_feedback
    path = str(tmp_path / ("f." + fmt))
    export(m.w.journal, fmt, path)
    lines = lines_of(path)
    k = [i for i, r in enumerate(journal_raws(m.w.journal)) if json.loads(r)["kind"] == "actuator_feedback"][2]
    altered = bump_measured(lines[k])
    assert altered != lines[k]
    lines[k] = altered
    write_lines(path, lines)
    code, report = check(path, "--root", m.root, "--feedback-public-key", FEEDBACK_PUBLIC)
    assert code == 2
    assert {"FEEDBACK_SIGNATURE_INVALID", "SIGNATURE_INVALID", "ENVELOPE_MISMATCH", "PREV_MISMATCH",
            "END_MISMATCH", "ROOT_MISMATCH"} <= set(found(report))
    assert [(f["n"], f["reason"]) for f in report["findings"] if f["finding"] == "FEEDBACK_SIGNATURE_INVALID"] == \
        [(k, "the feedback is not signed with the feedback key")]


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_report_the_keeper_rewrote_and_signed_again_is_found_by_the_feedback_key(recorder, tmp_path, fmt):
    """The operator changes the last report before export, signs the record again with the
    recorder's key and repairs every hash. The chain, the record's signature and the end
    line all agree with the edit; the report inside is no longer one the feedback key signed."""
    m = FedMachine(tmp_path, recorder)
    try:
        m.command(400)
        m.command(500)
        m.stop()
    finally:
        stop_machine(m)

    def rewrite(records):
        last = [r for r in records if r["kind"] == "actuator_feedback"][-1]
        last["feedback"]["measured"] = {"speed_mm_s": 0}
    root = forge(m.w, rewrite)
    path = str(tmp_path / ("f." + fmt))
    export(m.w.journal, fmt, path)
    code, report = check(path, "--root", root, "--public-key", m.w.public_key, "--feedback-public-key", FEEDBACK_PUBLIC)
    assert (code, found(report)) == (2, ["FEEDBACK_SIGNATURE_INVALID"])
    assert report["findings"][0]["reason"] == "the feedback is not signed with the feedback key"


def test_the_feedback_key_given_must_be_the_one_the_journal_names(with_feedback, tmp_path):
    m = with_feedback
    path = str(tmp_path / "f.syslog")
    export(m.w.journal, "syslog", path)
    code, report = check(path, "--feedback-public-key", ed.public_key(OTHER_SEED).hex())
    assert code == 2 and found(report) == ["FEEDBACK_SIGNATURE_INVALID", "KEY_MISMATCH"]
    assert sum(f["finding"] == "FEEDBACK_SIGNATURE_INVALID" for f in report["findings"]) == 5
    code, report = check(path, "--feedback-public-key", "ab")
    assert code == 1


def test_a_report_in_a_journal_that_names_no_feedback_key_is_found(tmp_path):
    report = ed.sign_record(FEEDBACK_SEED, {"schema": vj.FEEDBACK_SCHEMA, "seq": 0, "n": 2, "hash": "c" * 64,
                                            "sent": {"speed_mm_s": 400}, "measured": {"speed_mm_s": 400},
                                            "state": None, "after_ms": 100, "at_ms": None})
    bodies = awkward_bodies()[:2] + [
        {"kind": "command", "at": "2026-10-01T08:00:01Z", "outcome": "unchanged"},
        {"kind": "actuator_feedback", "at": "2026-10-01T08:00:02Z", "feedback": report},
    ]
    journal = synthetic_journal(str(tmp_path / "j"), SEED, bodies)
    path = str(tmp_path / "f.cef")
    export(journal, "cef", path)
    code, found_report = check(path, "--public-key", PUBLIC)
    assert (code, found(found_report)) == (2, ["FEEDBACK_SIGNATURE_INVALID"])
    assert found_report["findings"][0]["reason"] == "no feedback key is named or given"


def test_the_exporter_and_the_checker_know_every_kind_the_verifier_knows():
    """A record kind the export tools do not know makes every record of it malformed in the
    checker. This is how actuator_feedback was missed."""
    assert set(check_export.KINDS) == set(vj.KINDS)
    for kind in vj.KINDS:
        record = {"kind": kind, "outcome": "unchanged", "receipt": {"decision": "applied"}}
        assert export_journal.classify(record) == check_export.classify(record) != (4, 7, "unknown record"), kind


@pytest.mark.parametrize("fmt", FORMATS)
def test_the_same_journal_gives_the_same_bytes(scenario4, tmp_path, fmt):
    w, _ = scenario4
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    export(w.journal, fmt, a)
    export(w.journal, fmt, b)
    with open(a, "rb") as fa, open(b, "rb") as fb:
        assert fa.read() == fb.read()


def test_the_severity_and_names_on_the_lines(with_receipts, tmp_path):
    m = with_receipts
    syslog, cef = str(tmp_path / "r.syslog"), str(tmp_path / "r.cef")
    export(m.w.journal, "syslog", syslog, "--facility", "4", "--hostname", "robot-7")
    export(m.w.journal, "cef", cef)
    refused = next(i for i, r in enumerate(journal_raws(m.w.journal))
                   if '"decision":"refused"' in r and '"reason":"age"' in r)
    assert lines_of(syslog)[refused].startswith("<36>1 ")           # facility 4, severity 4
    assert " robot-7 sentinel-ledger - gate_receipt [sl@32473 n=\"%d\" kind=\"gate_receipt\"" % refused \
        in lines_of(syslog)[refused]
    assert lines_of(cef)[refused].startswith("CEF:0|Sentinel Ledger|journal export|1|gate_receipt|"
                                             "gate receipt: refused|7|externalId=%d " % refused)
    assert lines_of(syslog)[-1].startswith("<37>1 ")                # the end line: severity 5
    assert check(syslog, "--gate-public-key", GATE_PUBLIC)[0] == 0
    assert check(cef, "--gate-public-key", GATE_PUBLIC)[0] == 0


# --- altered, dropped, reordered ---------------------------------------------------------

@pytest.mark.parametrize("fmt", FORMATS)
def test_an_altered_record_is_found(scenario4, exported, fmt):
    w, root = scenario4
    path = exported(fmt)
    lines = lines_of(path)
    k = next(i for i, r in enumerate(journal_raws(w.journal)) if json.loads(r)["kind"] == "command")
    altered = re.sub(r'"speed_mm_s":(\d+)', lambda m: '"speed_mm_s":%d' % (int(m.group(1)) + 100), lines[k], count=1)
    assert altered != lines[k]
    lines[k] = altered
    write_lines(path, lines)
    code, report = check(path, "--root", root)
    assert code == 2
    assert {"SIGNATURE_INVALID", "ENVELOPE_MISMATCH", "PREV_MISMATCH", "END_MISMATCH", "ROOT_MISMATCH"} <= set(found(report))
    assert any(f["finding"] == "SIGNATURE_INVALID" and f["n"] == k for f in report["findings"])
    assert any(f["finding"] == "PREV_MISMATCH" and f["position"] == k + 1 for f in report["findings"])


@pytest.mark.parametrize("fmt", FORMATS)
def test_an_altered_last_record_with_every_hash_repaired_is_still_found_by_its_signature(scenario4, tmp_path, fmt):
    """The edit is made in the journal before export, so the line, the chain and the end
    line all agree with the edited text. Only the signature, made over the original, does not."""
    w, root = scenario4
    journal = str(tmp_path / "edited.journal")
    entries = [json.loads(line) for line in open(w.journal, encoding="utf-8") if line.strip()]
    last = json.loads(entries[-1]["raw"])
    last["at"] = last["at"].replace("T08:", "T09:")
    entries[-1]["raw"] = vj.canonical(last)
    with open(journal, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(json.dumps(e) + "\n" for e in entries))
    path = str(tmp_path / ("e." + fmt))
    done = export(journal, fmt, path)
    assert "the stored hash is not the leaf hash" in done.stderr     # the exporter says so, and exports
    code, report = check(path)
    assert (code, found(report)) == (2, ["SIGNATURE_INVALID"])
    assert check(path, "--root", root)[1]["findings"][-1]["finding"] == "ROOT_MISMATCH"


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize("which", ["first", "middle", "last"])
def test_a_dropped_record_is_found(scenario4, exported, fmt, which):
    path = exported(fmt)
    lines = lines_of(path)
    index = {"first": 0, "middle": len(lines) // 2, "last": len(lines) - 2}[which]
    del lines[index]
    write_lines(path, lines)
    code, report = check(path)
    assert code == 2
    names = found(report)
    assert "END_MISMATCH" in names
    if which == "first":
        assert {"NO_GENESIS", "POSITION_MISMATCH", "PREV_MISMATCH", "KEY_UNKNOWN"} <= set(names)
    if which == "middle":
        assert {"POSITION_MISMATCH", "PREV_MISMATCH"} <= set(names)
    if which == "last":
        assert names == ["END_MISMATCH"]
        fields = {f["field"] for f in report["findings"]}
        assert {"records", "root"} <= fields


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_dropped_end_line_is_found(exported, fmt):
    path = exported(fmt)
    write_lines(path, lines_of(path)[:-1])
    code, report = check(path)
    assert (code, found(report)) == (2, ["END_MISSING"])


@pytest.mark.parametrize("fmt", FORMATS)
def test_reordered_records_are_found(exported, fmt):
    path = exported(fmt)
    lines = lines_of(path)
    lines[3], lines[4] = lines[4], lines[3]
    write_lines(path, lines)
    code, report = check(path)
    assert code == 2
    assert {"POSITION_MISMATCH", "PREV_MISMATCH", "END_MISMATCH"} <= set(found(report))
    assert sorted(f["position"] for f in report["findings"] if f["finding"] == "POSITION_MISMATCH") == [3, 4]


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_record_moved_after_the_end_line_is_found(exported, fmt):
    path = exported(fmt)
    lines = lines_of(path)
    moved = lines.pop(5)
    lines.append(moved)
    write_lines(path, lines)
    code, report = check(path)
    assert code == 2 and "END_NOT_LAST" in found(report)


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_repeated_record_is_found(exported, fmt):
    path = exported(fmt)
    lines = lines_of(path)
    lines.insert(4, lines[3])
    write_lines(path, lines)
    code, report = check(path)
    assert code == 2 and {"POSITION_MISMATCH", "PREV_MISMATCH", "END_MISMATCH"} <= set(found(report))


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_changed_severity_or_event_name_is_found_though_the_record_is_untouched(exported, fmt):
    path = exported(fmt)
    lines = lines_of(path)
    if fmt == "syslog":
        pri = int(lines[2][1:lines[2].index(">")])
        lines[2] = "<%d>" % ((pri // 8) * 8 + 7) + lines[2][lines[2].index(">") + 1:]
    else:
        parts = lines[2].split("|", 7)
        parts[5], parts[6] = "heartbeat", "1"
        lines[2] = "|".join(parts)
    write_lines(path, lines)
    code, report = check(path)
    assert (code, found(report)) == (2, ["ENVELOPE_MISMATCH"])
    fields = {f["field"] for f in report["findings"]}
    assert fields == ({"severity"} if fmt == "syslog" else {"name", "severity"})


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_line_a_relay_cut_short_is_found(exported, fmt):
    path = exported(fmt)
    lines = lines_of(path)
    lines[3] = lines[3][:300] + "\n"
    write_lines(path, lines)
    code, report = check(path)
    assert code == 2 and set(found(report)) & {"LINE_MALFORMED", "RECORD_MALFORMED"}


# --- what needs a root from outside the file -------------------------------------------

@pytest.mark.parametrize("fmt", FORMATS)
def test_dropping_the_last_record_and_rewriting_the_end_line_needs_an_outside_root(scenario4, tmp_path, fmt):
    """The end line is in the same file. A shorter journal exported afresh is consistent
    with itself; only a root held elsewhere shows what is missing."""
    w, root = scenario4
    short = str(tmp_path / "short.journal")
    with open(w.journal, encoding="utf-8") as fh:
        kept = [line for line in fh if line.strip()][:-1]
    with open(short, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(kept))
    path = str(tmp_path / ("short." + fmt))
    export(short, fmt, path)
    code, report = check(path)
    assert (code, report["findings"]) == (0, [])
    text = subprocess.run([sys.executable, CHECKER, path], capture_output=True, text=True).stdout
    assert "not that nothing was removed from its end" in text
    code, report = check(path, "--root", root)
    assert (code, found(report)) == (2, ["ROOT_MISMATCH"])


@pytest.mark.parametrize("fmt", FORMATS)
def test_an_operator_who_re_signs_a_rewritten_journal_is_found_only_with_an_outside_root(recorder, tmp_path, fmt):
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = run_scenarios.Workspace(str(tmp_path), "scenario_2", recorder, fresh=False)
    published = state_root(w)

    def slower(records):
        for rec in records:
            if rec["kind"] == "command" and rec["applied"]:
                rec["applied"]["speed_mm_s"] = 100
                rec["reported"]["applied"] = rec["applied"]
                return
    forged_root = forge(w, slower)
    path = str(tmp_path / ("forged." + fmt))
    export(w.journal, fmt, path)
    assert check(path, "--public-key", w.public_key)[0] == 0
    code, report = check(path, "--root", published)
    assert (code, found(report)) == (2, ["ROOT_MISMATCH"])
    assert report["root_recomputed"] == forged_root


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_whole_file_signed_with_another_key_needs_the_machines_key(tmp_path, fmt):
    journal = synthetic_journal(str(tmp_path / "j"), OTHER_SEED, awkward_bodies())
    path = str(tmp_path / ("other." + fmt))
    export(journal, fmt, path)
    assert check(path)[0] == 0                       # consistent with the key it names itself
    code, report = check(path, "--public-key", PUBLIC)
    assert code == 2 and {"KEY_MISMATCH", "SIGNATURE_INVALID"} <= set(found(report))


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_receipt_the_gate_did_not_sign_is_found(recorder, tmp_path, fmt):
    m = Machine(tmp_path, recorder)
    try:
        m.command(400)
        m.command(300)
        m.stop()
    finally:
        if m.proc.poll() is None:
            m.proc.kill()

    def swap_receipt_signature(records):
        for rec in records:
            if rec["kind"] == "gate_receipt":
                rec["receipt"] = ed.sign_record(OTHER_SEED, rec["receipt"])
                return
    forge(m.w, swap_receipt_signature)
    path = str(tmp_path / ("r." + fmt))
    export(m.w.journal, fmt, path)
    code, report = check(path, "--public-key", m.w.public_key, "--gate-public-key", GATE_PUBLIC)
    assert (code, found(report)) == (2, ["RECEIPT_SIGNATURE_INVALID"])
    assert report["findings"][0]["reason"] == "the receipt is not signed with the gate's key"


# --- text no recorder writes, and what relays do to lines ------------------------------

@pytest.mark.parametrize("fmt", FORMATS)
def test_awkward_text_round_trips(tmp_path, fmt):
    journal = synthetic_journal(str(tmp_path / "j"), SEED, awkward_bodies())
    path = str(tmp_path / ("a." + fmt))
    export(journal, fmt, path, "--enterprise-number", "99999")
    code, report = check(path, "--public-key", PUBLIC)
    assert (code, report["findings"]) == (0, [])
    assert exported_raws(path, fmt) == journal_raws(journal)
    assert json.loads(exported_raws(path, fmt)[2])["reference"] == AWKWARD


def test_a_byte_order_mark_stripped_by_a_relay_still_checks(exported):
    path = exported("syslog")
    lines = lines_of(path)
    assert all("﻿" in line for line in lines)
    write_lines(path, [line.replace("﻿", "") for line in lines])
    assert check(path)[0] == 0


def test_a_syslog_header_put_in_front_of_cef_is_ignored(exported):
    path = exported("cef")
    write_lines(path, ["<134>Oct 16 23:00:00 relay-1 " + line for line in lines_of(path)])
    assert check(path)[0] == 0


@pytest.mark.parametrize("fmt", FORMATS)
def test_crlf_line_endings_still_check(exported, fmt):
    path = exported(fmt)
    write_lines(path, [line.replace("\n", "\r\n") for line in lines_of(path)])
    assert check(path)[0] == 0


@pytest.mark.parametrize("fmt", FORMATS)
def test_an_empty_or_unreadable_file_is_exit_1(tmp_path, fmt):
    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    assert check(str(empty))[0] == 1
    assert check(str(tmp_path / "absent"))[0] == 1
    garbage = tmp_path / "garbage"
    garbage.write_text("hello\n", encoding="utf-8")
    assert check(str(garbage))[0] == 1
    assert check(str(garbage), "--format", fmt)[0] == 2           # told the format: every line is malformed


def test_the_exporter_refuses_a_journal_it_cannot_read(tmp_path):
    bad = tmp_path / "bad.journal"
    bad.write_text('{"seq": 0, "raw": "not a record"}\n', encoding="utf-8")
    done = subprocess.run([sys.executable, EXPORTER, str(bad), "--format", "syslog"], capture_output=True, text=True)
    assert done.returncode == 1 and "run the verifier" in done.stderr
    done = subprocess.run([sys.executable, EXPORTER, str(bad), "--format", "syslog", "--hostname", "a b"],
                          capture_output=True, text=True)
    assert done.returncode == 1


# --- the two programs agree with each other, with the document, and with RFC 8032 ------

def test_the_exporter_and_the_checker_agree_with_the_document_on_severity_and_name():
    with open(os.path.join(REPO, "docs", "EXPORT.md"), encoding="utf-8") as fh:
        doc = fh.read()
    section = doc[doc.index("## 5. Severity and name"):doc.index("## 6.")]
    rows = re.findall(r"^\| (.+?) \| (\d) \| (\d+) \| (.+?) \|$", section, flags=re.M)
    assert len(rows) == 21

    def record_for(text):
        kinds = re.findall(r"`([a-z_]+)`", text)
        if text == "any other kind":
            return {"kind": "something_else"}
        if text == "end of export":
            return None
        if kinds[0] == "command":
            return {"kind": "command", "outcome": kinds[1] if len(kinds) > 1 else "sideways"}
        if kinds[0] == "gate_receipt":
            return {"kind": "gate_receipt", "receipt": {"decision": kinds[1]} if len(kinds) > 1 else None}
        return {"kind": kinds[0]}

    for text, syslog, cef, name in rows:
        record = record_for(text)
        want = (int(syslog), int(cef), name)
        if record is None:
            assert export_journal.END == check_export.END == want
        else:
            assert export_journal.classify(record) == check_export.classify(record) == want, text


def test_the_checker_agrees_with_rfc_8032_and_with_the_verifier():
    vectors = [
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", b"",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
         "d25bf5f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", b"\x72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
         "387b2eaeb4302aeeb00d291612bb0c00"),
    ]
    for public, message, signature in vectors:
        public, signature = bytes.fromhex(public), bytes.fromhex(signature)
        assert check_export.ed25519_verify(public, message, signature)
        assert not check_export.ed25519_verify(public, message + b"x", signature)
        assert not check_export.ed25519_verify(public, message, signature[:63] + bytes([signature[63] ^ 1]))
    message = b"a record" * 30
    signature = ed.sign(SEED, message)
    for public in (PUBLIC, ed.public_key(OTHER_SEED).hex()):
        assert check_export.ed25519_verify(bytes.fromhex(public), message, signature) == \
            vj.ed25519_verify(bytes.fromhex(public), message, signature)
    assert check_export.merkle_root([bytes([i]) * 32 for i in range(7)]) == vj.merkle_root([bytes([i]) * 32 for i in range(7)])


def test_neither_program_shares_code_with_the_rest_or_reads_the_clock():
    allowed = {"argparse", "calendar", "datetime", "hashlib", "json", "re", "sys"}
    for path in (EXPORTER, CHECKER):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        imports = set(re.findall(r"^(?:import|from)\s+([\w.]+)", source, flags=re.M))
        assert imports <= allowed, (path, imports - allowed)
        assert ".now(" not in source and ".today(" not in source and "import time" not in source
