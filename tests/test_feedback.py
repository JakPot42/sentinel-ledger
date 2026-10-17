"""What the actuator did after each command: the robot's signed feedback, what the recorder
writes down, and what the verifier then reports. docs/SPEC.md section 4.6.

The first part is the feedback reporter on its own, with the gate it sits beside. The
rest runs the real recorder program, the real gate class with its own key and the real
reporter with a key of its own, with the test standing where the wires between them would
be, as tests/test_receipts.py does. The test also plays the conveyor: it says what the
belt does with each action it is given. The ROS scenarios show the same over topics.

What the tests below hold the verifier to: a report that is missing, altered, or filed
under a command it does not belong to is a finding, whether the robot lost it, the
journal's keeper changed it with the recorder's key, or someone holding the feedback key
signed it to fit.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

import pure_ed25519 as ed
import run_scenarios
import verify_journal as vj
from actuator_feedback import FEEDBACK_SCHEMA, FeedbackReporter
from actuator_gate import Gate
from test_gate import PUBLIC, SEED, Line
from test_receipts import GATE_PUBLIC, GATE_SEED, SAFE, Machine, found
from test_tamper import forge

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDBACK_SEED = bytes(range(200, 232))            # the feedback key: neither the recorder's nor the gate's
FEEDBACK_PUBLIC = ed.public_key(FEEDBACK_SEED).hex()
BLOCKED = {"light_curtain_clear": 0}


def signed_with(statement, public):
    body = {k: v for k, v in statement.items() if k != "sig"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return vj.ed25519_verify(bytes.fromhex(public), text, bytes.fromhex(statement["sig"]))


# --- the reporter on its own ---------------------------------------------------------------

def gate_reporter_line(tmp_path, age_limit=None, deadman=None):
    line = Line(str(tmp_path))
    gate = Gate(os.path.join(str(tmp_path), "gate.state"), SAFE, PUBLIC, deadman, age_limit, gate_key=GATE_SEED)
    return gate, FeedbackReporter(os.path.join(str(tmp_path), "feedback.state"), FEEDBACK_SEED), line


def test_a_report_follows_each_command_the_gate_took_in_and_names_it(tmp_path):
    gate, reporter, line = gate_reporter_line(tmp_path, age_limit=1000)
    assert reporter.follow(gate.handle(line.record("genesis")), now=0.0) is False
    message = line.command(500, received_ms=1000)
    decision = gate.handle(message, now=1.0, wall_ms=1000)
    assert reporter.follow(decision, now=1.0) is True and reporter.due()
    report = reporter.report({"speed_mm_s": 480}, now=1.05, wall_ms=1050)
    assert report == dict(report, schema=FEEDBACK_SCHEMA, seq=0, n=1, hash=message["hash"], sent={"speed_mm_s": 500},
                          measured={"speed_mm_s": 480}, state=None, after_ms=50, at_ms=1050)
    assert not reporter.due() and reporter.report({"speed_mm_s": 0}) is None
    # Signed with the feedback key: not the gate's, not the recorder's, and not to be changed.
    assert signed_with(report, FEEDBACK_PUBLIC)
    assert not signed_with(report, GATE_PUBLIC) and not signed_with(report, PUBLIC)
    assert not signed_with(dict(report, measured={"speed_mm_s": 500}), FEEDBACK_PUBLIC)
    assert not signed_with(dict(report, n=2), FEEDBACK_PUBLIC)

    # A blocked command and one too old to carry out: the actuator was given the safe state.
    blocked = gate.handle(line.record("command", applied=None, outcome="blocked", received_ms=2000), wall_ms=2000)
    assert reporter.follow(blocked) and reporter.report(SAFE)["sent"] == SAFE
    stale = gate.handle(line.command(700, received_ms=3000), wall_ms=9000)
    assert stale["why"] == "stale_command" and reporter.follow(stale)
    assert reporter.report(SAFE)["sent"] == SAFE

    # Nothing follows a record that is not a command, a refusal, or a safe-state message.
    assert reporter.follow(gate.handle(line.record("heartbeat"))) is False
    assert reporter.follow(gate.handle({"type": "record", "n": 99})) is False
    assert reporter.follow(gate.handle({"type": "safe_state", "why": "recorder_fault"})) is False
    assert not reporter.due()


def test_a_deadman_trip_is_followed_by_no_report(tmp_path):
    gate, reporter, line = gate_reporter_line(tmp_path, deadman=4)
    gate.handle(line.record("genesis"), now=0.0)
    reporter.follow(gate.handle(line.command(500), now=1.0), now=1.0)
    reporter.report({"speed_mm_s": 500}, now=1.1)
    tripped = gate.check_deadman(6.0)
    assert tripped["why"] == "deadman" and reporter.follow(tripped, now=6.0) is False


def test_the_gates_decisions_name_the_record_they_are_about(tmp_path):
    gate, _, line = gate_reporter_line(tmp_path)
    first = line.record("genesis")
    assert gate.handle(first)["hash"] == first["hash"]
    command = line.command(300)
    assert gate.handle(command)["hash"] == command["hash"]
    assert gate.handle(command)["hash"] is None                    # sent twice: refused, about no record
    assert gate.handle({"type": "safe_state"})["hash"] is None


def test_a_reading_can_wait_one_control_step(tmp_path):
    gate, reporter, line = gate_reporter_line(tmp_path)
    gate.handle(line.record("genesis"))
    reporter.follow(gate.handle(line.command(300)), now=10.0)
    assert not reporter.due(10.02, 0.05) and reporter.due(10.05, 0.05) and reporter.due()


def test_the_reporter_uses_only_the_standard_library_and_the_gates_signing_code():
    """It is on the robot's side with the gate. It shares nothing with the recorder or the
    verifier, and it signs in one place: a report."""
    with open(os.path.join(REPO, "gate", "actuator_feedback.py"), encoding="utf-8") as fh:
        source = fh.read()
    assert set(re.findall(r"^(?:import|from)\s+([\w.]+)", source, flags=re.M)) == {"json", "os", "actuator_gate"}
    assert "from actuator_gate import ed25519_sign, load_gate_key" in source
    assert source.count("ed25519_sign(") == 1


def test_the_robot_reads_before_the_next_action_and_signs_after_it():
    """Checked in the source, since it needs ROS to run: in the simulated robot, the
    reading still due is taken before the wheels are given a new action, so it describes
    the old one, and is signed and saved after, so a stop never waits for it."""
    with open(os.path.join(REPO, "ros2", "sim_robot.py"), encoding="utf-8") as fh:
        robot = fh.read()
    act = robot.split("    def act(self, decision):")[1].split("    def on_control")[0]
    assert act.index("reading = self.read_wheels()") < act.index("self.velocity = {") < \
        act.index("self.send_feedback(reading)")
    assert robot.count("self.velocity = {") == 1 and robot.count("self.reporter.report(") == 1


def test_report_numbers_carry_on_after_the_reporter_restarts(tmp_path):
    gate, reporter, line = gate_reporter_line(tmp_path)
    gate.handle(line.record("genesis"))
    for speed in (100, 200):
        reporter.follow(gate.handle(line.command(speed)))
        reporter.report({"speed_mm_s": speed})
    again = FeedbackReporter(reporter.state_path, FEEDBACK_SEED)
    again.follow(gate.handle(line.command(300)))
    assert again.report({"speed_mm_s": 300})["seq"] == 2


# --- the recorder, the gate, the reporter and the verifier together -----------------------

class FedMachine(Machine):
    """The machine of tests/test_receipts.py, with a feedback key in its configuration and
    a feedback reporter beside the gate. The test plays the conveyor: after each action the
    belt runs at whatever `belt` makes of it. A reading is taken after each command, and
    before the belt is given anything else.

    `receipts=False`: a gate that signs no receipts. `clock=False`: readings carry no wall
    clock. `reads_late=True`: a robot with a bug in its control loop, which takes each
    reading only after the next action and files it under the earlier command."""

    def __init__(self, tmp_path, recorder, receipts=True, clock=True, reads_late=False,
                 reporter_class=FeedbackReporter, **how):
        self.reporter = None
        self.belt = lambda sent: dict(sent)
        self.belt_now, self.wall, self.clock, self.reads_late = dict(SAFE), 0, clock, reads_late
        self.reports, self.drop_feedback = [], lambda report: False
        self.receipts_on = receipts
        super().__init__(tmp_path, recorder, gate_key=GATE_SEED if receipts else None,
                         more_config='\n  "feedback_public_key": "%s",' % FEEDBACK_PUBLIC, **how)
        self.reporter = reporter_class(os.path.join(self.w.dir, "actuator_side", "feedback.state"), FEEDBACK_SEED)

    def judge(self, message):
        try:
            received = json.loads(message.get("record", "")).get("received_ms")
        except (ValueError, AttributeError):
            received = None
        wall_ms = (received if type(received) is int else 0) + self.late_ms
        self.now += 0.1
        decision = self.gate.handle(message, now=self.now, wall_ms=wall_ms)
        if decision["send"] is not None:
            if not self.reads_late:
                self.read()                    # the reading still due, before the belt is given anything else
            self.belt_now, self.wall = self.belt(decision["send"]), wall_ms
            if self.reads_late:
                self.read()                    # the bug: read after the next action
        if self.reporter is not None:
            self.reporter.follow(decision, self.now)
        self.hand_over(self.gate.issue_receipt(decision, wall_ms=wall_ms))
        return decision

    def read(self):
        if self.reporter is None or not self.reporter.due():
            return None
        report = self.reporter.report(dict(self.belt_now), None, now=self.now + 0.05,
                                      wall_ms=self.wall + 1 if self.clock else None)
        self.reports.append(report)
        if not self.drop_feedback(report):
            self.replies.append(self.ask({"op": "actuator_feedback", "feedback": report}))
        return report

    def command(self, speed, inputs=run_scenarios.CLEAR, late_ms=0):
        reply = super().command(speed, inputs, late_ms)
        if not self.reads_late:
            self.read()                        # the robot's next control step
            self.deliver()
        return reply

    def keys(self):
        return ["--feedback-public-key", FEEDBACK_PUBLIC] + (["--gate-public-key", GATE_PUBLIC] if self.receipts_on else [])

    def verify(self, *extra, root=None):
        return self.w.verify(*self.keys(), *extra, root=root or self.root, witness=False)

    def check_forged(self, change, with_the_key=True):
        """The journal's keeper rewrites it with `change` and repairs every hash (see
        tests/test_tamper.py), then hands it to the verifier."""
        return self.w.verify(*self.keys(), root=forge(self.w, change, with_the_key), witness=False, gate=False)

    def feedback_held(self):
        return [r["feedback"] for r in self.records() if r["kind"] == "actuator_feedback"]


@pytest.fixture()
def fed(recorder, tmp_path):
    made = []

    def make(**how):
        made.append(FedMachine(tmp_path, recorder, **how))
        return made[-1]
    yield make
    for m in made:
        if m.proc.poll() is None:
            m.proc.kill()
            m.proc.wait()
            m.proc.stdout.close()


def four_commands(m):
    return [m.command(400), m.command(1800), m.command(500, BLOCKED), m.command(300)]


def test_every_command_has_its_feedback_in_the_journal_and_the_journal_is_clean(fed):
    m = fed()
    replies = four_commands(m)
    m.stop()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    counts = report["counts"]
    assert (counts["commands"], counts["actuator_feedback"], counts["commands_without_feedback"]) == (4, 4, 0)
    held = m.feedback_held()
    assert held == m.reports and all(signed_with(f, FEEDBACK_PUBLIC) for f in held)
    assert [f["n"] for f in held] == [r["n"] for r in replies] and [f["seq"] for f in held] == [0, 1, 2, 3]
    # What the actuator was given, and what the belt then did: the clamped speed, the safe
    # state for the blocked command.
    assert [f["sent"]["speed_mm_s"] for f in held] == [400, 1500, 0, 300]
    assert [f["measured"] for f in held] == [f["sent"] for f in held]
    records = m.records()
    receipts = {r["receipt"]["n"]: r["receipt"] for r in records if r["kind"] == "gate_receipt"}
    assert all(receipts[f["n"]]["sent"] == f["sent"] for f in held)
    # Each report is a record of the recorder's, after the command it names.
    where = {r["feedback"]["n"]: r["n"] for r in records if r["kind"] == "actuator_feedback"}
    assert all(where[n] > n for n in where)
    assert records[0]["settings"]["feedback_public_key"] == FEEDBACK_PUBLIC
    text = subprocess.run([sys.executable, run_scenarios.VERIFIER, m.w.journal, "--root", m.root, "--rulesets",
                           os.path.join(m.w.data, "rulesets")] + m.keys(), capture_output=True, text=True).stdout
    assert "actuator feedback: 4 report(s) in the journal; 0 command(s) with no feedback" in text
    assert text.rstrip().endswith("NO FINDINGS")


def test_a_belt_that_does_not_move_is_in_the_journal_as_its_controller_reported_it(fed):
    """The gate applied the command and says so in its receipt. The belt did not move, and
    the report says so. The verifier checks the report is genuine and belongs to the
    command; it does not judge whether the belt obeyed, so the journal is clean."""
    m = fed()
    m.belt = lambda sent: {"speed_mm_s": 0}
    m.command(400)
    m.command(600)
    m.stop()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    receipts = [r["receipt"] for r in m.records() if r["kind"] == "gate_receipt"]
    assert [(r["decision"], r["sent"]) for r in receipts] == [("applied", {"speed_mm_s": 400}),
                                                             ("applied", {"speed_mm_s": 600})]
    assert [(f["sent"], f["measured"]) for f in m.feedback_held()] == [
        ({"speed_mm_s": 400}, {"speed_mm_s": 0}), ({"speed_mm_s": 600}, {"speed_mm_s": 0})]


def test_feedback_works_without_receipts(fed):
    m = fed(receipts=False)
    m.command(400)
    m.command(500, BLOCKED)
    m.stop()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    assert (report["counts"]["gate_receipts"], report["counts"]["actuator_feedback"]) == (0, 2)


def test_a_command_refused_for_its_age_is_followed_by_a_report_of_the_safe_state(fed):
    m = fed(age_limit=1000, clock=False)
    m.command(400)
    late = m.command(600, late_ms=6000)
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["GATE_REFUSED"]
    report_of_late = [f for f in m.feedback_held() if f["n"] == late["n"]]
    assert len(report_of_late) == 1 and report_of_late[0]["sent"] == SAFE == report_of_late[0]["measured"]


def test_the_recorder_writes_down_only_what_the_feedback_key_signed_and_only_once(fed):
    m = fed()
    m.command(400)
    genuine = m.reports[0]
    body = {k: v for k, v in genuine.items() if k != "sig"}
    with_the_gates_key = ed.sign_record(GATE_SEED, dict(body, seq=1))
    with_the_recorders_key = ed.sign_record(SEED, dict(body, seq=1))
    for bad in (with_the_gates_key, with_the_recorders_key, dict(genuine, seq=1), genuine, "a report",
                {"schema": FEEDBACK_SCHEMA}):
        reply = m.ask({"op": "actuator_feedback", "feedback": bad})
        assert reply["ok"] is False and reply["fault"] is False, reply
    m.stop()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    assert report["counts"]["actuator_feedback"] == 1


def test_the_verifier_is_given_the_feedback_key_and_the_journal_must_name_that_one(fed):
    m = fed()
    m.command(400)
    m.stop()
    code, report = m.w.verify("--feedback-public-key", GATE_PUBLIC, "--gate-public-key", GATE_PUBLIC,
                              root=m.root, witness=False)
    assert code == 2 and found(report) == ["KEY_MISMATCH"]
    assert report["findings"][0]["journal_feedback_key"] == FEEDBACK_PUBLIC


def test_a_machine_whose_configuration_names_no_feedback_key_is_as_it_was(recorder, tmp_path):
    m = Machine(tmp_path, recorder)
    try:
        m.command(400)
        m.stop()
    finally:
        if m.proc.poll() is None:
            m.proc.kill()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    assert report["counts"]["actuator_feedback"] == 0 and report["counts"]["commands_without_feedback"] == 0
    code, report = m.verify("--feedback-public-key", FEEDBACK_PUBLIC)
    assert code == 2 and found(report) == ["KEY_MISMATCH"]


# --- missing ---------------------------------------------------------------------------------

def test_a_lost_report_leaves_a_command_without_feedback_and_a_gap_in_the_numbers(fed):
    m = fed()
    m.command(400)
    m.drop_feedback = lambda report: report["seq"] == 1
    lost = m.command(500)
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_FEEDBACK", "FEEDBACK_MISSING"]
    by_kind = {f["finding"]: f for f in report["findings"]}
    assert by_kind["COMMAND_WITHOUT_FEEDBACK"]["n"] == lost["n"]
    assert (by_kind["FEEDBACK_MISSING"]["missing"], by_kind["FEEDBACK_MISSING"]["first_missing"]) == (1, 1)


def test_a_lost_last_report_shows_only_as_a_command_without_feedback(fed):
    """What numbering cannot do: with nothing after it, a lost report leaves no gap. The
    command it was about still has no feedback, and that is what shows."""
    m = fed()
    m.command(400)
    m.drop_feedback = lambda report: report["seq"] == 1
    last = m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_FEEDBACK"]
    assert report["findings"][0]["n"] == last["n"]


def test_the_keeper_cannot_remove_a_report_without_it_showing(fed):
    m = fed()
    m.command(400)
    removed = m.command(500)
    m.command(300)
    m.stop()

    def remove(records):
        return [r for r in records if not (r["kind"] == "actuator_feedback" and r["feedback"]["n"] == removed["n"])]
    code, report = m.check_forged(remove)
    assert code == 2 and {"COMMAND_WITHOUT_FEEDBACK", "FEEDBACK_MISSING"} <= set(found(report))
    assert removed["n"] in [f["n"] for f in report["findings"] if f["finding"] == "COMMAND_WITHOUT_FEEDBACK"]


# --- altered -----------------------------------------------------------------------------------

def stopped_after_two_commands(fed, **how):
    m = fed(**how)
    m.command(400)
    m.command(500)
    return m.stop()


# The journal's keeper edits the last report. An edit anywhere earlier changes the hash of
# every record after it, so every receipt and report after it would name a hash that is no
# longer there: true, and reported, but not what these tests are about.

def test_the_keeper_cannot_change_what_a_report_says(fed):
    """The keeper changes what the belt did, signs the record again with the recorder's
    key and repairs every hash. The report inside is no longer one the feedback key signed."""
    m = stopped_after_two_commands(fed)

    def rewrite(records):
        for r in records:
            if r["kind"] == "actuator_feedback" and r["feedback"]["seq"] == 1:
                r["feedback"]["measured"] = {"speed_mm_s": 0}
    code, report = m.check_forged(rewrite)
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_FEEDBACK", "FEEDBACK_INVALID"]
    assert "not signed with the feedback key" in report["findings"][0]["reason"]
    assert report["findings"][1]["n"] == m.reports[1]["n"]


def test_a_report_changed_by_someone_without_the_recorders_key_breaks_its_record_too(fed):
    m = stopped_after_two_commands(fed)

    def rewrite(records):
        for r in records:
            if r["kind"] == "actuator_feedback" and r["feedback"]["seq"] == 1:
                r["feedback"]["measured"] = {"speed_mm_s": 0}
    code, report = m.check_forged(rewrite, with_the_key=False)
    assert code == 2 and {"SIGNATURE_INVALID", "FEEDBACK_INVALID"} <= set(found(report))


def test_a_report_changed_in_place_breaks_the_chain(fed):
    m = stopped_after_two_commands(fed)
    with open(m.w.journal, encoding="utf-8") as fh:
        lines = fh.readlines()
    at = [i for i, line in enumerate(lines) if '\\"kind\\":\\"actuator_feedback\\"' in line][0]
    assert '\\"measured\\":{\\"speed_mm_s\\":400}' in lines[at]
    lines[at] = lines[at].replace('\\"measured\\":{\\"speed_mm_s\\":400}', '\\"measured\\":{\\"speed_mm_s\\":0}')
    with open(m.w.journal, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)
    code, report = m.verify()
    assert code == 2 and report["level_reached"] == 1 and report["findings"]


# --- filed under the wrong command ----------------------------------------------------------

def test_the_keeper_cannot_file_a_report_under_another_command(fed):
    """With the recorder's key only: the second command's report now names the first. It is
    no longer signed by the feedback key, and the second command is left without feedback."""
    m = stopped_after_two_commands(fed)

    def refile(records):
        reports = [r["feedback"] for r in records if r["kind"] == "actuator_feedback"]
        reports[1].update(n=reports[0]["n"], hash=reports[0]["hash"])
    code, report = m.check_forged(refile)
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_FEEDBACK", "FEEDBACK_INVALID"]
    assert [f["n"] for f in report["findings"] if f["finding"] == "COMMAND_WITHOUT_FEEDBACK"] == [m.reports[1]["n"]]


def test_a_report_that_does_not_belong_to_the_command_it_names_is_a_finding(fed):
    """Reports the feedback key did sign, made to name a command they do not belong to.
    Made here with the feedback key, which only the robot should hold."""
    def run(change):
        m = fed()
        m.command(400)
        m.command(500, BLOCKED)
        m.command(300)
        m.stop()

        edited = []

        def edit(records):
            edited.append(change(records, [r for r in records if r["kind"] == "actuator_feedback"]))
            for r in records:
                if r["kind"] == "actuator_feedback":
                    r["feedback"] = ed.sign_record(FEEDBACK_SEED, r["feedback"])
            # Where the edited report now sits in the journal.
            edited[0] = records.index(edited[0])
            return records
        code, report = m.check_forged(edit)
        return code, report, edited[0]

    # Each change returns the record it edited. f[0], f[1], f[2]: the records holding the
    # reports for the first, the second (blocked) and the third command.
    def another_commands(records, f):            # the third report names the first command
        first = f[0]["feedback"]
        f[2]["feedback"].update(n=first["n"], hash=first["hash"], sent=first["sent"], measured=first["measured"])
        return f[2]

    def not_a_command(records, f):
        f[2]["feedback"]["n"] = 1                  # record 1 is recorder_start
        return f[2]

    def wrong_hash(records, f):
        f[2]["feedback"]["hash"] = "00" * 32
        return f[2]

    def a_later_record(records, f):
        f[2]["feedback"]["n"] = len(records) - 1
        return f[2]

    def something_never_sent(records, f):
        f[2]["feedback"].update(sent={"speed_mm_s": 999}, measured={"speed_mm_s": 999})
        return f[2]

    def blocked_but_moving(records, f):
        f[1]["feedback"].update(sent={"speed_mm_s": 500}, measured={"speed_mm_s": 500})
        return f[1]

    def not_what_the_receipt_says(records, f):   # the safe state passes on its own; the receipt says 300
        f[2]["feedback"].update(sent=SAFE, measured=SAFE)
        return f[2]

    def read_after_the_next_action(records, f):  # the next action is the second command's
        f[0]["feedback"]["at_ms"] = 10 ** 13
        return f[0]

    cases = ((another_commands, "already has feedback"), (not_a_command, "not a command"),
             (wrong_hash, "not the hash of record"), (a_later_record, "not before it in the journal"),
             (something_never_sent, "neither the record's applied command nor the safe state"),
             (blocked_but_moving, "for a blocked command"),
             (not_what_the_receipt_says, "says the gate sent something else"),
             (read_after_the_next_action, "read after the gate's next action"))
    for change, reason in cases:
        code, report, position = run(change)
        mine = [f for f in report["findings"] if f["finding"] == "FEEDBACK_MISMATCH" and f["n"] == position]
        assert code == 2 and len(mine) == 1 and reason in mine[0]["reason"], (change.__name__, report["findings"])


def test_a_number_outside_the_journal_is_a_finding_even_without_the_check_that_rules_it_out(fed, tmp_path):
    """Found by the mutation check of 17 October 2026: with the check that a report names an
    earlier record removed, the verifier crashed on a report naming a later record, where it
    should have reported a finding. The record a report or a receipt names is now looked up
    in a way that cannot fail, whatever the number.

    The journal: the last report names the last record in the journal, and the last receipt
    a record far past the end, each signed with its own key. The verifier as shipped reports
    both as naming a record that is not before them. A copy with that check removed, after
    proving it was there to remove, still exits 2, now because neither names a command."""
    m = fed()
    m.command(400)
    m.command(500)
    m.stop()

    def point_past(records):
        report = [r for r in records if r["kind"] == "actuator_feedback"][-1]
        report["feedback"] = ed.sign_record(FEEDBACK_SEED, dict(report["feedback"], n=len(records) - 1))
        receipt = [r for r in records if r["kind"] == "gate_receipt"][-1]
        receipt["receipt"] = ed.sign_record(GATE_SEED, dict(receipt["receipt"], n=10 ** 9))
    root = forge(m.w, point_past)
    args = [m.w.journal, "--root", root, "--rulesets", os.path.join(m.w.data, "rulesets"), "--public-key",
            m.w.public_key, "--json"] + m.keys()

    def run(verifier):
        done = subprocess.run([sys.executable, verifier] + args, capture_output=True, text=True)
        assert "Traceback" not in done.stderr, done.stderr
        report = json.loads(done.stdout)
        return done.returncode, {(f["finding"], f["reason"].split(", which")[-1]) for f in report["findings"]
                                 if f["finding"] in ("FEEDBACK_MISMATCH", "RECEIPT_MISMATCH")}

    code, said = run(run_scenarios.VERIFIER)
    assert code == 2 and said == {("FEEDBACK_MISMATCH", " is not before it in the journal"),
                                  ("RECEIPT_MISMATCH", " is not before it in the journal")}

    with open(run_scenarios.VERIFIER, encoding="utf-8") as fh:
        source = fh.read()
    check = "    if n < 0 or n >= position:\n"
    assert source.count(check) == 2                                  # one for receipts, one for reports
    without = tmp_path / "verifier_without_the_check.py"
    without.write_text(source.replace(check, "    if False:\n"), encoding="utf-8")
    code, said = run(str(without))
    assert code == 2 and said == {("FEEDBACK_MISMATCH", " is not a command"), ("RECEIPT_MISMATCH", " is not a command")}

    # And the lookup on its own, for any number.
    records, hashes = [{"kind": "command"}], ["00" * 32]
    for n in (-1, 1, 10 ** 9, "0", True, None):
        assert vj.record_named(records, hashes, n) == (None, None)
    assert vj.record_named(records, hashes, 0) == (records[0], hashes[0])


def test_a_report_put_after_a_later_commands_report_is_a_finding(fed):
    """The second command's report never reached the recorder. It is genuine, signed with
    the feedback key, and names the second command correctly. The recorder will not write
    it once a later report is in. Someone who writes it in anyway, after the third
    command's report, leaves it out of order, and the verifier says so."""
    m = fed()
    m.command(400)
    m.drop_feedback = lambda report: report["seq"] == 1
    second = m.command(500)
    m.drop_feedback = lambda report: False
    m.command(300)
    late = m.reports[1]
    assert late["n"] == second["n"] and signed_with(late, FEEDBACK_PUBLIC)
    refused = m.ask({"op": "actuator_feedback", "feedback": late})
    assert refused["ok"] is False and "not newer" in refused["error"]
    m.stop()

    def insert(records):
        last = [i for i, r in enumerate(records) if r["kind"] == "actuator_feedback"][-1]
        records.insert(last + 1, {"schema": records[last]["schema"], "kind": "actuator_feedback",
                                  "at": records[last]["at"], "feedback": late})
        return records
    code, report = m.check_forged(insert)
    reasons = [f["reason"] for f in report["findings"] if f["finding"] == "FEEDBACK_MISMATCH"]
    assert code == 2 and len(reasons) == 1 and "comes after the feedback for record" in reasons[0]
    assert {"FEEDBACK_MISSING", "FEEDBACK_INVALID", "COMMAND_WITHOUT_FEEDBACK"} <= set(found(report))


def test_a_robot_that_reads_after_its_next_action_is_caught_by_the_time_of_its_reading(fed):
    """A bug in the robot's control loop, not in the reporter: each reading is taken after
    the next action has been given, and filed under the command before. Every report is
    genuinely signed and names a real command. The time of the reading gives it away: it is
    later than the gate's receipt for the next action, on the robot's own clock."""
    m = fed(reads_late=True)
    m.command(400)
    m.command(600)
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2
    late = [f for f in report["findings"] if f["finding"] == "FEEDBACK_MISMATCH"]
    assert len(late) == 2 and all("read after the gate's next action" in f["reason"] for f in late)
    # And the last command, whose reading never came, has none.
    assert found(report).count("COMMAND_WITHOUT_FEEDBACK") == 1
    # What the late reports say the belt did is the next command's speed.
    assert [f["measured"]["speed_mm_s"] for f in m.feedback_held()] == [600, 300]


def broken_reporter(tmp_path, line, replacement):
    """A copy of the reporter with one line changed, after proving the line was there."""
    with open(os.path.join(REPO, "gate", "actuator_feedback.py"), encoding="utf-8") as fh:
        source = fh.read()
    assert source.count(line) == 1
    folder = tmp_path / "broken_reporter"
    folder.mkdir()
    (folder / "actuator_feedback.py").write_text(source.replace(line, replacement), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("broken_actuator_feedback", str(folder / "actuator_feedback.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.FeedbackReporter


def test_planted_bug_reporter_reports_only_commands_that_moved_the_belt(fed, tmp_path):
    """A reporter that follows applied commands only. The blocked command, where the belt
    was given the safe state, has no report, and the verifier says so."""
    reporter = broken_reporter(tmp_path, 'FOLLOWS_A_COMMAND = ("applied", "blocked", "stale_command")',
                               'FOLLOWS_A_COMMAND = ("applied",)')
    m = fed(reporter_class=reporter)
    m.command(400)
    blocked = m.command(500, BLOCKED)
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_FEEDBACK"]
    assert report["findings"][0]["n"] == blocked["n"]


def test_planted_bug_reporter_does_not_keep_its_number(fed, tmp_path):
    """A reporter that never saves its number starts again from 0 after a restart. The
    recorder will not write a report numbered no higher than the last, so the commands after
    the restart have none."""
    reporter = broken_reporter(tmp_path, "        self.save()\n        return signed", "        return signed")
    m = fed(reporter_class=reporter)
    m.command(400)
    m.reporter = reporter(m.reporter.state_path, FEEDBACK_SEED)     # the robot restarts
    after = m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_FEEDBACK"]
    assert report["findings"][0]["n"] == after["n"]
    assert m.replies[-1]["ok"] is False and "not newer" in m.replies[-1]["error"]


# --- malformed, and a change of key ------------------------------------------------------------

def test_a_malformed_report_is_a_finding(fed):
    for change in (lambda f: f.update(measured={"belt": 400}),
                   lambda f: f.update(measured={"speed_mm_s": "400"}),
                   lambda f: f.update(measured=None, state=None),
                   lambda f: f.update(state=[1, 2]),
                   lambda f: f.update(sent=["speed_mm_s"], measured=None, state={"x_mm": 1}),
                   lambda f: f.update(seq=-1),
                   lambda f: f.update(after_ms=-5),
                   lambda f: f.update(schema="sentinel-ledger/actuator-feedback/9"),
                   lambda f: f.pop("hash")):
        m = fed()
        m.command(400)
        m.stop()

        def edit(records):
            for r in records:
                if r["kind"] == "actuator_feedback":
                    change(r["feedback"])
                    r["feedback"] = ed.sign_record(FEEDBACK_SEED, r["feedback"])
        code, report = m.check_forged(edit)
        assert code == 2 and "FEEDBACK_INVALID" in found(report), report["findings"]


def test_a_report_in_a_journal_whose_settings_name_no_feedback_key_is_a_finding(fed):
    """The keeper takes the feedback key out of the first record's settings, so that no
    command is expected to have a report. The reports already in the journal now have no
    key to be checked against, and each is reported."""
    m = stopped_after_two_commands(fed)

    def drop_key(records):
        del records[0]["settings"]["feedback_public_key"]
    code, report = m.w.verify("--gate-public-key", GATE_PUBLIC, root=forge(m.w, drop_key), witness=False, gate=False)
    reasons = [f["reason"] for f in report["findings"] if f["finding"] == "FEEDBACK_INVALID"]
    assert code == 2 and len(reasons) == 2 and all("name no feedback key" in r for r in reasons)
    assert "COMMAND_WITHOUT_FEEDBACK" not in found(report)


def test_a_feedback_key_that_is_not_a_key_makes_the_settings_unusable(fed):
    m = stopped_after_two_commands(fed)

    def bad_key(records):
        records[0]["settings"]["feedback_public_key"] = "not a key"
    code, report = m.check_forged(bad_key)
    assert code == 2 and {"finding": "RECORD_MALFORMED", "n": 0,
                          "reason": "genesis lacks a usable state or settings"} in report["findings"]


def test_a_change_of_the_feedback_key_in_the_journal_is_a_finding(fed):
    """The recorder refuses one (tested in the recorder's own tests). A journal that has
    one anyway, written by someone else, is reported."""
    m = stopped_after_two_commands(fed)

    def change_key(records):
        genesis = records[0]
        settings = dict(genesis["settings"], feedback_public_key=GATE_PUBLIC)
        change = {"schema": genesis["schema"], "kind": "intervention_declared", "at": records[2]["at"],
                  "target": "config", "old": genesis["state"]["config_sha256"], "new": "11" * 32,
                  "operator": "someone", "reference": "none", "authorisation": None, "settings": settings}
        records.insert(2, change)
        return records
    code, report = m.check_forged(change_key)
    reasons = [f.get("reason", "") for f in report["findings"] if f["finding"] == "RECORD_MALFORMED"]
    assert code == 2 and any("feedback key" in r for r in reasons), report["findings"]
