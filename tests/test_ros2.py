"""The ROS 2 path: the recorder node and the simulated robot, launched together as two
processes, driven over topics. docs/SPEC.md section 15.

These tests need a sourced ROS 2 environment (run `. /opt/ros/lyrical/setup.sh` first).
Where there is none they are skipped, and test_ros2_tests_ran_or_were_skipped_knowingly
says so in its name. Nothing here uses the network beyond localhost.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

HAVE_ROS = shutil.which("ros2") is not None and bool(os.environ.get("ROS_DISTRO"))
pytestmark = pytest.mark.skipif(not HAVE_ROS, reason="no sourced ROS 2 environment")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "ros2", "run_ros_scenarios.py")
EXPORTER = os.path.join(REPO, "export", "export_journal.py")
CHECKER = os.path.join(REPO, "export", "check_export.py")
SIM_RUNNER = os.path.join(REPO, "ros2", "run_on_your_sim.py")
STAND_IN = os.path.join(REPO, "ros2", "stand_in_sim.py")
# A domain of its own and localhost-only discovery, so nothing else on the machine or
# the network can take part.
ENV = dict(os.environ, ROS_DOMAIN_ID="78", ROS_AUTOMATIC_DISCOVERY_RANGE="LOCALHOST")


def expected(number):
    import run_ros_scenarios
    return json.loads(json.dumps(run_ros_scenarios.EXPECTED[number]))


def run(number, node_bin, out, slow_flush_node=None, **extra_env):
    """Run one scenario in its own process. Returns (driver exit code, observations)."""
    slow = ["--slow-flush-node", slow_flush_node] if slow_flush_node else []
    done = subprocess.run([sys.executable, DRIVER, "--node", node_bin, "--out", str(out), "--only", str(number),
                           "--json"] + slow, capture_output=True, text=True, env=dict(ENV, **extra_env), timeout=300)
    return done.returncode, json.loads(done.stdout.strip().splitlines()[-1])[str(number)]


@pytest.fixture()
def tmp_path(tmp_path):
    """Every test in this file keeps its journal in a RAM-backed folder where there is one.
    These tests are judged pass or fail and several turn on timing; a disk whose flushes
    can take seconds fails them for a reason that is true and is not theirs to judge
    (docs/SPEC.md section 15.8). For tests only: a real journal does not belong in RAM.
    ros2/soak_real_disk.py is the run on a real disk."""
    if not (os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK)):
        yield tmp_path
        return
    folder = tempfile.mkdtemp(prefix="sentinel-ledger-pytest-", dir="/dev/shm")
    try:
        yield type(tmp_path)(folder)
    finally:
        for where, _, files in os.walk(folder):
            for name in files:
                os.chmod(os.path.join(where, name), 0o600)
        shutil.rmtree(folder, ignore_errors=True)


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13])
def test_ros_scenario_is_as_expected(number, ros_node, tmp_path):
    code, observed = run(number, ros_node(), tmp_path)
    want = expected(number)
    assert {k: observed.get(k) for k in want} == want
    assert code == 0


def test_a_six_second_flush_stops_the_robot_and_is_stated_in_the_journal(ros_node, tmp_path):
    """Scenario 11, on a node built so that one flush can be made slow. The deadman stops
    the robot at four seconds. The command, six seconds old when its record lands, is
    refused for its age and the robot stays stopped. The recorder writes a record stating
    the stall, and the verifier reports STORAGE_STALL: a finding, exit 2, and not an
    unexplained gap.

    The refusal is in the journal: the gate signs a receipt saying it refused that record
    for its age, the recorder writes the receipt down as a record, and the verifier
    reports GATE_REFUSED with the reason, in its JSON and in the text a person reads.
    Before receipts the journal showed that command as recorded and forwarded, and
    nothing else."""
    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=ros_node("test-slow-flush"))
    want = expected(11)
    assert {k: observed.get(k) for k in want} == want
    assert code == 0
    assert observed["age_refusal_in_journal"] is True and observed["verifier_output_shows_it"] is True
    assert "GATE_REFUSED" in observed["findings"] and "refused:age" in observed["receipts"]
    with open(os.path.join(str(tmp_path), "ros_scenario_11", "verifier_output.txt"), encoding="utf-8") as fh:
        report = fh.read()
    assert '  GATE_REFUSED n=' in report and 'reason="age"' in report and "ms old; the limit is 1000 ms" in report


def test_the_slow_flush_switch_does_nothing_in_a_normal_build(ros_node, tmp_path):
    """The same scenario with the node as shipped: the environment variable is ignored,
    nothing is slow, and there is no stall to state."""
    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=ros_node())
    assert code == 2
    assert observed["findings"] == [] and observed["stalls_stated"] == 0 and observed["deadman_trips"] == 0


def test_the_two_nodes_are_separate_processes_started_by_one_launch(ros_node, tmp_path):
    run(3, ros_node(), tmp_path)
    with open(os.path.join(str(tmp_path), "ros_scenario_3", "launch-1.log"), encoding="utf-8") as fh:
        log = fh.read()
    started = [line for line in log.splitlines() if "process started with pid" in line]
    assert len(started) == 2
    assert "[recorder-" in started[0] and "[robot-" in started[1]
    assert len({line.split("[")[-1] for line in started}) == 2


def test_an_exit_is_how_the_process_really_ended_not_what_its_exit_file_says(tmp_path):
    """Launch states how each process ended. A recorder that wrote 0 to its exit file and
    then crashed as it shut down (signal 11) has not exited 0, and is not reported as 0."""
    import run_ros_scenarios
    log = tmp_path / "launch-1.log"
    log.write_text(
        "[INFO] [recorder-1]: process started with pid [439]\n"
        "[INFO] [robot-2]: process started with pid [440]\n"
        "[recorder-1] {\"kind\": \"stop\"}\n"
        "[ERROR] [recorder-1]: process has died [pid 439, exit code -11, cmd '/x/sentinel_recorder_node'].\n"
        "[ERROR] [robot-2]: process has died [pid 440, exit code 2, cmd 'python3 sim_robot.py'].\n",
        encoding="utf-8")
    assert run_ros_scenarios.process_exits(str(log)) == {"recorder": -11, "robot": 2}
    log.write_text("[INFO] [recorder-1]: process has finished cleanly [pid 439]\n", encoding="utf-8")
    assert run_ros_scenarios.process_exits(str(log)) == {"recorder": 0}
    assert run_ros_scenarios.describe_exit(-11, 0) == "-11 (SIGSEGV), though its exit file said 0"
    assert run_ros_scenarios.describe_exit(0, 0) == "0"
    assert run_ros_scenarios.describe_exit(None, 0).startswith("unknown")


def test_the_robot_has_no_plain_twist_input_and_the_node_publishes_none():
    """The stated design, checked in the source: the robot subscribes to nothing of type
    Twist, and the recorder node creates no Twist publisher."""
    with open(os.path.join(REPO, "ros2", "sim_robot.py"), encoding="utf-8") as fh:
        robot = fh.read()
    assert "Twist" not in robot.replace("plain Twist input", "")
    with open(os.path.join(REPO, "ros2", "sentinel_recorder_node", "src", "main.rs"), encoding="utf-8") as fh:
        node = fh.read()
    assert "create_publisher::<geometry_msgs" not in node
    assert node.count("create_publisher::<Text>") == 2


# --- planted bugs on the ROS path -------------------------------------------------------

def test_planted_bug_twist_accepts_nan_and_infinity(ros_node, tmp_path):
    """The node stops refusing NaN, infinity and over-limit values. An infinite turn rate
    becomes a record and reaches the robot. Scenario 2 turns red."""
    code, observed = run(2, ros_node("planted-bug-twist-accepts-nonfinite"), tmp_path)
    assert code == 2
    assert observed["replies_ok"] == [True] * 7
    assert observed["commands"] == 7 and len(observed["sent"]) == 7


def test_planted_bug_node_drops_a_record(ros_node, tmp_path):
    """The node writes a record and never publishes it. Nothing unrecorded reaches the
    robot: the gate sees a gap, refuses every record after it, and the robot gets only the
    safe state. The robot's exit code turns red."""
    code, observed = run(1, ros_node("planted-bug-ros-drops-a-record"), tmp_path)
    assert code == 2
    assert observed["robot_exit"] == 2
    # The journal is whole, and it now says what the gate did: it holds the gate's signed
    # refusals, and the commands that were refused have no receipt saying they were applied,
    # and no report of what the wheels did, since the robot never acted on them. With every
    # record refused, no valid record arrives, and the deadman trips as well.
    assert observed["verifier_exit"] == 2
    assert observed["findings"] == ["COMMAND_WITHOUT_FEEDBACK", "COMMAND_WITHOUT_RECEIPT", "GATE_DEADMAN",
                                    "GATE_REFUSED"]
    assert "refused:chain" in observed["receipts"] and "deadman" in observed["receipts"]
    assert [why for why, _ in observed["sent"] if why == "applied"] == [] or \
        len([why for why, _ in observed["sent"] if why == "applied"]) < 5
    assert ["gate_refused", 0] in observed["sent"]


def test_planted_bug_forward_first_on_the_ros_path(ros_node, tmp_path):
    """The same bound as the file demo. The node publishes the record before writing it,
    and the write fails: that one command reaches the robot. The gate's head is then not
    in the journal, and the verifier exits 2."""
    code, observed = run(5, ros_node("planted-bug-forward-first"), tmp_path)
    assert code == 2
    assert observed["applied"] == [500, 700, 900]
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["GATE_HEAD_NOT_IN_JOURNAL"]
    # After the restart the gate refuses the recorder, so the next command does not move the robot.
    assert observed["exits_after_restart"][1] == 2
    assert observed["applied_after_restart"] == []


def test_planted_bug_gate_skips_the_signature_check(ros_node, tmp_path):
    """The gate with its signature check removed. The forged record of scenario 7 is
    accepted and the robot moves at the forger's 1500 mm/s: the scenario turns red. This
    is what the gate did before records were signed.

    The gate is Python, so the bug is planted by handing the robot a copy of the gate with
    one line changed, and the test first proves the line was there to change."""
    broken = tmp_path / "broken_gate"
    broken.mkdir()
    with open(os.path.join(REPO, "gate", "actuator_gate.py"), encoding="utf-8") as fh:
        source = fh.read()
    check = "    if not signature_ok(record, public_key):"
    assert source.count(check) == 1
    (broken / "actuator_gate.py").write_text(source.replace(check, "    if False:"), encoding="utf-8")

    code, observed = run(7, ros_node(), tmp_path, SL_GATE_DIR=str(broken))
    assert code == 2
    assert observed["forged"] == [True, "applied"]
    assert ["applied", 1500] in observed["sent"]
    # With the forgery accepted, the real recorder's next record no longer follows the
    # gate's head, and the verifier finds the gate's head missing from the journal.
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["GATE_HEAD_NOT_IN_JOURNAL"]

    # The same scenario with the real gate, in the same test, so the difference is the one line.
    code, observed = run(7, ros_node(), tmp_path)
    assert code == 0 and observed["forged"] == [False, "gate_refused"]
    assert ["applied", 1500] not in observed["sent"]


def test_planted_bug_gate_has_no_deadman(ros_node, tmp_path):
    """The gate with its deadman removed, which is the gate as it was. The recorder goes
    silent for ten seconds with the robot at 0.5 m/s, and the robot keeps going for all of
    it: scenario 10 turns red.

    Planted the same way as the signature bug: a copy of the gate with one line changed,
    after proving the line was there to change."""
    broken = tmp_path / "gate_without_deadman"
    broken.mkdir()
    with open(os.path.join(REPO, "gate", "actuator_gate.py"), encoding="utf-8") as fh:
        source = fh.read()
    check = "        if self.deadman_seconds is None or self.last_valid is None or self.tripped:"
    assert source.count(check) == 1
    (broken / "actuator_gate.py").write_text(source.replace(check, "        if True:"), encoding="utf-8")

    code, observed = run(10, ros_node(), tmp_path, SL_GATE_DIR=str(broken))
    assert code == 2
    assert observed["deadman_trips"] == 0 and observed["robot_stopped_short"] is False
    assert observed["sent"] == [["applied", 500], ["applied", 300]]
    # The journal looks the same either way: it shows the gap. Only the robot differs.
    assert observed["findings"] == ["HEARTBEAT_GAP"]

    code, observed = run(10, ros_node(), tmp_path)
    assert code == 0 and observed["deadman_trips"] == 1 and observed["robot_stopped_short"] is True


def test_planted_bug_gate_does_not_check_a_commands_age(ros_node, tmp_path):
    """The gate with its age check removed, which is the gate as it was. In scenario 11
    the robot is stopped by the deadman at four seconds, and at six it starts moving
    again on a command six seconds old: the scenario turns red.

    Planted the same way as the other gate bugs: a copy of the gate with one line changed,
    after proving the line was there to change."""
    broken = tmp_path / "gate_without_age_check"
    broken.mkdir()
    with open(os.path.join(REPO, "gate", "actuator_gate.py"), encoding="utf-8") as fh:
        source = fh.read()
    check = "            if stale is not None:"
    assert source.count(check) == 1
    (broken / "actuator_gate.py").write_text(source.replace(check, "            if False:"), encoding="utf-8")

    slow = ros_node("test-slow-flush")
    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=slow, SL_GATE_DIR=str(broken))
    assert code == 2
    assert observed["stale_refusals"] == 0
    # The stale command moved the robot.
    assert observed["sent"] == [["applied", 500], ["deadman", 0], ["applied", 200], ["applied", 300]]
    # The stall is stated either way. But the journal now tells the two gates apart: this
    # one's receipt says it applied the old command, where the real gate's says refused.
    assert observed["findings"] == ["GATE_DEADMAN", "STORAGE_STALL"]
    assert observed["receipts"] == ["applied", "deadman", "applied", "applied"]

    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=slow)
    assert code == 0 and observed["stale_refusals"] == 1
    assert ["applied", 200] not in observed["sent"]
    assert observed["receipts"] == ["applied", "deadman", "refused:age", "applied"]


def test_planted_bug_gate_drops_the_receipts_for_its_refusals(ros_node, tmp_path):
    """The gate refuses as it should and keeps quiet about it: every receipt for a refusal
    is dropped before it is sent. The robot behaves exactly as before. The journal is what
    turns red.

    Scenario 11: the command refused for its age has no receipt, and the gate's receipt
    numbers skip one. The verifier reports both. It cannot say the command was refused,
    because nothing in the journal says so; it says the journal does not account for it.

    Scenario 7: the forged record was never a command of the recorder's, so no command is
    left without a receipt. The gap in the gate's numbers still shows.

    Planted the same way as the other gate bugs: a copy of the gate with one line changed,
    after proving the line was there to change."""
    broken = tmp_path / "gate_that_hides_refusals"
    broken.mkdir()
    with open(os.path.join(REPO, "gate", "actuator_gate.py"), encoding="utf-8") as fh:
        source = fh.read()
    line = "        return signed\n"
    assert source.count(line) == 1
    (broken / "actuator_gate.py").write_text(
        source.replace(line, '        return None if signed["decision"] == "refused" else signed\n'), encoding="utf-8")

    slow = ros_node("test-slow-flush")
    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=slow, SL_GATE_DIR=str(broken))
    assert code == 2
    # The robot did the right thing: stopped by the deadman, the stale command not carried out.
    assert observed["sent"] == [["applied", 500], ["deadman", 0], ["stale_command", 0], ["applied", 300]]
    assert observed["stale_refusals"] == 1
    # The journal has no receipt for the refused command, and the verifier says so.
    assert observed["receipts"] == ["applied", "deadman", "applied"]
    assert observed["age_refusal_in_journal"] is False and observed["verifier_reports_the_age_refusal"] is False
    assert observed["verifier_exit"] == 2
    assert observed["findings"] == ["COMMAND_WITHOUT_RECEIPT", "GATE_DEADMAN", "RECEIPT_MISSING", "STORAGE_STALL"]

    code, observed = run(7, ros_node(), tmp_path, SL_GATE_DIR=str(broken))
    assert code == 2
    assert observed["forged"] == [False, "gate_refused"] and ["applied", 1500] not in observed["sent"]
    assert observed["receipts"] == ["applied", "applied"]
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["RECEIPT_MISSING"]

    # The same two scenarios with the real gate, so the difference is the one line.
    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=slow)
    assert code == 0 and "GATE_REFUSED" in observed["findings"] and "RECEIPT_MISSING" not in observed["findings"]
    code, observed = run(7, ros_node(), tmp_path)
    assert code == 0 and observed["findings"] == ["GATE_REFUSED"]


def test_planted_bug_gate_signs_no_receipts(ros_node, tmp_path):
    """The gate with its receipts removed, which is the gate as it was. The robot moves as
    commanded. Every command record is in the journal with nothing to say what the gate
    did with it, and the verifier reports each one."""
    broken = tmp_path / "gate_without_receipts"
    broken.mkdir()
    with open(os.path.join(REPO, "gate", "actuator_gate.py"), encoding="utf-8") as fh:
        source = fh.read()
    check = "        if self.gate_key is None or about is None:"
    assert source.count(check) == 1
    (broken / "actuator_gate.py").write_text(source.replace(check, "        if True:"), encoding="utf-8")

    code, observed = run(3, ros_node(), tmp_path, SL_GATE_DIR=str(broken))
    assert code == 2
    assert observed["sent"] == [["blocked", 0], ["applied", 500], ["blocked", 0], ["applied", 500]]
    assert observed["receipts"] == []
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["COMMAND_WITHOUT_RECEIPT"]

    code, observed = run(3, ros_node(), tmp_path)
    assert code == 0 and observed["receipts"] == ["blocked", "applied", "blocked", "applied"]


def test_planted_bug_reporter_reports_only_commands_that_moved_the_wheels(ros_node, tmp_path):
    """The feedback reporter follows applied commands only. In scenario 3 the two blocked
    commands, where the wheels were given the safe state, have no feedback, and the
    verifier reports both. The robot moves exactly as before.

    Planted the same way as the gate bugs: a copy of the reporter with one line changed,
    after proving the line was there to change. The robot takes the gate from gate/."""
    broken = tmp_path / "reporter_that_skips_blocked"
    broken.mkdir()
    with open(os.path.join(REPO, "gate", "actuator_feedback.py"), encoding="utf-8") as fh:
        source = fh.read()
    line = 'FOLLOWS_A_COMMAND = ("applied", "blocked", "stale_command")'
    assert source.count(line) == 1
    (broken / "actuator_feedback.py").write_text(source.replace(line, 'FOLLOWS_A_COMMAND = ("applied",)'),
                                                 encoding="utf-8")

    code, observed = run(3, ros_node(), tmp_path, SL_GATE_DIR=str(broken))
    assert code == 2
    assert observed["sent"] == [["blocked", 0], ["applied", 500], ["blocked", 0], ["applied", 500]]
    assert observed["feedback"] == ["none", 500, "none", 500]
    assert observed["verifier_exit"] == 2 and observed["findings"] == ["COMMAND_WITHOUT_FEEDBACK"]

    code, observed = run(3, ros_node(), tmp_path)
    assert code == 0 and observed["feedback"] == [0, 500, 0, 500]


def test_a_scenario_13_journal_exports_and_checks_clean_and_an_altered_report_is_found(ros_node, tmp_path):
    """docs/EXPORT.md on a journal from the ROS path: two commands, two receipts and two
    reports of wheels that never turned. Exported in both formats, it checks clean against
    the three keys its genesis record names. A report changed in the exported file is found
    by the feedback key."""
    code, observed = run(13, ros_node(), tmp_path)
    assert code == 0 and observed["reports_published"] == 2
    data = os.path.join(str(tmp_path), "ros_scenario_13", "data")
    journal = os.path.join(data, "logchain.journal")
    with open(os.path.join(data, "logchain.state"), encoding="utf-8") as fh:
        root = json.load(fh)["merkle_root"]

    def check(path):
        done = subprocess.run([sys.executable, CHECKER, path, "--root", root, "--json"], capture_output=True, text=True)
        return done.returncode, json.loads(done.stdout)

    for fmt in ("syslog", "cef"):
        path = os.path.join(str(tmp_path), "scenario_13." + fmt)
        done = subprocess.run([sys.executable, EXPORTER, journal, "--format", fmt, "--out", path],
                              capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        code, report = check(path)
        assert (code, report["findings"]) == (0, [])
        assert (report["counts"]["feedback_checked"], report["counts"]["receipts_checked"]) == (2, 2)
        with open(path, encoding="utf-8", newline="") as fh:
            lines = fh.read().splitlines(True)
        k = next(i for i, line in enumerate(lines) if '"kind":"actuator_feedback"' in line)
        altered = re.sub(r'"measured":\{"(\w+)":(-?\d+)',
                         lambda g: '"measured":{"%s":%d' % (g.group(1), int(g.group(2)) + 100), lines[k], count=1)
        assert altered != lines[k]
        lines[k] = altered
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("".join(lines))
        code, report = check(path)
        assert code == 2
        assert [(f["n"], f["reason"]) for f in report["findings"] if f["finding"] == "FEEDBACK_SIGNATURE_INVALID"] == \
            [(k, "the feedback is not signed with the feedback key")]


# --- a signed log on someone else's simulation (ros2/run_on_your_sim.py) ----------------

def run_on_sim(ros_node, out, sim_args="", *extra):
    done = subprocess.run([sys.executable, SIM_RUNNER, "--node", ros_node(), "--out", str(out), "--start-timeout",
                           "60", "--sim", "%s %s %s" % (sys.executable, STAND_IN, sim_args)] + list(extra),
                          capture_output=True, text=True, env=ENV, timeout=300)
    run = os.path.join(str(out), "run")
    with open(os.path.join(run, "data", "logchain.journal"), encoding="utf-8") as fh:
        records = [json.loads(json.loads(line)["raw"]) for line in fh]
    with open(os.path.join(run, "verifier_output.json"), encoding="utf-8") as fh:
        verified = json.load(fh)
    return done, run, records, verified


def test_a_signed_log_on_a_stand_in_simulation(ros_node, tmp_path):
    """The runner in front of a simulation it knows nothing about: five commands, each a
    signed record the gate checked before the robot was given anything, a receipt for
    each, and a feedback report of what the simulation's odometry measured."""
    done, run, records, verified = run_on_sim(ros_node, tmp_path)
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    for name in ("verifier_output.txt", "journal.syslog", "export_check.txt", "SUMMARY.md"):
        assert os.path.getsize(os.path.join(run, name)) > 0, name
    assert verified["findings"] == []
    commands = [r for r in records if r["kind"] == "command"]
    assert [c["outcome"] for c in commands] == ["unchanged", "unchanged", "blocked", "unchanged", "unchanged"]
    receipts = {r["receipt"]["n"]: r["receipt"]["decision"] for r in records
                if r["kind"] == "gate_receipt" and r["receipt"]["decision"] != "deadman"}
    assert [receipts[c["n"]] for c in commands] == ["applied", "applied", "blocked", "applied", "applied"]
    reports = {r["feedback"]["n"]: r["feedback"] for r in records if r["kind"] == "actuator_feedback"}
    assert sorted(reports) == [c["n"] for c in commands]
    forward, turn, blocked = (reports[c["n"]] for c in commands[:3])
    assert forward["sent"]["linear_x_mm_s"] == 200 and forward["measured"]["linear_x_mm_s"] > 0
    assert turn["sent"]["angular_z_mrad_s"] == 500 and turn["measured"]["angular_z_mrad_s"] > 0
    assert blocked["sent"]["linear_x_mm_s"] == 0
    assert all(set(f["state"]) == {"x_mm", "y_mm", "heading_mrad"} for f in reports.values())
    with open(os.path.join(run, "export_check.txt"), encoding="utf-8") as fh:
        assert fh.read().rstrip().endswith("NO FINDINGS")
    with open(os.path.join(run, "SUMMARY.md"), encoding="utf-8") as fh:
        summary = fh.read()
    assert "Verifier exit 0, findings: none." in summary and summary.count("\n| ") == 6
    assert "Recorder exit 0, bridge exit 0 " in summary
    assert "once the odometry had been arriving steadily" in summary


def test_twist_stamped_and_a_robot_that_does_not_move_are_in_the_journal_as_odometry_saw_them(ros_node, tmp_path):
    """The other message type, and a simulated robot whose wheels never turn. The gate
    applied every command it should have and says so; the feedback says the robot did not
    move; the verifier reports nothing, because it does not judge obedience (SPEC 4.6).
    The simulation also leaves a process behind that ignores SIGINT and SIGTERM, as
    Gazebo's server can: the runner stops it."""
    left = tmp_path / "left_behind.pid"
    done, run, records, verified = run_on_sim(ros_node, tmp_path / "out",
                                              "--cmd-type twist_stamped --stuck --leave-behind %s" % left,
                                              "--cmd-type", "twist_stamped")
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
    assert "still running after its launch ended; it has been stopped" in done.stdout
    pid = int(left.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert verified["findings"] == []
    reports = [r["feedback"] for r in records if r["kind"] == "actuator_feedback"]
    assert len(reports) == 5
    assert any(f["sent"]["linear_x_mm_s"] == 200 for f in reports)
    assert all(f["measured"]["linear_x_mm_s"] == 0 and f["measured"]["angular_z_mrad_s"] == 0 for f in reports)


def test_on_a_simulation_slower_than_real_time_the_reading_waits_for_its_own_time(ros_node, tmp_path):
    """A stand-in whose clock runs at 0.6 of real time and stamps its odometry with it. The
    runner has the bridge wait until the odometry's stamps have advanced one second before
    each reading, about 1.67 s of wall time; told to use the wall clock, it reads after one
    wall second, 0.6 s of the robot's time. The feedback reports themselves are the same
    kind either way (SPEC 4.6)."""
    for clock, low, high in (("stamp", 1550, 2600), ("wall", 950, 1450)):
        done, run, records, verified = run_on_sim(ros_node, tmp_path / clock, "--clock-rate 0.6",
                                                  "--read-clock", clock)
        assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-3000:]
        assert verified["findings"] == []
        reports = [r["feedback"] for r in records if r["kind"] == "actuator_feedback"]
        assert len(reports) == 5
        assert all(low <= f["after_ms"] <= high for f in reports), (clock, [f["after_ms"] for f in reports])
        with open(os.path.join(run, "SUMMARY.md"), encoding="utf-8") as fh:
            summary = fh.read()
        rate = float(re.search(r"the time in the odometry's stamps ran at ([0-9.]+) of real time",
                               summary).group(1))
        assert 0.45 <= rate <= 0.7, rate
        simulated = [float(x) for x in re.findall(r"\(([0-9.]+) s simulated\)", summary)]
        assert len(simulated) == 5
        if clock == "stamp":
            assert "once the stamps had advanced 1 s" in summary
            assert all(0.95 <= x <= 1.6 for x in simulated), simulated
        else:
            assert "on the wall clock (--read-clock wall)" in summary
            assert all(x < 0.95 for x in simulated), simulated


def test_a_simulation_whose_time_stands_still_is_not_driven(ros_node, tmp_path):
    """A stand-in that publishes odometry while its time stands still: every stamp the same.
    The runner waits for the stamps to advance steadily, gives up after --steady-timeout,
    sends no command, exits 1 and leaves nothing of the run behind."""
    left = tmp_path / "left_behind.pid"
    done = subprocess.run([sys.executable, SIM_RUNNER, "--node", ros_node(), "--out", str(tmp_path / "out"),
                           "--start-timeout", "60", "--steady-timeout", "5", "--sim",
                           "%s %s --paused --leave-behind %s" % (sys.executable, STAND_IN, left)],
                          capture_output=True, text=True, env=ENV, timeout=300)
    assert done.returncode == 1, done.stdout[-3000:] + done.stderr[-3000:]
    assert "could not run: timed out waiting for odometry arriving steadily" in done.stderr
    pid = int(left.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with open(os.path.join(str(tmp_path / "out"), "run", "data", "logchain.journal"), encoding="utf-8") as fh:
        records = [json.loads(json.loads(line)["raw"]) for line in fh]
    assert not [r for r in records if r["kind"] == "command"]


@pytest.mark.skipif(False, reason="always runs")
def test_ros2_tests_ran_or_were_skipped_knowingly():
    """Fails nowhere. It exists so the count of skipped tests is read and not missed:
    without ROS 2, every other test in this file is skipped, not passed."""
    assert True
