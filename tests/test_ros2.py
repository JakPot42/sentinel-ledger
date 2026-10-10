"""The ROS 2 path: the recorder node and the simulated robot, launched together as two
processes, driven over topics. docs/SPEC.md section 15.

These tests need a sourced ROS 2 environment (run `. /opt/ros/lyrical/setup.sh` first).
Where there is none they are skipped, and test_ros2_tests_ran_or_were_skipped_knowingly
says so in its name. Nothing here uses the network beyond localhost.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

HAVE_ROS = shutil.which("ros2") is not None and bool(os.environ.get("ROS_DISTRO"))
pytestmark = pytest.mark.skipif(not HAVE_ROS, reason="no sourced ROS 2 environment")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "ros2", "run_ros_scenarios.py")
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


@pytest.mark.parametrize("number", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12])
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
    unexplained gap."""
    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=ros_node("test-slow-flush"))
    want = expected(11)
    assert {k: observed.get(k) for k in want} == want
    assert code == 0


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
    assert "sentinel_recorder_node" in started[0] and "python3" in started[1]
    assert len({line.split("[")[-1] for line in started}) == 2


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
    assert observed["verifier_exit"] == 0  # the journal itself is whole
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
    # The journal is the same either way: the stall is stated. Only the robot differs.
    assert observed["findings"] == ["STORAGE_STALL"]

    code, observed = run(11, ros_node(), tmp_path, slow_flush_node=slow)
    assert code == 0 and observed["stale_refusals"] == 1
    assert ["applied", 200] not in observed["sent"]


@pytest.mark.skipif(False, reason="always runs")
def test_ros2_tests_ran_or_were_skipped_knowingly():
    """Fails nowhere. It exists so the count of skipped tests is read and not missed:
    without ROS 2, every other test in this file is skipped, not passed."""
    assert True
