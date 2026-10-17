#!/usr/bin/env python3
"""Run the ROS 2 scenarios and judge each one by exit codes.

    . /opt/ros/lyrical/setup.sh
    python3 ros2/run_ros_scenarios.py --node /path/to/sentinel_recorder_node [--out DIR] [--only N]
                                      [--slow-flush-node /path/to/a/test/build]

Where the journal goes. These scenarios are judged pass or fail, and several of them turn
on timing: a heartbeat every two seconds, a gap after four. On a disk whose flushes can
take seconds they fail for a true reason that has nothing to do with the code under test
(docs/SPEC.md section 15.8). So by default the scenario folders, journal included, go to a
RAM-backed folder under /dev/shm. That is for these tests only: a journal in RAM is gone
at power-off and is no place for a real one. `--out DIR` puts them wherever you say, and
ros2/soak_real_disk.py runs the same scenarios on a real disk and reports what it measures.

Each scenario starts the recorder node and the simulated robot together with `ros2
launch`, as two processes, and then acts as the other nodes on the graph: a controller
publishing Twist on cmd_vel_in, a safety sensor publishing on safety_inputs, and, where
the scenario calls for it, a rogue node publishing on cmd_vel_out.

The robot's gate signs a receipt for every command record it takes in, every message it
refuses and every deadman trip, and the recorder writes each receipt into the journal.
After each command record it takes in, the robot also signs, with the feedback key, what
its wheels then did, and the recorder writes that into the journal too. Every scenario
checks the receipts and the feedback the journal ends up holding.

Exit 0 only if every observation of every scenario is the expected one.

  1  clean run: commands inside the limits, all six Twist fields, a quiet period with heartbeats
  2  the speed clamp changes commands; NaN, infinity and an over-limit value are refused
  3  no safety signal, then a broken light curtain: blocked, the robot gets the safe state
  4  a declared ruleset upload; firmware changed behind the recorder's back, found at the next start
  5  the journal becomes unwritable: the command is not forwarded; then a restart
  6  another node publishes to cmd_vel_out: no record, junk, a replay, a tampered record, a gap. All
     refused, and each refusal is in the journal with its reason
  7  another node forges a correctly chained record, with a signature lifted from a real one: refused
  8  the same, signed with a key of the forger's own: refused
  9  the same, with no signature at all: refused
 10  the recorder goes silent while the robot is moving (the process is frozen): the gate's
     deadman stops the robot after four seconds; the journal shows the gap
 11  one flush to disk takes six seconds (needs --slow-flush-node, a test build): the
     deadman stops the robot; the command, six seconds old when its record lands, is
     refused for its age and the robot stays stopped; the recorder states the stall in a
     record, and the verifier reports a storage stall and not an unexplained gap; the
     refusal for age and the deadman trip are in the journal as receipts, and the
     verifier reports both
 12  the folder for anchor statements becomes unwritable: commands still go through, and
     the recorder states the lost anchor in a signed record, which the verifier reports
 13  the wheels do not turn (a test switch in the simulated robot): the gate applies each
     command and says so in its receipt, and the feedback in the journal says the wheels
     did not move
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time

import rclpy
from geometry_msgs.msg import Twist
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "demo"))
import pure_ed25519 as ed  # noqa: E402
VERIFIER = os.path.join(REPO, "verifier", "verify_journal.py")
LAUNCH = os.path.join(HERE, "launch", "sentinel.launch.py")
RULESET_V2 = os.path.join(HERE, "changes", "ruleset_v2.json")
LATCHED = QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=1000, reliability=ReliabilityPolicy.RELIABLE,
                     durability=DurabilityPolicy.TRANSIENT_LOCAL)
CLEAR = {"light_curtain_clear": 1}
SERIAL = [0]


def leaf_hash(text):
    return hashlib.sha256(b"\x00" + text.encode("utf-8")).hexdigest()


class TimedOut(Exception):
    pass


class Session:
    """One working directory, and the processes and topics of one scenario."""

    def __init__(self, out, name, node_bin):
        self.node_bin = node_bin
        self.extra_env = {}
        self.dir = os.path.join(out, name)
        if os.path.isdir(self.dir):
            for folder, _, files in os.walk(self.dir):
                for f in files:
                    os.chmod(os.path.join(folder, f), stat.S_IWRITE | stat.S_IREAD)
            shutil.rmtree(self.dir)
        shutil.copytree(os.path.join(HERE, "installed"), os.path.join(self.dir, "installed"))
        self.installed = os.path.join(self.dir, "installed")
        # A fresh signing key for this run: the private half in a folder of its own, away
        # from the journal and readable by this user only; the public half in the configuration.
        self.key_file = os.path.join(self.dir, "recorder_private", "recorder.key")
        os.makedirs(os.path.dirname(self.key_file))
        seed = os.urandom(32)
        with os.fdopen(os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as fh:
            fh.write(seed.hex() + "\n")
        self.public_key = ed.public_key(seed).hex()
        # The gate's own key, for its receipts: a different key, in a folder on the
        # robot's side. The recorder is never given this file.
        self.gate_key_file = os.path.join(self.dir, "robot_private", "gate.key")
        os.makedirs(os.path.dirname(self.gate_key_file))
        gate_seed = os.urandom(32)
        with os.fdopen(os.open(self.gate_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as fh:
            fh.write(gate_seed.hex() + "\n")
        self.gate_public_key = ed.public_key(gate_seed).hex()
        # The feedback key, for what the wheels did: a third key, also on the robot's side.
        self.feedback_key_file = os.path.join(self.dir, "robot_private", "feedback.key")
        feedback_seed = os.urandom(32)
        with os.fdopen(os.open(self.feedback_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as fh:
            fh.write(feedback_seed.hex() + "\n")
        self.feedback_public_key = ed.public_key(feedback_seed).hex()
        config_path = os.path.join(self.installed, "config.json")
        with open(config_path, encoding="utf-8") as fh:
            config = fh.read().replace('"recorder_public_key": ""', '"recorder_public_key": "%s"' % self.public_key)
            config = config.replace('"gate_public_key": ""', '"gate_public_key": "%s"' % self.gate_public_key)
            config = config.replace('"feedback_public_key": ""', '"feedback_public_key": "%s"' % self.feedback_public_key)
        with open(config_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(config)
        self.data = os.path.join(self.dir, "data")
        self.journal = os.path.join(self.data, "logchain.journal")
        self.gate_state = os.path.join(self.dir, "robot_side", "gate.state")
        self.actuator = os.path.join(self.dir, "robot_side", "actuator.jsonl")
        self.runs = 0
        self.exits = []  # (recorder exit, robot exit) for each launch
        self.proc = self.node = None

    # -- starting and stopping ----------------------------------------------------------

    def launch(self):
        self.runs += 1
        for name in ("recorder.exit", "robot.exit"):
            if os.path.exists(os.path.join(self.dir, name)):
                os.remove(os.path.join(self.dir, name))
        env = dict(os.environ, SL_WORKDIR=self.dir, SL_NODE_BIN=self.node_bin, **self.extra_env)
        self.log = open(os.path.join(self.dir, "launch-%d.log" % self.runs), "w")
        self.proc = subprocess.Popen(["ros2", "launch", LAUNCH], env=env, stdout=self.log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        SERIAL[0] += 1
        self.node = rclpy.create_node("sl_scenario_driver_%d" % SERIAL[0])
        self.statuses, self.gate_events, self.link = [], [], []
        self.node.create_subscription(String, "recorder_status", lambda m: self.statuses.append(json.loads(m.data)), LATCHED)
        self.node.create_subscription(String, "gate_events", lambda m: self.gate_events.append(json.loads(m.data)), LATCHED)
        self.node.create_subscription(String, "cmd_vel_out", lambda m: self.link.append(m.data), LATCHED)
        self.cmd = self.node.create_publisher(Twist, "cmd_vel_in", 100)
        self.safety = self.node.create_publisher(String, "safety_inputs", 100)
        self.control = self.node.create_publisher(String, "recorder_control", 100)
        self.robot_control = self.node.create_publisher(String, "robot_control", 10)
        # What a rogue node would create: a publisher on the robot's only input.
        self.rogue_pub = self.node.create_publisher(String, "cmd_vel_out", LATCHED)
        self.wait(lambda: any(s.get("kind") == "start" for s in self.statuses), 40, "the recorder node to start")
        self.wait(lambda: all(p.get_subscription_count() >= 1 for p in (self.cmd, self.safety, self.control)),
                  20, "the recorder node's subscriptions")
        self.wait(lambda: self.robot_control.get_subscription_count() >= 1 and
                  self.rogue_pub.get_subscription_count() >= 2, 20, "the robot's subscriptions")
        started = [s for s in self.statuses if s.get("kind") == "start"][0]
        if started.get("ok"):
            self.wait(lambda: len(self.gate_events) >= 1, 20, "the gate to judge the recorder's first record")
        return started

    def wait(self, done, timeout, what):
        deadline = time.monotonic() + timeout
        while not done():
            if time.monotonic() > deadline:
                raise TimedOut("timed out waiting for " + what)
            rclpy.spin_once(self.node, timeout_sec=0.05)

    def quiet(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            rclpy.spin_once(self.node, timeout_sec=0.05)

    def end(self):
        """Ask the recorder to stop and the robot to shut down, and collect exit codes."""
        stopped = self.ask(self.control, {"op": "stop"}, "stop")
        self.quiet(0.5)
        self.robot_control.publish(String(data=json.dumps({"op": "shutdown"})))
        self.quiet(0.5)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGINT)
            self.proc.wait(timeout=30)
        self.log.close()
        self.node.destroy_node()
        codes = []
        for name in ("recorder.exit", "robot.exit"):
            try:
                with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
                    codes.append(json.load(fh)["exit"])
            except (OSError, ValueError):
                codes.append(None)
        self.exits.append(tuple(codes))
        return stopped

    # -- acting as the other nodes ------------------------------------------------------

    def ask(self, publisher, payload, kind):
        """Publish a JSON message and wait for the recorder's reply to it."""
        seen = len(self.statuses)
        publisher.publish(String(data=json.dumps(payload)))
        self.wait(lambda: any(s.get("kind") == kind for s in self.statuses[seen:]), 15, "a reply to " + kind)
        return [s for s in self.statuses[seen:] if s.get("kind") == kind][0]

    def inputs(self, values):
        return self.ask(self.safety, values, "safety_inputs")

    def command(self, lx=0.0, ly=0.0, lz=0.0, ax=0.0, ay=0.0, az=0.0):
        """Publish one Twist. Returns the recorder's reply, after the gate has judged the
        record if there was one."""
        msg = Twist()
        msg.linear.x, msg.linear.y, msg.linear.z = float(lx), float(ly), float(lz)
        msg.angular.x, msg.angular.y, msg.angular.z = float(ax), float(ay), float(az)
        seen, judged = len(self.statuses), len(self.gate_events)
        self.cmd.publish(msg)
        self.wait(lambda: any(s.get("kind") == "command" for s in self.statuses[seen:]), 15, "a reply to a command")
        reply = [s for s in self.statuses[seen:] if s.get("kind") == "command"][0]
        if reply.get("ok"):
            # Wait until the gate has judged this record, accepted or not.
            try:
                self.wait(lambda: any(e.get("n") == reply["n"] or e.get("accepted") is False
                                      for e in self.gate_events[judged:]), 5, "the gate")
            except TimedOut:
                pass
            self.receipt_settled(seen, judged, lambda e: e.get("of") == reply["n"])
            self.feedback_settled(seen, judged, reply["n"])
        self.quiet(0.2)
        return reply

    def receipt_settled(self, seen, judged, mine):
        """Wait until the gate's receipt picked out by `mine` has been written into the
        journal and its record has in turn reached the gate. If it never comes, carry on:
        what the journal then lacks is for the verifier to say."""
        found = lambda: [e for e in self.statuses[seen:] if e.get("kind") == "gate_receipt" and mine(e)]
        try:
            self.wait(lambda: bool(found()), 3, "the gate's receipt")
            if found()[0].get("ok"):
                self.wait(lambda: any(e.get("head", -1) >= found()[0]["n"] for e in self.gate_events[judged:]),
                          3, "the receipt's record to reach the gate")
        except TimedOut:
            pass

    def feedback_settled(self, seen, judged, n):
        """Wait until the feedback for command record `n` has been written into the journal
        and its record has reached the gate. If it never comes, carry on: what the journal
        then lacks is for the verifier to say."""
        found = lambda: [e for e in self.statuses[seen:] if e.get("kind") == "actuator_feedback" and e.get("of") == n]
        try:
            self.wait(lambda: bool(found()), 3, "the actuator's feedback")
            if found()[0].get("ok"):
                self.wait(lambda: any(e.get("head", -1) >= found()[0]["n"] for e in self.gate_events[judged:]),
                          3, "the feedback's record to reach the gate")
        except TimedOut:
            pass

    def gate_head(self):
        """The number and hash of the last record the gate accepted, from its state file."""
        with open(self.gate_state, encoding="utf-8") as fh:
            state = json.load(fh)
        return state["n"], state["hash"]

    def rogue(self, text):
        """Publish straight onto the robot's input. Returns what the gate said."""
        # Heartbeat records reach the gate at any moment, so the event is matched to this
        # exact message and not taken as "the next one".
        judged, mark = len(self.gate_events), hashlib.sha256(text.encode("utf-8")).hexdigest()
        seen = len(self.statuses)
        self.rogue_pub.publish(String(data=text))
        mine = lambda: [e for e in self.gate_events[judged:] if e.get("message_sha256") == mark]
        self.wait(lambda: bool(mine()), 10, "the gate to judge a rogue message")
        # The refusal's receipt goes to the recorder, which writes a record of it.
        self.receipt_settled(seen, judged, lambda e: True)
        return mine()[0]

    def last_command_message(self):
        """The most recent command record the recorder really sent, as it was sent."""
        for text in reversed(self.link):
            message = json.loads(text)
            if message.get("type") == "record" and json.loads(message["record"]).get("kind") == "command":
                return message
        raise TimedOut("no command record seen on cmd_vel_out")

    # -- checks -------------------------------------------------------------------------

    def state_root(self):
        with open(os.path.join(self.data, "logchain.state"), encoding="utf-8") as fh:
            return json.load(fh)["merkle_root"]

    def verify(self, root=None):
        done = subprocess.run(
            [sys.executable, VERIFIER, self.journal, "--root", str(root or self.state_root()),
             "--rulesets", os.path.join(self.data, "rulesets"), "--gate-state", self.gate_state,
             "--public-key", self.public_key, "--gate-public-key", self.gate_public_key,
             "--feedback-public-key", self.feedback_public_key, "--json"],
            capture_output=True, text=True)
        try:
            return done.returncode, json.loads(done.stdout)
        except ValueError:
            return done.returncode, {}

    def verify_text(self, root=None):
        """The verifier's report as a person reads it. Also kept in the scenario's folder."""
        done = subprocess.run(
            [sys.executable, VERIFIER, self.journal, "--root", str(root or self.state_root()),
             "--rulesets", os.path.join(self.data, "rulesets"), "--gate-state", self.gate_state,
             "--public-key", self.public_key, "--gate-public-key", self.gate_public_key,
             "--feedback-public-key", self.feedback_public_key],
            capture_output=True, text=True)
        with open(os.path.join(self.dir, "verifier_output.txt"), "w", encoding="utf-8") as fh:
            fh.write(done.stdout)
        return done.stdout

    def records(self):
        with open(self.journal, encoding="utf-8") as fh:
            return [json.loads(json.loads(line)["raw"]) for line in fh]

    def receipts(self):
        """What the gate's receipts in the journal say, in order: "applied", "blocked",
        "deadman", or "refused:" and the reason. Only receipts the gate really signed."""
        said = []
        for record in self.records():
            if record["kind"] != "gate_receipt":
                continue
            receipt = record["receipt"]
            body = {k: v for k, v in receipt.items() if k != "sig"}
            text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            if not ed.verify(bytes.fromhex(self.gate_public_key), text.encode("utf-8"), bytes.fromhex(receipt["sig"])):
                said.append("not signed by the gate")
            elif receipt["decision"] == "refused":
                said.append("refused:" + receipt["reason"])
            else:
                said.append(receipt["decision"])
        return said

    def feedback(self, field="linear_x_mm_s"):
        """For each command record in the journal, in order: what the feedback signed with
        the feedback key says the wheels did (one field of `measured`), "none" when no such
        feedback names that record by number and hash, or "twice" when more than one does."""
        with open(self.journal, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh]
        records = [json.loads(e["raw"]) for e in entries]
        said = {}
        for record in records:
            if record["kind"] != "actuator_feedback":
                continue
            report = record["feedback"]
            body = {k: v for k, v in report.items() if k != "sig"}
            text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            if not ed.verify(bytes.fromhex(self.feedback_public_key), text.encode("utf-8"), bytes.fromhex(report["sig"])):
                continue
            n = report["n"]
            if 0 <= n < len(entries) and entries[n]["hash"] == report["hash"]:
                said[n] = "twice" if n in said else report["measured"][field]
        return [said.get(r["n"], "none") for r in records if r["kind"] == "command"]

    def recorder_pid(self):
        """The process id of this scenario's recorder node, found by what it is running
        and which journal it was given."""
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open("/proc/%s/cmdline" % name, "rb") as fh:
                    command = fh.read().split(b"\0")[0].decode()
                with open("/proc/%s/environ" % name, "rb") as fh:
                    environ = fh.read().split(b"\0")
            except OSError:
                continue
            if command == self.node_bin and ("SL_DATA_DIR=" + self.data).encode() in environ:
                return int(name)
        raise TimedOut("the recorder node's process was not found")

    def deadman_events(self):
        return [e for e in self.gate_events if e.get("why") == "deadman"]

    def robot_exit_file(self):
        with open(os.path.join(self.dir, "robot.exit"), encoding="utf-8") as fh:
            return json.load(fh)

    def sent(self, field="linear_x_mm_s"):
        if not os.path.exists(self.actuator):
            return []
        with open(self.actuator, encoding="utf-8") as fh:
            return [(a["why"], a["sent"][field]) for a in map(json.loads, fh)]


def kinds(report):
    return sorted({f["finding"] for f in report.get("findings", [])})


def summary(s, stopped, report_pair):
    code, report = report_pair
    return {"recorder_exit": s.exits[-1][0], "robot_exit": s.exits[-1][1], "verifier_exit": code,
            "findings": kinds(report), "stopped_cleanly": bool(stopped.get("ok")), "receipts": s.receipts(),
            "feedback": s.feedback()}


def scenario_1(s):
    s.launch()
    s.inputs(CLEAR)
    s.command(0.2)
    s.command(0.4)
    s.command(0.1, 0.02, 0.003, 0.4, 0.05, 0.006)
    s.quiet(5)
    s.command(0.9)
    s.command(0.3)
    stopped = s.end()
    obs = summary(s, stopped, s.verify(stopped.get("root")))
    counts = s.verify(stopped.get("root"))[1].get("counts", {})
    with open(s.actuator, encoding="utf-8") as fh:
        third = json.loads(fh.readlines()[2])["sent"]
    obs.update(commands=counts.get("commands"), unchanged=counts.get("unchanged"),
               at_least_two_heartbeats=counts.get("heartbeats", 0) >= 2, sent=s.sent(),
               all_six_fields=third)
    return obs


def scenario_2(s):
    s.launch()
    s.inputs(CLEAR)
    replies = [s.command(0.8), s.command(1.8), s.command(-1.8),
               s.command(float("nan")), s.command(0.0, 0.0, 0.0, 0.0, 0.0, float("inf")), s.command(6.0),
               s.command(1.5)]
    stopped = s.end()
    pair = s.verify(stopped.get("root"))
    counts = pair[1].get("counts", {})
    obs = summary(s, stopped, pair)
    with open(s.journal, encoding="utf-8") as fh:
        records = [json.loads(json.loads(line)["raw"]) for line in fh]
    clamped = [r for r in records if r["kind"] == "command" and r["outcome"] == "changed"][0]
    obs.update(replies_ok=[r.get("ok") for r in replies], commands=counts.get("commands"),
               changed=counts.get("changed"), unchanged=counts.get("unchanged"), sent=s.sent(),
               clamped_record_requested=clamped["requested"]["linear_x_mm_s"],
               clamped_record_applied=clamped["applied"]["linear_x_mm_s"],
               clamped_record_rules=clamped["rules_acted"])
    return obs


def scenario_3(s):
    s.launch()
    first = s.command(0.5)  # no safety signal has arrived yet
    s.inputs(CLEAR)
    s.command(0.5)
    s.inputs({"light_curtain_clear": 0})
    s.command(0.5)
    s.inputs(CLEAR)
    s.command(0.5)
    stopped = s.end()
    pair = s.verify(stopped.get("root"))
    obs = summary(s, stopped, pair)
    obs.update(first_outcome=first.get("outcome"), blocked=pair[1].get("counts", {}).get("blocked"), sent=s.sent())
    return obs


def scenario_4(s):
    s.launch()
    s.inputs(CLEAR)
    s.command(0.4)
    declared = s.ask(s.control, {"op": "declare", "target": "ruleset", "file": RULESET_V2,
                                 "operator": "demo-operator-1", "reference": "CHG-0001"}, "declare")
    s.command(1.2)
    s.end()
    # Between the two launches someone changes the installed firmware without telling the recorder.
    with open(os.path.join(s.installed, "software", "robot_safety_fw.bin"), "ab") as fh:
        fh.write(b"patched outside the change process\n")
    s.launch()
    s.inputs(CLEAR)
    s.command(0.9)
    stopped = s.end()
    pair = s.verify(stopped.get("root"))
    counts = pair[1].get("counts", {})
    obs = summary(s, stopped, pair)
    obs.update(declare_ok=declared.get("ok"), declared=counts.get("interventions_declared"),
               detected=counts.get("interventions_detected"), changed=counts.get("changed"),
               exits_first_launch=s.exits[0], sent=s.sent())
    return obs


def scenario_5(s):
    s.launch()
    s.inputs(CLEAR)
    replies = [s.command(0.5), s.command(0.7)]
    # The journal becomes unwritable while the node is running. A real failed write.
    os.chmod(s.journal, stat.S_IREAD)
    try:
        replies += [s.command(0.9), s.command(0.3)]
        stopped = s.end()
    finally:
        os.chmod(s.journal, stat.S_IWRITE | stat.S_IREAD)
    pair = s.verify()
    obs = summary(s, stopped, pair)
    sent = s.sent()
    obs.update(replies_ok=[r.get("ok") for r in replies], commands_recorded=pair[1].get("counts", {}).get("commands"),
               applied=[v for why, v in sent if why == "applied"],
               only_safe_state_after_the_fault=bool(sent[2:]) and sent[2] == ("recorder_fault", 0) and
               all(why in ("recorder_fault", "deadman") and value == 0 for why, value in sent[2:]))

    # The fault is cleared and both processes are started again. More than four seconds
    # pass with no record and no orderly stop, and the verifier says so.
    time.sleep(5)
    s.launch()
    s.inputs(CLEAR)
    again = s.command(0.4)
    stopped = s.end()
    code, report = s.verify(stopped.get("root"))
    obs.update(restart_reply_ok=again.get("ok"), exits_after_restart=s.exits[-1],
               receipts_after_restart=s.receipts(), feedback_after_restart=s.feedback(),
               verifier_exit_after_restart=code, findings_after_restart=kinds(report),
               applied_after_restart=[v for why, v in s.sent() if why == "applied"][len(obs["applied"]):])
    return obs


def scenario_6(s):
    s.launch()
    s.inputs(CLEAR)
    s.command(0.5)
    real = s.last_command_message()
    fast = {f: 0 for f in ("linear_x_mm_s", "linear_y_mm_s", "linear_z_mm_s", "angular_x_mrad_s",
                           "angular_y_mrad_s", "angular_z_mrad_s")}
    fast["linear_x_mm_s"] = 1500

    def refused(event):
        return (event["accepted"], event["why"])

    obs = {}
    # A command with no record at all, the way a node that only knows "publish to the robot" would send it.
    obs["no_record"] = refused(s.rogue(json.dumps({"type": "record", "n": s.gate_head()[0] + 1, "action": fast})))
    obs["not_json"] = refused(s.rogue("linear: {x: 1.5}"))
    # A real record the recorder sent earlier, sent again.
    replay = s.rogue(json.dumps(real))
    obs["replay"] = refused(replay)
    # The replayed record is genuinely signed. It is refused for where it sits in the chain.
    obs["replay_refused_for_its_position"] = "does not extend the chain" in (replay["reason"] or "")
    # The same record with its text changed and its hash left alone.
    tampered = dict(real, record=real["record"].replace('"linear_x_mm_s":500', '"linear_x_mm_s":1500'))
    assert tampered["record"] != real["record"]
    obs["tampered"] = refused(s.rogue(json.dumps(tampered)))
    # A well-formed record with a correct hash, but two ahead of the gate's head: a gap.
    # The rogue cannot sign it, so it is refused before its position is even considered.
    # A gap made of genuinely signed records is the planted bug in tests/test_ros2.py.
    # (Each refusal above put a receipt record in the journal, so the head has moved on.)
    head, head_hash = s.gate_head()
    ahead = json.dumps({"kind": "command", "n": head + 2, "prev": head_hash, "applied": fast,
                        "outcome": "unchanged"}, sort_keys=True, separators=(",", ":"))
    gap = s.rogue(json.dumps({"type": "record", "n": head + 2, "hash": leaf_hash(ahead), "record": ahead}))
    obs["gap"] = refused(gap)
    # After five refusals the recorder's own next command is still accepted.
    after = s.command(0.6)
    stopped = s.end()
    obs.update(summary(s, stopped, s.verify(stopped.get("root"))))
    obs.update(command_after_ok=after.get("ok"), sent=s.sent())
    return obs


def forged_next_record(s, sign):
    """Another node builds the record that would follow the gate's head: the right number,
    the right `prev`, a correct hash, and an action of its own. `sign` decides what it does
    about the signature. Until records were signed, the gate accepted this."""
    s.launch()
    s.inputs(CLEAR)
    s.command(0.5)
    real = s.last_command_message()
    record = json.loads(real["record"])
    # The gate's head is no longer that command: the receipt for it is a record too.
    head, head_hash = s.gate_head()
    record.update(n=head + 1, prev=head_hash)
    for where in (record, record["reported"]):
        where["applied"] = dict(record["requested"], linear_x_mm_s=1500)
    forged = json.dumps(sign(record), sort_keys=True, separators=(",", ":"))
    event = s.rogue(json.dumps({"type": "record", "n": record["n"], "hash": leaf_hash(forged), "record": forged}))
    after = s.command(0.6)  # the real recorder carries on
    stopped = s.end()
    obs = summary(s, stopped, s.verify(stopped.get("root")))
    obs.update(forged=(event["accepted"], event["why"]),
               refused_for_its_signature="not signed by the recorder" in (event["reason"] or ""),
               command_after_ok=after.get("ok"), sent=s.sent())
    return obs


def scenario_7(s):
    # The forger has no key and leaves the real record's signature on the forged one.
    return forged_next_record(s, lambda record: record)


def scenario_8(s):
    # The forger signs properly, with a key of their own.
    return forged_next_record(s, lambda record: ed.sign_record(bytes(range(32)), record))


def scenario_9(s):
    # The forger removes the signature.
    return forged_next_record(s, lambda record: {k: v for k, v in record.items() if k != "sig"})


DEADMAN_SECONDS = 4  # gate_deadman_seconds in ros2/installed/config.json


def scenario_10(s):
    s.launch()
    s.inputs(CLEAR)
    s.command(0.5)
    # The recorder stops dead while the robot is moving at 0.5 m/s: its process is frozen,
    # as a hang or a stalled disk would leave it. No record of any kind can reach the gate.
    pid = s.recorder_pid()
    os.kill(pid, signal.SIGSTOP)
    try:
        s.quiet(10)
    finally:
        os.kill(pid, signal.SIGCONT)
    s.quiet(1)
    trips = s.deadman_events()
    after = s.command(0.3)
    s.quiet(1)
    stopped = s.end()
    obs = summary(s, stopped, s.verify(stopped.get("root")))
    silent = trips[0]["silent_seconds"] if trips else None
    pose_x = s.robot_exit_file()["pose"][0]
    obs.update(sent=s.sent(), deadman_trips=len(trips),
               # Twenty checks a second: the trip comes within a few tenths of the limit.
               tripped_in_time=silent is not None and DEADMAN_SECONDS < silent <= DEADMAN_SECONDS + 0.5,
               # At 0.5 m/s for the whole ten seconds the robot would be past 5 m. Stopped
               # by the deadman it has covered about 2.5 m, then some more at 0.3 m/s.
               robot_stopped_short=pose_x < 4.0,
               command_after_ok=after.get("ok"))
    return obs


def scenario_11(s):
    # The second command's record takes six seconds to reach the disk. Only a test build
    # of the node can be told to do this.
    s.extra_env = {"SL_TEST_SLOW_FLUSH": "command:2:6000"}
    s.launch()
    s.inputs(CLEAR)
    s.command(0.5)
    slow = s.command(0.2)
    s.quiet(1.5)
    stale = [e for e in s.gate_events if e.get("why") == "stale_command"]
    # A fresh command afterwards is carried out as usual.
    after = s.command(0.3)
    stopped = s.end()
    code, report = s.verify(stopped.get("root"))
    obs = summary(s, stopped, (code, report))
    stalls = [f for f in report.get("findings", []) if f["finding"] == "STORAGE_STALL"]
    # The refusal for age, as the journal holds it and as the verifier reports it.
    records = s.records()
    slow_n = slow.get("n")
    slow_hash = leaf_hash(json.dumps(records[slow_n], sort_keys=True, separators=(",", ":"))) if slow_n else None
    in_journal = [r["receipt"] for r in records if r["kind"] == "gate_receipt" and r["receipt"]["reason"] == "age"]
    reported = [f for f in report.get("findings", []) if f["finding"] == "GATE_REFUSED"]
    text = s.verify_text(stopped.get("root"))
    line = [l for l in text.splitlines() if l.strip().startswith("GATE_REFUSED")]
    obs.update(sent=s.sent(), deadman_trips=len(s.deadman_events()), slow_command_ok=slow.get("ok"),
               # The slow command was recorded, and was not carried out: six seconds old
               # against a limit of one.
               stale_refusals=len(stale),
               stale_command_was_the_slow_one=bool(stale) and stale[0].get("n") == slow.get("n")
               and "ms old" in (stale[0].get("reason") or ""),
               command_after_ok=after.get("ok"),
               stalls_stated=report.get("counts", {}).get("storage_stalls"),
               stall_is_of_the_slow_record=bool(stalls) and stalls[0]["of_record"] == slow.get("n")
               and stalls[0]["n"] == slow.get("n") + 1,
               stated_duration_fits=bool(stalls) and 6000 <= stalls[0]["stalled_ms"] < 9000,
               # The journal holds a receipt, signed by the gate, that names the slow
               # record by number and hash and says it was refused for its age.
               age_refusal_in_journal=len(in_journal) == 1 and in_journal[0]["decision"] == "refused"
               and in_journal[0]["n"] == slow_n and in_journal[0]["hash"] == slow_hash
               and "ms old" in (in_journal[0]["detail"] or ""),
               verifier_reports_the_age_refusal=len(reported) == 1 and reported[0]["reason"] == "age"
               and reported[0]["of_record"] == slow_n,
               verifier_output_shows_it=len(line) == 1 and 'reason="age"' in line[0]
               and "of_record=%s" % slow_n in line[0] and "ms old" in line[0],
               the_record_itself_is_unchanged=slow_n is not None and records[slow_n]["kind"] == "command"
               and records[slow_n]["outcome"] == "unchanged")
    return obs


def scenario_12(s):
    s.launch()
    s.inputs(CLEAR)
    s.command(0.5)
    # The folder the anchor statements go to stops being writable. The journal is fine.
    anchors = os.path.join(s.data, "anchors")
    os.chmod(anchors, stat.S_IREAD | stat.S_IEXEC)
    try:
        replies = [s.command(0.1 * k) for k in (2, 3, 4, 5, 6)]
        s.quiet(1)
    finally:
        os.chmod(anchors, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    stopped = s.end()
    code, report = s.verify(stopped.get("root"))
    obs = summary(s, stopped, (code, report))
    with open(s.journal, encoding="utf-8") as fh:
        records = [json.loads(json.loads(line)["raw"]) for line in fh]
    failed = [r for r in records if r["kind"] == "anchor_failed"]
    obs.update(replies_ok=[r.get("ok") for r in replies], sent=s.sent(),
               anchor_failures_stated=len(failed) >= 1,
               each_names_a_statement_that_is_missing=bool(failed) and all(
                   not os.path.exists(os.path.join(anchors, "%08d.json" % r["entry_count"])) for r in failed),
               each_is_signed=bool(failed) and all(len(r.get("sig", "")) == 128 for r in failed),
               status_also_said_so=any(m.get("kind") == "anchor" and m.get("ok") is False for m in s.statuses))
    return obs


def scenario_13(s):
    # The wheels ignore every action. The gate does its job and the robot does not move.
    s.extra_env = {"SL_TEST_STUCK_WHEELS": "1"}
    s.launch()
    s.inputs(CLEAR)
    s.command(0.5)
    s.quiet(1)
    s.command(0.3)
    s.quiet(1)
    stopped = s.end()
    obs = summary(s, stopped, s.verify(stopped.get("root")))
    obs.update(sent=s.sent(), robot_did_not_move=s.robot_exit_file()["pose"] == [0.0, 0.0, 0.0],
               reports_published=s.robot_exit_file().get("feedback_reports"))
    return obs


SCENARIOS = {1: scenario_1, 2: scenario_2, 3: scenario_3, 4: scenario_4, 5: scenario_5, 6: scenario_6,
             7: scenario_7, 8: scenario_8, 9: scenario_9, 10: scenario_10, 11: scenario_11, 12: scenario_12,
             13: scenario_13}
NEEDS_SLOW_FLUSH_NODE = (11,)
CLEAN = {"recorder_exit": 0, "robot_exit": 0, "verifier_exit": 0, "findings": [], "stopped_cleanly": True}
REFUSED = (False, "gate_refused")
# Every scenario also says which receipts the journal must hold, in order, and for each
# command record what the feedback signed with the feedback key says the wheels did.
EXPECTED = {
    1: dict(CLEAN, receipts=["applied"] * 5, feedback=[200, 400, 100, 900, 300],
            commands=5, unchanged=5, at_least_two_heartbeats=True,
            sent=[("applied", 200), ("applied", 400), ("applied", 100), ("applied", 900), ("applied", 300)],
            all_six_fields={"linear_x_mm_s": 100, "linear_y_mm_s": 20, "linear_z_mm_s": 3,
                            "angular_x_mrad_s": 400, "angular_y_mrad_s": 50, "angular_z_mrad_s": 6}),
    2: dict(CLEAN, receipts=["applied"] * 4, feedback=[800, 1500, -1500, 1500],
            replies_ok=[True, True, True, False, False, False, True], commands=4, changed=2, unchanged=2,
            sent=[("applied", 800), ("applied", 1500), ("applied", -1500), ("applied", 1500)],
            clamped_record_requested=1800, clamped_record_applied=1500, clamped_record_rules=["R2-forward-speed"]),
    3: dict(CLEAN, receipts=["blocked", "applied", "blocked", "applied"], feedback=[0, 500, 0, 500],
            first_outcome="blocked", blocked=2,
            sent=[("blocked", 0), ("applied", 500), ("blocked", 0), ("applied", 500)]),
    4: dict(CLEAN, receipts=["applied"] * 3, feedback=[400, 1000, 900],
            declare_ok=True, declared=1, detected=1, changed=1, exits_first_launch=(0, 0),
            sent=[("applied", 400), ("applied", 1000), ("applied", 900)]),
    5: dict(CLEAN, receipts=["applied"] * 2, receipts_after_restart=["applied"] * 3,
            feedback=[500, 700], feedback_after_restart=[500, 700, 400],
            recorder_exit=3, stopped_cleanly=False, replies_ok=[True, True, False, False],
            commands_recorded=2, applied=[500, 700], only_safe_state_after_the_fault=True,
            restart_reply_ok=True, exits_after_restart=(0, 0), verifier_exit_after_restart=2,
            findings_after_restart=["HEARTBEAT_GAP"], applied_after_restart=[400]),
    # Five refusals: the verifier now reports each one, with the reason the gate gave.
    6: dict(CLEAN, robot_exit=2, verifier_exit=2, findings=["GATE_REFUSED"],
            receipts=["applied", "refused:form", "refused:form", "refused:chain", "refused:form",
                      "refused:signature", "applied"],
            feedback=[500, 600], no_record=REFUSED, not_json=REFUSED, replay=REFUSED, tampered=REFUSED,
            gap=REFUSED, replay_refused_for_its_position=True, command_after_ok=True,
            sent=[("applied", 500)] + [("gate_refused", 0)] * 5 + [("applied", 600)]),
}
# A forged next record, three ways. In each: refused for its signature, the robot never
# moves at the forger's 1500, the recorder's own next command still goes through, and the
# journal is whole. The journal also says the gate refused something, and why.
FORGERY_REFUSED = dict(CLEAN, robot_exit=2, verifier_exit=2, findings=["GATE_REFUSED"],
                       receipts=["applied", "refused:signature", "applied"], feedback=[500, 600],
                       forged=REFUSED, refused_for_its_signature=True, command_after_ok=True,
                       sent=[("applied", 500), ("gate_refused", 0), ("applied", 600)])
EXPECTED.update({7: FORGERY_REFUSED, 8: FORGERY_REFUSED, 9: FORGERY_REFUSED})
# The recorder silent for ten seconds: the robot is stopped by the deadman, and the gap is
# in the journal as a gap, because nothing the recorder wrote explains it. The deadman
# trip is in the journal too, as the gate's receipt, written once the recorder is back.
EXPECTED[10] = dict(CLEAN, verifier_exit=2, findings=["GATE_DEADMAN", "HEARTBEAT_GAP"],
                    receipts=["applied", "deadman", "applied"], feedback=[500, 300], deadman_trips=1,
                    tripped_in_time=True,
                    robot_stopped_short=True, command_after_ok=True,
                    sent=[("applied", 500), ("deadman", 0), ("applied", 300)])
# A six-second flush: the robot is stopped by the deadman at four seconds and stays
# stopped, because the command whose record then lands is six seconds old and the gate
# refuses to carry it out. The journal says what happened. Still a finding, still exit 2.
# The robot exits 2 because its gate refused something, which is the expected result here.
# The journal also holds the gate's receipts for the deadman trip and for the refusal.
EXPECTED[11] = dict(CLEAN, robot_exit=2, verifier_exit=2,
                    findings=["GATE_DEADMAN", "GATE_REFUSED", "STORAGE_STALL"],
                    receipts=["applied", "deadman", "refused:age", "applied"], feedback=[500, 0, 300],
                    age_refusal_in_journal=True, verifier_reports_the_age_refusal=True,
                    verifier_output_shows_it=True, the_record_itself_is_unchanged=True, deadman_trips=1,
                    slow_command_ok=True, stale_refusals=1, stale_command_was_the_slow_one=True,
                    command_after_ok=True, stalls_stated=1, stall_is_of_the_slow_record=True,
                    stated_duration_fits=True,
                    sent=[("applied", 500), ("deadman", 0), ("stale_command", 0), ("applied", 300)])
# Anchor statements cannot be written: not a fault, every command goes out, and the
# journal carries a signed record of each statement lost. The verifier reports them.
EXPECTED[12] = dict(CLEAN, verifier_exit=2, findings=["ANCHOR_FAILED"], receipts=["applied"] * 6,
                    feedback=[500, 200, 300, 400, 500, 600],
                    replies_ok=[True] * 5,
                    anchor_failures_stated=True, each_names_a_statement_that_is_missing=True, each_is_signed=True,
                    status_also_said_so=True,
                    sent=[("applied", 500), ("applied", 200), ("applied", 300), ("applied", 400), ("applied", 500),
                          ("applied", 600)])
# The wheels do not turn. The journal is clean, because nothing in it is false: the gate
# applied both commands, as its receipts say, and the wheels did not move, as the feedback
# says. The verifier checks the feedback is genuine and belongs to its command; whether the
# robot did what it was told is there to read, and the verifier does not judge it.
EXPECTED[13] = dict(CLEAN, receipts=["applied"] * 2, feedback=[0, 0], robot_did_not_move=True,
                    reports_published=2, sent=[("applied", 500), ("applied", 300)])


def run_scenario(number, node_bin, out):
    session = Session(out, "ros_scenario_%d" % number, node_bin)
    try:
        return SCENARIOS[number](session)
    except TimedOut as exc:
        return {"error": str(exc)}
    finally:
        if session.proc is not None and session.proc.poll() is None:
            os.killpg(session.proc.pid, signal.SIGINT)
            try:
                session.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(session.proc.pid, signal.SIGKILL)


def default_out():
    """A RAM-backed folder where there is one, so that the pass/fail result does not depend
    on how fast the disk flushes. For tests only."""
    if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
        return "/dev/shm/sentinel-ledger-tests-%d/ros_out" % os.getuid(), True
    return os.path.join(HERE, "out"), False


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the ROS 2 scenarios and judge them by exit code.")
    ap.add_argument("--node", required=True, help="path to the sentinel_recorder_node binary")
    ap.add_argument("--slow-flush-node", help="the node built with --features test-slow-flush, for scenario 11")
    ap.add_argument("--out", help="where scenario files are written (default: a RAM-backed folder, tests only)")
    ap.add_argument("--only", type=int, choices=sorted(SCENARIOS), help="run one scenario")
    ap.add_argument("--json", action="store_true", help="print the observations as JSON and nothing else")
    args = ap.parse_args(argv)
    node_bin = os.path.abspath(args.node)
    if not os.path.exists(node_bin):
        print("error: no node binary at %s" % node_bin, file=sys.stderr)
        return 1

    # Every line of the result also goes to results.txt in the output folder, and the
    # observations to results.json, written as each scenario ends. Whatever is done with
    # this program's output afterwards, what each scenario showed is still on disk.
    slow_bin = os.path.abspath(args.slow_flush_node) if args.slow_flush_node else None
    if slow_bin and not os.path.exists(slow_bin):
        print("error: no node binary at %s" % slow_bin, file=sys.stderr)
        return 1
    out, in_ram = (os.path.abspath(args.out), False) if args.out else default_out()
    os.makedirs(out, exist_ok=True)
    kept = open(os.path.join(out, "results.txt"), "w", encoding="utf-8")

    def say(line):
        kept.write(line + "\n")
        kept.flush()
        if not args.json:
            print(line, flush=True)

    say("scenario folders: %s%s" % (out, " (RAM-backed: for tests only, never for a real journal)" if in_ram else ""))
    rclpy.init()
    numbers = [args.only] if args.only else sorted(SCENARIOS)
    failed, skipped, everything = 0, 0, {}
    for number in numbers:
        if number in NEEDS_SLOW_FLUSH_NODE and not slow_bin:
            skipped += 1
            say("ROS scenario %d: NOT RUN, it needs --slow-flush-node" % number)
            continue
        observed = run_scenario(number, slow_bin if number in NEEDS_SLOW_FLUSH_NODE else node_bin, out)
        everything[number] = observed
        wrong = {k: v for k, v in EXPECTED[number].items() if json.dumps(observed.get(k), sort_keys=True) != json.dumps(v, sort_keys=True)}
        if "error" in observed:
            wrong["error"] = None
        failed += bool(wrong)
        say("ROS scenario %d: %s" % (number, "as expected" if not wrong else "NOT AS EXPECTED"))
        for key, value in observed.items():
            say("  %s%-34s %s" % ("! " if key in wrong else "  ", key, json.dumps(value)))
            if key in wrong and wrong[key] is not None:
                say("    %-34s %s" % ("expected", json.dumps(wrong[key])))
        for key in wrong:
            if key not in observed:
                say("  ! %-34s (not observed)" % key)
                if wrong[key] is not None:
                    say("    %-34s %s" % ("expected", json.dumps(wrong[key])))
        with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as fh:
            json.dump({"scenarios": everything, "not_as_expected": failed, "run": len(everything),
                       "planned": len(numbers), "folder": out, "ram_backed": in_ram}, fh, indent=1, sort_keys=True)
    rclpy.shutdown()
    ran = len(numbers) - skipped
    say("%d of %d ROS scenario(s) as expected%s" % (ran - failed, ran, ", %d not run" % skipped if skipped else ""))
    kept.close()
    if args.json:
        print(json.dumps(everything))
    # A scenario asked for by number and not run is not a pass.
    return 0 if not failed and not (skipped and args.only) else 2


if __name__ == "__main__":
    sys.exit(main())
