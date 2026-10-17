#!/usr/bin/env python3
"""A minimal simulated robot with the gate inside it. docs/SPEC.md section 15.

    sim_robot.py --state FILE --actuator FILE --safe-state JSON --public-key HEX
                 [--deadman-seconds N] [--max-command-age-ms N] [--gate-key FILE]
                 [--feedback-key FILE --feedback-state FILE] [--exit-file FILE]

It has one command input, the topic cmd_vel_out, and that input goes straight into the
gate (gate/actuator_gate.py, the same code the file demo uses). The robot moves only on
an action the gate hands it. It has no plain Twist input. There is nothing for another
node to publish to that would move it without a record signed by the recorder. The robot
holds the recorder's public key and no private key.

Topics:
  cmd_vel_out    std_msgs/String  in   what the recorder node publishes: records, or a safe-state message
  robot_control  std_msgs/String  in   {"op":"shutdown"}, used by the demo to end a run
  gate_events    std_msgs/String  out  one JSON line per message judged
  gate_receipts  std_msgs/String  out  the gate's signed receipts, for the recorder to write down
  actuator_feedback  std_msgs/String  out  signed reports of what the wheels did after each command

The "robot" is a point with a pose. Twenty times a second it moves by its current
velocity. Headless, so a run can be judged by exit code.

Deadman: with --deadman-seconds, the same twenty-times-a-second step asks the gate whether
a valid record has arrived in that time. If not, the robot takes the safe state and stays
in it until the recorder's next accepted command. Without this the robot would go on at
its last commanded velocity for as long as the recorder stayed silent. This robot is one
thread, so anything slow on its own side delays that check; in a real controller the
deadman belongs on a timer of its own.

Command age: with --max-command-age-ms, a command received by the recorder longer ago than
that is not carried out when it arrives, and the robot takes the safe state. Its record
still counts as the next in the chain. The age is the robot's wall clock less the
recorder's, so on two machines it is only as good as their clocks agree.

Receipts: with --gate-key, the gate signs a receipt for every command record it takes
into the chain (applied, blocked, or refused for its age), for every message it refuses,
and for every deadman trip, and the robot publishes it on gate_receipts. The recorder
node writes each one into the journal. The robot acts first and signs afterwards. The
key is the gate's own; the robot still holds no key that can sign a record.

Feedback (docs/SPEC.md section 4.6): with --feedback-key, after acting on each command
record the gate took into the chain, the robot reads what its wheels are doing and where
odometry puts it, signs that with the feedback key and publishes it on actuator_feedback
for the recorder to write down. The reading is taken on the first motion step at least one
step after the action, or at once if anything else is about to be sent to the wheels
first, so that it never describes a later action. In that case it is read before the new
action and signed after it, so a stop never waits for a signature or a disk. `measured` is
the wheels' velocity, under the same six keys as the action; `state` is the pose from
odometry, in millimetres and milliradians.

SL_TEST_STUCK_WHEELS=1 makes the wheels ignore every action: the robot is told to move and
does not. For the scenario that shows the journal then says so; nothing else uses it.

Exit codes: 0 the gate refused nothing, 2 it refused at least one message.
"""
import argparse
import hashlib
import json
import math
import os
import sys
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gate"))
# SL_GATE_DIR lets a test put a deliberately broken gate, or a broken feedback reporter, in
# the robot (tests/test_ros2.py). Whatever that folder does not hold comes from gate/.
if os.environ.get("SL_GATE_DIR"):
    sys.path.insert(0, os.environ["SL_GATE_DIR"])
from actuator_gate import Gate, load_gate_key  # noqa: E402
from actuator_feedback import FeedbackReporter, load_feedback_key  # noqa: E402

LATCHED = QoSProfile(history=HistoryPolicy.KEEP_LAST, depth=1000, reliability=ReliabilityPolicy.RELIABLE,
                     durability=DurabilityPolicy.TRANSIENT_LOCAL)
FIELDS = ("linear_x_mm_s", "linear_y_mm_s", "linear_z_mm_s", "angular_x_mrad_s", "angular_y_mrad_s",
          "angular_z_mrad_s")
STEP = 0.05


class SimRobot(Node):
    def __init__(self, args):
        super().__init__("sim_robot")
        self.gate = Gate(args.state, json.loads(args.safe_state), args.public_key, args.deadman_seconds,
                         args.max_command_age_ms, load_gate_key(args.gate_key) if args.gate_key else None)
        self.deadman_trips = 0
        self.reporter = None
        if args.feedback_key:
            self.reporter = FeedbackReporter(args.feedback_state, load_feedback_key(args.feedback_key))
        self.reported = 0
        self.stuck = os.environ.get("SL_TEST_STUCK_WHEELS") == "1"
        self.actuator_path = args.actuator
        self.velocity = dict.fromkeys(FIELDS, 0)
        self.pose = [0.0, 0.0, 0.0]  # x in metres, y in metres, heading in radians
        self.accepted = self.refused = self.judged = 0
        self.done = False
        self.events = self.create_publisher(String, "gate_events", LATCHED)
        self.receipts = self.create_publisher(String, "gate_receipts", LATCHED)
        self.feedback = self.create_publisher(String, "actuator_feedback", LATCHED)
        self.create_subscription(String, "cmd_vel_out", self.on_message, LATCHED)
        self.create_subscription(String, "robot_control", self.on_control, 10)
        self.create_timer(STEP, self.move)

    def on_message(self, msg):
        try:
            message = json.loads(msg.data)
        except ValueError:
            message = {}
        decision = self.gate.handle(message, now=time.monotonic(), wall_ms=int(time.time() * 1000))
        self.judged += 1
        if decision["reason"]:
            self.refused += 1
        elif decision["n"] is not None:
            self.accepted += 1
        # Act first, then sign and write things down: neither the signature nor a slow
        # disk on the robot's side may delay a stop.
        self.act(decision)
        if self.reporter is not None:
            self.reporter.follow(decision, time.monotonic())
        receipt = self.gate.issue_receipt(decision, wall_ms=int(time.time() * 1000))
        self.gate.save()
        event = {"judged": self.judged, "accepted": decision["accepted"], "n": decision["n"],
                 "why": decision["why"], "reason": decision["reason"], "head": self.gate.state["n"],
                 "message_sha256": hashlib.sha256(msg.data.encode("utf-8")).hexdigest()}
        self.events.publish(String(data=json.dumps(event, sort_keys=True)))
        self.send_receipt(receipt)

    def send_receipt(self, receipt):
        if receipt is not None:
            self.receipts.publish(String(data=json.dumps(receipt, sort_keys=True, separators=(",", ":"))))

    def wheels(self):
        """What the wheels are doing: the velocity they were given, unless they are stuck."""
        return dict.fromkeys(FIELDS, 0) if self.stuck else dict(self.velocity)

    def read_wheels(self):
        """The reading due, if one is: the wheels, the pose, and when. None otherwise."""
        if self.reporter is None or not self.reporter.due():
            return None
        pose = {"x_mm": int(round(self.pose[0] * 1000)), "y_mm": int(round(self.pose[1] * 1000)),
                "heading_mrad": int(round(self.pose[2] * 1000))}
        return self.wheels(), pose, time.monotonic(), int(time.time() * 1000)

    def send_feedback(self, reading):
        """Sign a reading taken by read_wheels, keep the reporter's number, publish it."""
        if reading is None:
            return
        measured, pose, now, wall_ms = reading
        report = self.reporter.report(measured, pose, now=now, wall_ms=wall_ms)
        self.reported += 1
        self.feedback.publish(String(data=json.dumps(report, sort_keys=True, separators=(",", ":"))))

    def act(self, decision):
        if decision["send"] is not None:
            # A reading still due describes the action now ending. Its numbers are taken
            # before the wheels are given anything else, or they would describe the wrong
            # command. It is signed and written down after: like a receipt, it must not
            # delay the action, which may be a stop.
            reading = self.read_wheels()
            # This is the only place the robot's velocity is ever set.
            self.velocity = {f: int(decision["send"].get(f, 0)) for f in FIELDS}
            with open(self.actuator_path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps({"n": decision["n"], "sent": decision["send"], "why": decision["why"]},
                                    sort_keys=True, separators=(",", ":")) + "\n")
            self.send_feedback(reading)

    def on_control(self, msg):
        if "shutdown" in msg.data:
            self.done = True

    def move(self):
        tripped = self.gate.check_deadman(time.monotonic())
        if tripped:
            self.deadman_trips += 1
            self.act(tripped)
            receipt = self.gate.issue_receipt(tripped, wall_ms=int(time.time() * 1000))
            self.gate.save()
            self.events.publish(String(data=json.dumps(
                {"accepted": None, "n": None, "why": "deadman", "reason": None, "head": self.gate.state["n"],
                 "silent_seconds": tripped["silent_seconds"], "pose": [round(p, 3) for p in self.pose]},
                sort_keys=True)))
            self.send_receipt(receipt)
        wheels = self.wheels()
        vx, vy = wheels["linear_x_mm_s"] / 1000.0, wheels["linear_y_mm_s"] / 1000.0
        heading = self.pose[2]
        self.pose[0] += (vx * math.cos(heading) - vy * math.sin(heading)) * STEP
        self.pose[1] += (vx * math.sin(heading) + vy * math.cos(heading)) * STEP
        self.pose[2] += wheels["angular_z_mrad_s"] / 1000.0 * STEP
        # The reading for the last command, once its action has been in force for a step.
        if self.reporter is not None and self.reporter.due(time.monotonic(), STEP):
            self.send_feedback(self.read_wheels())


def main(argv=None):
    ap = argparse.ArgumentParser(description="Simulated robot with the Sentinel Ledger gate inside it.")
    ap.add_argument("--state", required=True, help="where the gate keeps the last accepted number and hash")
    ap.add_argument("--actuator", required=True, help="a log of every action the robot acted on")
    ap.add_argument("--safe-state", required=True, help="the safe-state action, as JSON, set on the robot's side")
    ap.add_argument("--public-key", required=True, help="the recorder's Ed25519 public key, 64 hex characters")
    ap.add_argument("--deadman-seconds", type=int, help="no valid record for this long means the safe state")
    ap.add_argument("--max-command-age-ms", type=int, help="a command older than this is not carried out")
    ap.add_argument("--gate-key", help="the gate's own signing key file; with it the gate signs receipts")
    ap.add_argument("--feedback-key", help="the feedback key file; with it the robot signs what its wheels did")
    ap.add_argument("--feedback-state", help="where the feedback reporter keeps the number of its next report")
    ap.add_argument("--exit-file", help="the exit code is also written here, for a launcher")
    args, _ = ap.parse_known_args(argv)
    if bool(args.feedback_key) != bool(args.feedback_state):
        ap.error("--feedback-key and --feedback-state go together")

    rclpy.init()
    robot = SimRobot(args)
    try:
        while rclpy.ok() and not robot.done:
            rclpy.spin_once(robot, timeout_sec=0.1)
    except KeyboardInterrupt:
        pass
    code = 2 if robot.refused else 0
    if args.exit_file:
        with open(args.exit_file, "w", encoding="utf-8") as fh:
            json.dump({"exit": code, "accepted": robot.accepted, "refused": robot.refused,
                       "deadman_trips": robot.deadman_trips, "feedback_reports": robot.reported,
                       "pose": [round(p, 3) for p in robot.pose]}, fh)
    robot.destroy_node()
    if rclpy.ok():
        rclpy.shutdown()
    return code


if __name__ == "__main__":
    sys.exit(main())
