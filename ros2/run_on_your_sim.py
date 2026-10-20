#!/usr/bin/env python3
"""A signed log on your simulation: run Sentinel Ledger in front of a ROS 2 robot
simulation, drive it through a short script, and keep the signed journal and the
verifier's report.

    . /opt/ros/lyrical/setup.sh
    python3 ros2/run_on_your_sim.py --node /path/to/sentinel_recorder_node \
        --sim "ros2 launch ros2/examples/turtlebot3_headless.launch.py" --env TURTLEBOT3_MODEL=burger \
        [--cmd-topic /cmd_vel] [--cmd-type twist|twist_stamped] [--odom-topic /odom] \
        [--speed 0.2] [--turn 0.5] [--settle 3] [--read-clock sim|wall] [--out DIR]

What runs (ros2/launch/sentinel_on_sim.launch.py): your simulation, started by the
command given with --sim; the recorder node, as everywhere else in this repository; and
ros2/sim_bridge.py, the gate, between the recorder and your robot's command topic. This
program plays the controller. Once your robot publishes odometry it waits --settle
seconds (default 3), since a simulator can publish odometry before it takes commands, and
then sends five velocity commands to the recorder: forward, turn, forward with the light
curtain interrupted (the ruleset blocks it, so the robot is given its safe state),
forward more slowly, stop. Each command becomes a signed record, the gate checks each
record before your robot is given anything, signs a receipt for what it did, and after
each command reads your robot's odometry and signs that as the actuator's feedback. All
of it goes into the journal. If the simulation publishes /clock, the bridge waits for one
second of the simulation's own time before each reading (--read-clock sim, the default
here; at most five seconds of wall time), and SUMMARY.md says how fast simulated time ran
against the wall clock and how much of it passed before each reading. When the run is
over, anything of the simulation's still running is stopped.

What you get, in the run's folder (printed at the end):
  data/logchain.journal   the journal: every record, numbered, chained and signed
  verifier_output.txt     the verifier's report on it, as a person reads it
  verifier_output.json    the same, as data
  journal.syslog          the journal exported as RFC 5424 syslog (docs/EXPORT.md)
  export_check.txt        the offline checker's report on that export
  SUMMARY.md              what was asked for, what the gate did, what odometry measured

What it does not show. The bridge sits in front of your robot's command topic, not inside
your robot: any node can still publish to that topic and move the robot with no record
(SPEC 15.7). The feedback is what your simulation's odometry reports, and the verifier
does not judge whether the robot did what it was told (SPEC 4.6). One run, one script.

Exit codes: 0 the run finished and the verifier found nothing; 2 it finished with a
finding, or the recorder or the bridge exited with an error or crashed (how each process
really ended is read from launch's log, not from the exit file it writes); 1 it could not
run.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time

import rclpy
from nav_msgs.msg import Odometry
from rosgraph_msgs.msg import Clock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_ros_scenarios as base  # noqa: E402
from run_ros_scenarios import CLEAR, TimedOut, describe_exit, kinds  # noqa: E402

REPO = os.path.dirname(HERE)
LAUNCH = os.path.join(HERE, "launch", "sentinel_on_sim.launch.py")
EXPORTER = os.path.join(REPO, "export", "export_journal.py")
CHECKER = os.path.join(REPO, "export", "check_export.py")
INTERRUPTED = {"light_curtain_clear": 0}


class SimSession(base.Session):
    """A session whose robot is someone else's simulation, behind ros2/sim_bridge.py."""

    def __init__(self, out, name, node_bin, sim_command, cmd_topic, cmd_type, odom_topic, env, start_timeout,
                 settle=3.0, read_clock="sim"):
        super().__init__(out, name, node_bin)
        self.launch_file = LAUNCH
        self.robot_process = "bridge"
        self.odom_topic, self.start_timeout, self.settle = odom_topic, start_timeout, settle
        self.left_running = False
        self.extra_env = dict(env, SL_SIM_COMMAND=sim_command, SL_SIM_CMD_TOPIC=cmd_topic,
                              SL_SIM_CMD_TYPE=cmd_type, SL_SIM_ODOM_TOPIC=odom_topic,
                              SL_SIM_READ_CLOCK=read_clock)

    def launch(self):
        started = super().launch()
        self.odometry, self.clock = [], []
        self.node.create_subscription(Odometry, self.odom_topic, self.odometry.append, 10)
        # The simulation's own clock, if it publishes one, against the wall clock: how fast
        # simulated time ran while the commands were sent, and how much of it passed before
        # each reading. Each sample: (monotonic, wall clock, simulated), in seconds.
        self.node.create_subscription(
            Clock, "/clock", lambda m: self.clock.append(
                (time.monotonic(), time.time(), m.clock.sec + m.clock.nanosec / 1e9)), 10)
        # A simulator can take a minute or more to load a world; nothing is commanded before
        # the robot is publishing odometry.
        self.wait(lambda: len(self.odometry) >= 1, self.start_timeout, "odometry on " + self.odom_topic)
        # The first odometry can come before the simulation is ready to take commands: on a
        # TurtleBot3 in Gazebo the first command once reached the wheels 0.8 s late. Wait.
        self.quiet(self.settle)
        return started

    def end(self):
        """As Session.end, then stop anything of the simulation's that outlived its launch
        (Gazebo can take longer to stop than launch waits). Everything started here is in
        one process group."""
        stopped = super().end()
        if group_alive(self.proc.pid):
            self.left_running = True
            os.killpg(self.proc.pid, signal.SIGINT)
            deadline = time.monotonic() + 20
            while group_alive(self.proc.pid) and time.monotonic() < deadline:
                time.sleep(0.5)
            if group_alive(self.proc.pid):
                os.killpg(self.proc.pid, signal.SIGKILL)
        return stopped

    def real_time_factor(self, since):
        """Simulated seconds per wall second from `since` (time.monotonic()) until now, from
        /clock; None if the simulation published no clock in that time."""
        seen = [c for c in self.clock if c[0] >= since]
        if len(seen) < 2 or seen[-1][0] - seen[0][0] <= 0:
            return None
        return (seen[-1][2] - seen[0][2]) / (seen[-1][0] - seen[0][0])

    def sim_at(self, wall):
        """The simulation's time at wall-clock time `wall` (seconds since the epoch), from the
        /clock samples either side of it; None outside them."""
        before = [c for c in self.clock if c[1] <= wall]
        after = [c for c in self.clock if c[1] >= wall]
        if not before or not after:
            return None
        (_, w0, s0), (_, w1, s1) = before[-1], after[0]
        return s0 if w1 == w0 else s0 + (s1 - s0) * (wall - w0) / (w1 - w0)


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def script(s, speed, turn):
    """The five commands. Returns (what was asked, the recorder's reply) for each."""
    asked = []
    s.inputs(CLEAR)
    for label, twist, inputs, settle in (
            ("forward", (speed, 0.0), None, 3.0),
            ("turn on the spot", (0.0, turn), None, 3.0),
            ("forward, light curtain interrupted", (speed, 0.0), INTERRUPTED, 2.0),
            ("forward, more slowly", (speed / 2, 0.0), CLEAR, 3.0),
            ("stop", (0.0, 0.0), None, 2.0)):
        if inputs is not None:
            s.inputs(inputs)
        reply = s.command(twist[0], az=twist[1])
        asked.append((label, twist, reply))
        s.quiet(settle)
    return asked


def rows(s):
    """For each command record: what was requested and applied, the gate's receipt, and
    the feedback. Read from the journal, which the verifier has checked."""
    records = s.records()
    # A deadman receipt names the last record the gate accepted, not a decision about it.
    receipts = {r["receipt"].get("n"): r["receipt"] for r in records
                if r["kind"] == "gate_receipt" and r["receipt"].get("n") is not None
                and r["receipt"].get("decision") != "deadman"}
    feedback = {r["feedback"]["n"]: r["feedback"] for r in records if r["kind"] == "actuator_feedback"}
    out = []
    for r in records:
        if r["kind"] != "command":
            continue
        receipt, report = receipts.get(r["n"], {}), feedback.get(r["n"], {})
        measured = report.get("measured") or {}
        sim_after = None
        if report.get("at_ms") is not None and report.get("after_ms") is not None:
            acted = s.sim_at((report["at_ms"] - report["after_ms"]) / 1000.0)
            read = s.sim_at(report["at_ms"] / 1000.0)
            if acted is not None and read is not None:
                sim_after = read - acted
        out.append({"n": r["n"], "requested": (r["requested"].get("linear_x_mm_s"), r["requested"].get("angular_z_mrad_s")),
                    "outcome": r["outcome"],
                    "receipt": receipt.get("decision", "none") + (":" + receipt["reason"] if receipt.get("reason") else ""),
                    "sent": (report.get("sent", {}).get("linear_x_mm_s"), report.get("sent", {}).get("angular_z_mrad_s")),
                    "measured": (measured.get("linear_x_mm_s"), measured.get("angular_z_mrad_s")),
                    "after_ms": report.get("after_ms"), "sim_after": sim_after})
    return out


def export_and_check(s, root):
    syslog = os.path.join(s.dir, "journal.syslog")
    done = subprocess.run([sys.executable, EXPORTER, s.journal, "--format", "syslog", "--out", syslog],
                          capture_output=True, text=True)
    checked = subprocess.run([sys.executable, CHECKER, syslog, "--root", root] + s.keys(),
                             capture_output=True, text=True)
    with open(os.path.join(s.dir, "export_check.txt"), "w", encoding="utf-8") as fh:
        fh.write(done.stderr + checked.stdout + checked.stderr)
    return checked.returncode


def write_summary(s, args, table, verified, exits, export_code, rtf=None, exit_files=(None, None)):
    code, report = verified
    if rtf is None:
        pace = ("The simulation published no /clock, so how fast its time ran was not measured, and "
                "the bridge timed each odometry reading on the wall clock.")
    elif args.read_clock == "sim":
        pace = ("While the commands were sent, simulated time ran at %.2f of real time (from /clock). "
                "The bridge took each odometry reading once /clock had advanced 1 s since the action, "
                "or after 5 s of wall time if it had not." % rtf)
    else:
        pace = ("While the commands were sent, simulated time ran at %.2f of real time (from /clock). "
                "The bridge timed its odometry reading on the wall clock (--read-clock wall), so its "
                "1 s wait was about %.2f s of simulated time." % (rtf, rtf))
    lines = ["# A signed log on a simulated robot", "",
             "Simulation: `%s`" % args.sim, "",
             "Command topic `%s` (%s), odometry `%s`." % (args.cmd_topic, args.cmd_type, args.odom_topic), "",
             pace, "",
             "| record | asked for (mm/s, mrad/s) | the record's outcome | the gate's receipt "
             "| the robot was given | odometry measured, and how long after |",
             "|---|---|---|---|---|---|"]
    for row in table:
        after = "%s ms" % row["after_ms"]
        if row["sim_after"] is not None:
            after += " (%.2f s simulated)" % row["sim_after"]
        lines.append("| %d | %s | %s | %s | %s | %s, %s |" % (
            row["n"], row["requested"], row["outcome"], row["receipt"], row["sent"], row["measured"], after))
    lines += ["",
              "Recorder exit %s, bridge exit %s (0: the gate refused nothing)."
              % (describe_exit(exits[0], exit_files[0]), describe_exit(exits[1], exit_files[1])),
              "Verifier exit %s, findings: %s." % (code, ", ".join(kinds(report)) or "none"),
              "Export checked offline: exit %s." % export_code, "",
              "The verifier checks that every record, receipt and feedback report is genuine and in "
              "its place. It does not judge whether the robot did what it was told: compare the last "
              "two columns yourself. The bridge sits in front of the robot's command topic, not inside "
              "the robot, so a node that publishes to that topic directly is not in this journal.", ""]
    with open(os.path.join(s.dir, "SUMMARY.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run Sentinel Ledger in front of a ROS 2 robot simulation.")
    ap.add_argument("--node", required=True, help="the sentinel_recorder_node binary")
    ap.add_argument("--sim", required=True, help="the command that starts your simulation, for example "
                    "\"ros2 launch turtlebot3_gazebo empty_world.launch.py\"")
    ap.add_argument("--cmd-topic", default="/cmd_vel")
    ap.add_argument("--cmd-type", choices=("twist", "twist_stamped"), default="twist")
    ap.add_argument("--odom-topic", default="/odom")
    ap.add_argument("--env", action="append", default=[], metavar="NAME=VALUE",
                    help="an environment variable your simulation needs; may be given more than once")
    ap.add_argument("--speed", type=float, default=0.2, help="forward speed for the script, m/s")
    ap.add_argument("--turn", type=float, default=0.5, help="turn rate for the script, rad/s")
    ap.add_argument("--start-timeout", type=float, default=180, help="seconds to wait for the first odometry")
    ap.add_argument("--settle", type=float, default=3.0,
                    help="seconds to wait after the first odometry before the first command (default 3)")
    ap.add_argument("--read-clock", choices=("sim", "wall"), default="sim",
                    help="time the wait before each odometry reading on the simulation's /clock where it "
                         "publishes one (sim, the default) or on the wall clock (wall)")
    ap.add_argument("--out", default=os.path.join(HERE, "out", "your_sim"))
    args = ap.parse_args(argv)
    env = {}
    for item in args.env:
        if "=" not in item:
            ap.error("--env takes NAME=VALUE")
        name, value = item.split("=", 1)
        env[name] = value

    rclpy.init()
    s = SimSession(os.path.abspath(args.out), "run", os.path.abspath(args.node), args.sim, args.cmd_topic,
                   args.cmd_type, args.odom_topic, env, args.start_timeout, args.settle, args.read_clock)
    try:
        s.launch()
        began = time.monotonic()
        script(s, args.speed, args.turn)
        rtf = s.real_time_factor(began)
        stopped = s.end()
    except TimedOut as exc:
        print("could not run: %s. The launch log is in %s" % (exc, s.dir), file=sys.stderr)
        if s.proc is not None and s.proc.poll() is None:
            os.killpg(s.proc.pid, signal.SIGINT)
        return 1
    finally:
        if rclpy.ok():
            rclpy.shutdown()
    root = stopped.get("root") or s.state_root()
    verified = s.verify(root)
    with open(os.path.join(s.dir, "verifier_output.json"), "w", encoding="utf-8") as fh:
        json.dump(verified[1], fh, indent=1, sort_keys=True)
    s.verify_text(root)
    export_code = export_and_check(s, root)
    text = write_summary(s, args, rows(s), verified, s.exits[-1], export_code, rtf, s.exit_files[-1])
    print(text)
    if s.left_running:
        print("The simulation was still running after its launch ended; it has been stopped.")
    print("Everything is in %s" % s.dir)
    clean = s.exits[-1] == (0, 0) and verified[0] == 0 and export_code == 0
    return 0 if clean else 2


if __name__ == "__main__":
    sys.exit(main())
