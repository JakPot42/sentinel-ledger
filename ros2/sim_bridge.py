#!/usr/bin/env python3
"""The gate in front of a real ROS 2 robot simulation: a robot maker's own model.

    sim_bridge.py [the options of ros2/sim_robot.py]
                  [--cmd-topic /cmd_vel] [--cmd-type twist|twist_stamped] [--odom-topic /odom]
                  [--read-after 1.0] [--read-clock wall|sim] [--read-cap 5.0]

ros2/sim_robot.py is a point with a pose and the gate inside it. This is the same gate,
the same receipts and the same feedback reporter, standing between the recorder and a
simulated robot that someone else built (Gazebo, Webots or any simulator that takes
velocity commands on a topic and publishes odometry). Only two things change:

- What the gate passes on goes to the robot's own command topic, twenty times a second
  for as long as it is in force, as a controller expects; zero before the gate has passed
  anything, and the safe state after a stop.
- What the wheels did is read from the robot's own odometry, not from a velocity this
  program set itself. The feedback report (SPEC 4.6) then says what the simulation
  measured: `measured` from the odometry's twist, `state` from its pose. The reading is
  taken once the action has been in force for `--read-after` seconds (default 1.0, where
  the simulated robot of sim_robot.py reads after one 50 ms step, since a real base takes
  time to respond), or at once if the gate passes on another action first.

When the reading is due. With `--read-clock wall` (the default) those seconds are wall-clock
seconds. A simulation can run slower than real time, and then one wall second is less than
a second of the robot's own time, so the reading can come before the robot has finished
responding. With `--read-clock sim` they are seconds of the simulation's own clock, from
/clock (rosgraph_msgs/Clock): the reading is due once /clock has advanced `--read-after`
seconds since the action took effect, or after `--read-cap` seconds of wall time (default
5.0) if it has not, so a paused or stalled simulation is still read. Where no /clock has
been seen, the wall clock decides. Either way the deadman and the limit on a command's age
stay on the wall clock: they watch the link to the recorder, which runs in real time. The
feedback report is unchanged (SPEC 4.6): its `after_ms` is wall-clock time.

What this does not do. The robot's command topic is an ordinary topic, so any node can
publish to it and move the robot without a record (SPEC 15.7): this bridge does not
sit inside the robot. It shows the journal, the receipts and the feedback on the maker's
model, nothing more. Odometry is the simulation's word, as feedback is the controller's.

Topics, besides those of ros2/sim_robot.py:
  --cmd-topic   geometry_msgs/Twist or TwistStamped  out  what the gate passed on
  --odom-topic  nav_msgs/Odometry                    in   what the robot measured
  /clock        rosgraph_msgs/Clock                  in   the simulation's time (--read-clock sim)
"""
import json
import os
import sys
import time

from geometry_msgs.msg import Twist, TwistStamped
from nav_msgs.msg import Odometry
from rosgraph_msgs.msg import Clock
from std_msgs.msg import String

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bridge_units  # noqa: E402
import sim_robot  # noqa: E402
from sim_robot import STEP, SimRobot  # noqa: E402


class SimBridge(SimRobot):
    def __init__(self, args):
        self.odometry = None             # the latest (linear, angular, pose) from the robot
        self.odometry_count = 0
        self.sim_now = None              # the simulation's time from /clock, in seconds
        self.acted_at = (time.monotonic(), None)   # when the action in force took effect: (wall, sim)
        super().__init__(args)
        self.read_after = max(STEP, args.read_after)
        self.read_clock, self.read_cap = args.read_clock, args.read_cap
        if self.read_clock == "sim":
            self.create_subscription(Clock, "/clock", self.on_clock, 10)
        self.stamped = args.cmd_type == "twist_stamped"
        self.out = self.create_publisher(TwistStamped if self.stamped else Twist, args.cmd_topic, 10)
        self.create_subscription(Odometry, args.odom_topic, self.on_odometry, 10)

    def on_odometry(self, msg):
        t, p = msg.twist.twist, msg.pose.pose
        self.odometry = ((t.linear.x, t.linear.y, t.linear.z), (t.angular.x, t.angular.y, t.angular.z),
                         (p.position.x, p.position.y, p.orientation.x, p.orientation.y, p.orientation.z,
                          p.orientation.w))
        self.odometry_count += 1
        state = bridge_units.pose_state(*self.odometry[2])
        self.pose = [state["x_mm"] / 1000.0, state["y_mm"] / 1000.0, state["heading_mrad"] / 1000.0]

    def on_clock(self, msg):
        self.sim_now = msg.clock.sec + msg.clock.nanosec / 1e9

    def act(self, decision):
        if decision["send"] is not None:
            self.acted_at = (time.monotonic(), self.sim_now)
        super().act(decision)

    def wheels(self):
        """What the robot's odometry says it is doing, or None before any has arrived."""
        if self.odometry is None:
            return None
        return bridge_units.twist_to_measured(*self.odometry[:2])

    def read_wheels(self):
        if self.reporter is None or not self.reporter.due():
            return None
        if self.odometry is None:
            # Nothing measured yet. The report says so rather than inventing a number.
            return None, {"odometry_messages": 0}, time.monotonic(), int(time.time() * 1000)
        return (self.wheels(), bridge_units.pose_state(*self.odometry[2]), time.monotonic(),
                int(time.time() * 1000))

    def publish_action(self):
        linear_x, linear_y, linear_z, angular_x, angular_y, angular_z = bridge_units.action_to_twist(self.velocity)
        twist = Twist()
        twist.linear.x, twist.linear.y, twist.linear.z = linear_x, linear_y, linear_z
        twist.angular.x, twist.angular.y, twist.angular.z = angular_x, angular_y, angular_z
        if self.stamped:
            msg = TwistStamped()
            msg.header.stamp = self.get_clock().now().to_msg()
            msg.twist = twist
            self.out.publish(msg)
        else:
            self.out.publish(twist)

    def move(self):
        """Twenty times a second: the deadman, then the action in force to the robot, then
        the reading due, if one is."""
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
        # self.velocity is set in one place only, SimRobot.act, from what the gate passed on.
        self.publish_action()
        # The reading is taken once the action has been in force for --read-after seconds,
        # on the clock --read-clock names, so the robot has had time to respond; or at once,
        # before the gate passes on anything else (SimRobot.act). Either way it describes
        # this action (SPEC 4.6).
        if self.reporter is not None and self.reporter.due() and bridge_units.reading_due(
                self.read_clock, time.monotonic(), self.sim_now, self.acted_at, self.read_after, self.read_cap):
            self.send_feedback(self.read_wheels())


def main(argv=None):
    ap = sim_robot.make_parser("The Sentinel Ledger gate in front of a ROS 2 robot simulation.")
    ap.add_argument("--cmd-topic", default="/cmd_vel", help="the robot's velocity command topic")
    ap.add_argument("--cmd-type", choices=("twist", "twist_stamped"), default="twist",
                    help="geometry_msgs/Twist or TwistStamped on that topic")
    ap.add_argument("--odom-topic", default="/odom", help="the robot's nav_msgs/Odometry topic")
    ap.add_argument("--read-after", type=float, default=1.0,
                    help="seconds an action is in force before its feedback reading is taken (default 1.0); "
                         "a new action before then takes the reading at once")
    ap.add_argument("--read-clock", choices=("wall", "sim"), default="wall",
                    help="time --read-after on the wall clock (default) or on the simulation's /clock")
    ap.add_argument("--read-cap", type=float, default=5.0,
                    help="with --read-clock sim: wall-clock seconds after which the reading is taken anyway "
                         "(default 5.0)")
    args, _ = ap.parse_known_args(argv)
    return sim_robot.run(SimBridge, ap, args)


if __name__ == "__main__":
    sys.exit(main())
