#!/usr/bin/env python3
"""A stand-in for a robot simulation, for tests only: a two-wheeled base with no physics.

    stand_in_sim.py [--cmd-topic /cmd_vel] [--cmd-type twist|twist_stamped] [--odom-topic /odom]
                    [--lag 0.2] [--timeout 0.5] [--stuck] [--leave-behind FILE] [--clock-rate R] [--paused]

It takes velocity commands on a topic and publishes nav_msgs/Odometry twenty times a
second, as Gazebo with a diff drive plugin, or a ros2_control diff_drive_controller, would.
Its speed follows the command with a first-order lag (`--lag` seconds), so what odometry
reports after a step is not exactly what was sent. With no command for `--timeout`
seconds it stops, as diff_drive_controller does after `cmd_vel_timeout`. `--stuck` makes
it ignore every command. `--leave-behind FILE` starts a child process that ignores SIGINT
and SIGTERM and writes its pid to FILE, as a simulator's server can outlive the launch that
started it; the runner must still leave nothing running. Its odometry is stamped with the
time. `--clock-rate R` gives it a clock of its own that runs at R times real time, as a
simulation slower than real time has; its odometry is then stamped with that clock, as
Gazebo stamps odometry with simulated time, and its speed follows the command over
simulated time. `--paused` is a simulation that publishes odometry while its time stands
still: every stamp the same, and nothing moves.

It exists so that ros2/sim_bridge.py and ros2/run_on_your_sim.py can be tested on any
machine with ROS 2, without a simulator installed. It is not a simulation of anyone's robot.
"""
import argparse
import math
import subprocess
import sys
import time

import rclpy
from geometry_msgs.msg import Twist, TwistStamped
from nav_msgs.msg import Odometry
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node

STEP = 0.05


class StandIn(Node):
    def __init__(self, args):
        super().__init__("stand_in_sim")
        self.lag, self.timeout, self.stuck = args.lag, args.timeout, args.stuck
        self.target = (0.0, 0.0)            # forward speed (m/s), turn rate (rad/s)
        self.speed = [0.0, 0.0]
        self.pose = [0.0, 0.0, 0.0]
        self.last_command = None
        kind = TwistStamped if args.cmd_type == "twist_stamped" else Twist
        self.create_subscription(kind, args.cmd_topic, self.on_command, 10)
        self.odom = self.create_publisher(Odometry, args.odom_topic, 10)
        # With --clock-rate, each 50 ms step of wall time is clock_rate * 50 ms of simulated
        # time, counted from 1000 s so that no stamp is ever zero.
        self.clock_rate, self.paused = args.clock_rate, args.paused
        self.sim_time = 1000.0
        self.create_timer(STEP, self.step)

    def on_command(self, msg):
        twist = msg.twist if isinstance(msg, TwistStamped) else msg
        self.target = (twist.linear.x, twist.angular.z)
        self.last_command = time.monotonic()

    def step(self):
        target = self.target
        if self.stuck or self.last_command is None or time.monotonic() - self.last_command > self.timeout:
            target = (0.0, 0.0)
        dt = 0.0 if self.paused else STEP * self.clock_rate if self.clock_rate else STEP
        k = 0.0 if dt <= 0 else 1.0 if self.lag <= 0 else min(1.0, dt / self.lag)
        self.speed = [s + (t - s) * k for s, t in zip(self.speed, target)]
        heading = self.pose[2]
        self.pose[0] += self.speed[0] * math.cos(heading) * dt
        self.pose[1] += self.speed[0] * math.sin(heading) * dt
        self.pose[2] += self.speed[1] * dt
        msg = Odometry()
        if self.clock_rate or self.paused:
            self.sim_time += dt
            msg.header.stamp.sec = int(self.sim_time)
            msg.header.stamp.nanosec = int(round((self.sim_time - int(self.sim_time)) * 1e9)) % 1000000000
        else:
            msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id, msg.child_frame_id = "odom", "base_link"
        msg.pose.pose.position.x, msg.pose.pose.position.y = self.pose[0], self.pose[1]
        msg.pose.pose.orientation.z = math.sin(self.pose[2] / 2)
        msg.pose.pose.orientation.w = math.cos(self.pose[2] / 2)
        msg.twist.twist.linear.x, msg.twist.twist.angular.z = self.speed[0], self.speed[1]
        self.odom.publish(msg)


def main(argv=None):
    ap = argparse.ArgumentParser(description="A stand-in robot simulation, for tests only.")
    ap.add_argument("--cmd-topic", default="/cmd_vel")
    ap.add_argument("--cmd-type", choices=("twist", "twist_stamped"), default="twist")
    ap.add_argument("--odom-topic", default="/odom")
    ap.add_argument("--lag", type=float, default=0.2)
    ap.add_argument("--timeout", type=float, default=0.5)
    ap.add_argument("--stuck", action="store_true")
    ap.add_argument("--leave-behind", metavar="FILE")
    ap.add_argument("--clock-rate", type=float, default=0.0, metavar="R")
    ap.add_argument("--paused", action="store_true")
    args, _ = ap.parse_known_args(argv)
    if args.leave_behind:
        child = subprocess.Popen([sys.executable, "-c", "import signal, time; "
                                  "signal.signal(signal.SIGINT, signal.SIG_IGN); "
                                  "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(args.leave_behind, "w", encoding="utf-8") as fh:
            fh.write("%d\n" % child.pid)
    rclpy.init()
    node = StandIn(args)
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    node.destroy_node()
    if rclpy.ok():
        rclpy.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
