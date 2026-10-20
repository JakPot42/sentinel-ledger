"""Start the recorder node and the simulated robot together, as two processes.

    SL_WORKDIR=/some/dir SL_NODE_BIN=/path/to/sentinel_recorder_node \
        ros2 launch ros2/launch/sentinel.launch.py

SL_WORKDIR must hold `installed/` (config.json, ruleset.json, software/) and the recorder's
private key at `recorder_private/recorder.key`. The journal goes to `data/`, the robot's
gate state and action log to `robot_side/`. The robot is given the public key from the
configuration and never sees the private one. It is also given the deadman time and the limit on
a command's age from the configuration (`gate_deadman_seconds`, `gate_max_command_age_ms`),
when they are there. When the configuration names a `gate_public_key`, the robot is given
the gate's own signing key, `robot_private/gate.key`, and signs receipts with it; the
recorder never sees that file. When it names a `feedback_public_key`, the robot is given
the feedback key, `robot_private/feedback.key`, and signs what its wheels did after each
command with it, keeping the number of its next report in `robot_side/feedback.state`.
Each process also writes its exit code to a file there, because a launch does not hand
them back. The processes are named `recorder` and `robot`, so that launch's own log line
for each exit (`[recorder-1]: process has died [pid ..., exit code -11, ...]`) says which
it was: a process can write 0 to its file and still crash after that.
"""
import json
import os
import sys

from launch import LaunchDescription
from launch.actions import ExecuteProcess


def generate_launch_description():
    work = os.environ["SL_WORKDIR"]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    robot_side = os.path.join(work, "robot_side")
    os.makedirs(robot_side, exist_ok=True)
    with open(os.path.join(work, "installed", "config.json"), encoding="utf-8") as fh:
        # The robot's own copy of the safe state and of the recorder's public key, fixed
        # when it is started. It does not take either from the recorder at run time.
        config = json.load(fh)
        safe_state = json.dumps(config["safe_state_action"])
    recorder = ExecuteProcess(
        name="recorder",
        cmd=[os.environ["SL_NODE_BIN"]],
        additional_env={"SL_DATA_DIR": os.path.join(work, "data"),
                        "SL_INSTALLED": os.path.join(work, "installed"),
                        "SL_KEY_FILE": os.path.join(work, "recorder_private", "recorder.key"),
                        "SL_EXIT_FILE": os.path.join(work, "recorder.exit")},
        output="screen")
    deadman = ["--deadman-seconds", str(config["gate_deadman_seconds"])] if "gate_deadman_seconds" in config else []
    if "gate_max_command_age_ms" in config:
        deadman += ["--max-command-age-ms", str(config["gate_max_command_age_ms"])]
    if "gate_public_key" in config:
        deadman += ["--gate-key", os.path.join(work, "robot_private", "gate.key")]
    if "feedback_public_key" in config:
        deadman += ["--feedback-key", os.path.join(work, "robot_private", "feedback.key"),
                    "--feedback-state", os.path.join(robot_side, "feedback.state")]
    robot = ExecuteProcess(
        name="robot",
        cmd=[sys.executable, os.path.join(here, "sim_robot.py"),
             "--state", os.path.join(robot_side, "gate.state"),
             "--actuator", os.path.join(robot_side, "actuator.jsonl"),
             "--safe-state", safe_state,
             "--public-key", config["recorder_public_key"],
             "--exit-file", os.path.join(work, "robot.exit")] + deadman,
        output="screen")
    return LaunchDescription([recorder, robot])
