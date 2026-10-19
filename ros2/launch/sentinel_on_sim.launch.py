"""Start the recorder node, the gate bridge and a robot simulation, as separate processes.

    SL_WORKDIR=/some/dir SL_NODE_BIN=/path/to/sentinel_recorder_node \
    SL_SIM_COMMAND="ros2 launch turtlebot3_gazebo empty_world.launch.py" \
        ros2 launch ros2/launch/sentinel_on_sim.launch.py

The recorder and its working directory are exactly as in sentinel.launch.py. In place of
the simulated robot there is ros2/sim_bridge.py, the same gate in front of the robot in
the simulation, and the simulation itself, started from SL_SIM_COMMAND (split as a shell
would, but not run through one). Optional: SL_SIM_CMD_TOPIC (default /cmd_vel),
SL_SIM_CMD_TYPE (twist or twist_stamped, default twist), SL_SIM_ODOM_TOPIC (default /odom).

When the bridge exits, which it does when the run is over, everything is shut down,
the simulation included.
"""
import json
import os
import shlex
import sys

from launch import LaunchDescription
from launch.actions import EmitEvent, ExecuteProcess, RegisterEventHandler
from launch.event_handlers import OnProcessExit
from launch.events import Shutdown


def generate_launch_description():
    work = os.environ["SL_WORKDIR"]
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    robot_side = os.path.join(work, "robot_side")
    os.makedirs(robot_side, exist_ok=True)
    with open(os.path.join(work, "installed", "config.json"), encoding="utf-8") as fh:
        config = json.load(fh)
        safe_state = json.dumps(config["safe_state_action"])
    recorder = ExecuteProcess(
        cmd=[os.environ["SL_NODE_BIN"]],
        additional_env={"SL_DATA_DIR": os.path.join(work, "data"),
                        "SL_INSTALLED": os.path.join(work, "installed"),
                        "SL_KEY_FILE": os.path.join(work, "recorder_private", "recorder.key"),
                        "SL_EXIT_FILE": os.path.join(work, "recorder.exit")},
        output="screen")
    gate = ["--deadman-seconds", str(config["gate_deadman_seconds"])] if "gate_deadman_seconds" in config else []
    if "gate_max_command_age_ms" in config:
        gate += ["--max-command-age-ms", str(config["gate_max_command_age_ms"])]
    if "gate_public_key" in config:
        gate += ["--gate-key", os.path.join(work, "robot_private", "gate.key")]
    if "feedback_public_key" in config:
        gate += ["--feedback-key", os.path.join(work, "robot_private", "feedback.key"),
                 "--feedback-state", os.path.join(robot_side, "feedback.state")]
    bridge = ExecuteProcess(
        cmd=[sys.executable, os.path.join(here, "sim_bridge.py"),
             "--state", os.path.join(robot_side, "gate.state"),
             "--actuator", os.path.join(robot_side, "actuator.jsonl"),
             "--safe-state", safe_state,
             "--public-key", config["recorder_public_key"],
             "--exit-file", os.path.join(work, "robot.exit"),
             "--cmd-topic", os.environ.get("SL_SIM_CMD_TOPIC", "/cmd_vel"),
             "--cmd-type", os.environ.get("SL_SIM_CMD_TYPE", "twist"),
             "--odom-topic", os.environ.get("SL_SIM_ODOM_TOPIC", "/odom")] + gate,
        output="screen")
    simulation = ExecuteProcess(cmd=shlex.split(os.environ["SL_SIM_COMMAND"]), output="screen")
    when_done = RegisterEventHandler(OnProcessExit(target_action=bridge, on_exit=[EmitEvent(event=Shutdown())]))
    return LaunchDescription([simulation, recorder, bridge, when_done])
