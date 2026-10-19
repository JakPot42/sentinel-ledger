"""A TurtleBot3 in Gazebo's empty world with no window: an example simulation for
ros2/run_on_your_sim.py.

    export TURTLEBOT3_MODEL=burger
    ros2 launch ros2/examples/turtlebot3_headless.launch.py

It needs the turtlebot3_gazebo and ros_gz packages (on ROS 2 Lyrical:
ros-lyrical-turtlebot3-gazebo, ros-lyrical-ros-gz). turtlebot3_gazebo's own
empty_world.launch.py always opens Gazebo's window; this starts the same world, the same
robot and the same topic bridge without it. It includes ROBOTIS's own launch files for the
robot (spawn_turtlebot3.launch.py, robot_state_publisher.launch.py) rather than copying
them.

The Burger's lidar is a GPU lidar, so even with no window the simulator must render:
`--headless-rendering` renders off screen. Where there is no usable GPU (WSL 2 without
one, a server), set LIBGL_ALWAYS_SOFTWARE=1 to render on the CPU; the simulation then
runs slower than real time, and ros2/run_on_your_sim.py reports by how much.

Topics, as turtlebot3_gazebo bridges them: /cmd_vel (geometry_msgs/TwistStamped) in,
/odom (nav_msgs/Odometry) and /clock out.
"""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import AppendEnvironmentVariable, IncludeLaunchDescription
from launch.launch_description_sources import PythonLaunchDescriptionSource


def generate_launch_description():
    tb3 = get_package_share_directory("turtlebot3_gazebo")
    ros_gz_sim = get_package_share_directory("ros_gz_sim")
    world = os.path.join(tb3, "worlds", "empty_world.world")
    server = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(os.path.join(ros_gz_sim, "launch", "gz_sim.launch.py")),
        launch_arguments={"gz_args": "-r -s --headless-rendering -v2 " + world,
                          "on_exit_shutdown": "true"}.items())
    robot = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(os.path.join(tb3, "launch", "spawn_turtlebot3.launch.py")),
        launch_arguments={"x_pose": "0.0", "y_pose": "0.0"}.items())
    state = IncludeLaunchDescription(
        PythonLaunchDescriptionSource(os.path.join(tb3, "launch", "robot_state_publisher.launch.py")),
        launch_arguments={"use_sim_time": "true"}.items())
    models = AppendEnvironmentVariable("GZ_SIM_RESOURCE_PATH", os.path.join(tb3, "models"))
    return LaunchDescription([models, server, robot, state])
