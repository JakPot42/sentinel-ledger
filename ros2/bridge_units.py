"""Units between a record and a ROS 2 robot, for ros2/sim_bridge.py. No ROS imports, so
the conversions can be tested anywhere.

A record carries whole numbers: millimetres per second and milliradians per second, under
six keys (SPEC 7.3). A robot's command topic carries metres and radians per second as
floats, and its odometry reports the same, with a pose as a position and a quaternion.
"""
import math

FIELDS = ("linear_x_mm_s", "linear_y_mm_s", "linear_z_mm_s", "angular_x_mrad_s", "angular_y_mrad_s",
          "angular_z_mrad_s")


def action_to_twist(action):
    """The six velocities of a record's action, in metres and radians per second, in the
    order linear x, y, z, angular x, y, z. A key the action lacks is zero."""
    return tuple(int(action.get(f, 0)) / 1000.0 for f in FIELDS)


def twist_to_measured(linear, angular):
    """What a robot's odometry says it is doing, as a record's six whole numbers. `linear`
    and `angular` are (x, y, z) in metres and radians per second."""
    values = tuple(linear) + tuple(angular)
    return {f: int(round(v * 1000)) for f, v in zip(FIELDS, values)}


def yaw_of(x, y, z, w):
    """The heading, in radians, of a unit quaternion: the rotation about the vertical axis."""
    return math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))


def pose_state(px, py, qx, qy, qz, qw):
    """Where odometry puts the robot, in millimetres and milliradians, as the feedback's
    `state` (SPEC 4.6)."""
    return {"x_mm": int(round(px * 1000)), "y_mm": int(round(py * 1000)),
            "heading_mrad": int(round(yaw_of(qx, qy, qz, qw) * 1000))}


def reading_due(clock, wall_now, sim_now, acted, read_after, cap):
    """Whether the odometry reading for the action in force is due. `acted` is when the
    action took effect: (wall-clock seconds, simulated seconds or None).

    clock "wall": once the action has been in force for `read_after` seconds of wall time.
    clock "sim": once the simulation's clock has advanced `read_after` seconds since then,
    or after `cap` seconds of wall time, whichever comes first, so a simulation that is
    paused or stalled is still read. Where there is no simulated time (no /clock seen, now
    or when the action took effect), as "wall"."""
    acted_wall, acted_sim = acted
    waited = wall_now - acted_wall
    if clock == "sim" and sim_now is not None and acted_sim is not None:
        return sim_now - acted_sim >= read_after or waited >= cap
    return waited >= read_after
