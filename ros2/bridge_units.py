"""Units between a record and a ROS 2 robot, for ros2/sim_bridge.py, and the timing the
bridge and ros2/run_on_your_sim.py read from odometry's stamps. No ROS imports, so all of
it can be tested anywhere.

A record carries whole numbers: millimetres per second and milliradians per second, under
six keys (SPEC 7.3). A robot's command topic carries metres and radians per second as
floats, and its odometry reports the same, with a pose as a position and a quaternion.
A simulation stamps its odometry with its own time, which can run slower than the wall
clock.
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


def stamp_seconds(sec, nanosec):
    """The time in a message's header stamp, in seconds; None for a stamp left at zero, as
    a publisher that does not stamp its messages leaves it."""
    if sec == 0 and nanosec == 0:
        return None
    return sec + nanosec / 1e9


def reading_due(clock, wall_now, stamp_now, acted, read_after, cap):
    """Whether the odometry reading for the action in force is due. `stamp_now` is the stamp
    of the latest odometry, in seconds, or None. `acted` is when the action took effect:
    (wall-clock seconds, the stamp of the latest odometry then, or None).

    clock "wall": once the action has been in force for `read_after` seconds of wall time.
    clock "stamp": once the odometry's stamps have advanced `read_after` seconds since then,
    or after `cap` seconds of wall time, whichever comes first, so a simulation that is
    paused or stalled is still read. A simulation stamps its odometry with its own time, so
    this waits for `read_after` seconds of the robot's time. Where there is no stamp (none
    yet, or stamps left at zero, now or when the action took effect), as "wall"."""
    acted_wall, acted_stamp = acted
    waited = wall_now - acted_wall
    if clock == "stamp" and stamp_now is not None and acted_stamp is not None:
        return stamp_now - acted_stamp >= read_after or waited >= cap
    return waited >= read_after


def steady(samples, now, window, max_gap=0.5, tolerance=0.25):
    """Whether odometry has been arriving steadily, with its stamps advancing at a steady
    rate, for the last `window` seconds of wall time up to `now`. `samples` are
    (arrival, stamp) pairs in the order they arrived: arrival on the wall clock (monotonic
    seconds), stamp in seconds or None.

    Steady means all of: odometry was already arriving before the window began; no gap of
    more than `max_gap` seconds between arrivals in it, or since the last; and the stamps
    advanced at a rate above zero in both halves of the window, the two rates within
    `tolerance` of the larger. A slow rate is steady if it holds. Where the stamps in the
    window are all None (unstamped odometry), arriving steadily is all there is to see, and
    that is enough."""
    start = now - window
    before = [s for s in samples if s[0] < start]
    recent = [s for s in samples if s[0] >= start]
    if not before or not recent:
        return False
    arrivals = [before[-1][0]] + [s[0] for s in recent] + [now]
    if max(b - a for a, b in zip(arrivals, arrivals[1:])) > max_gap:
        return False
    stamps = [s[1] for s in recent]
    if all(st is None for st in stamps):
        return True
    if any(st is None for st in stamps):
        return False
    middle = start + window / 2
    rates = []
    for half in ([s for s in recent if s[0] < middle], [s for s in recent if s[0] >= middle]):
        if len(half) < 2 or half[-1][0] <= half[0][0]:
            return False
        rates.append((half[-1][1] - half[0][1]) / (half[-1][0] - half[0][0]))
    if min(rates) <= 0:
        return False
    return abs(rates[0] - rates[1]) <= tolerance * max(rates)
