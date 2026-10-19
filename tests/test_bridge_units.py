"""The unit conversions between a record and a ROS 2 robot (ros2/bridge_units.py), used by
ros2/sim_bridge.py. No ROS needed: these run everywhere. The bridge itself runs in
tests/test_ros2.py, against a stand-in simulation."""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ros2"))
import bridge_units as bu  # noqa: E402


def test_an_action_becomes_metres_and_radians_per_second_in_twist_order():
    action = {"linear_x_mm_s": 200, "linear_y_mm_s": -50, "linear_z_mm_s": 0, "angular_x_mrad_s": 0,
              "angular_y_mrad_s": 0, "angular_z_mrad_s": 500}
    assert bu.action_to_twist(action) == (0.2, -0.05, 0.0, 0.0, 0.0, 0.5)


def test_a_key_the_action_lacks_is_zero():
    assert bu.action_to_twist({"linear_x_mm_s": 150}) == (0.15, 0.0, 0.0, 0.0, 0.0, 0.0)
    assert bu.action_to_twist({}) == (0.0,) * 6


def test_odometry_becomes_the_records_six_whole_numbers():
    measured = bu.twist_to_measured((0.19996, 0.0, 0.0), (0.0, 0.0, -0.4999))
    assert measured == {"linear_x_mm_s": 200, "linear_y_mm_s": 0, "linear_z_mm_s": 0, "angular_x_mrad_s": 0,
                        "angular_y_mrad_s": 0, "angular_z_mrad_s": -500}
    assert all(type(v) is int for v in measured.values())
    assert sorted(measured) == sorted(bu.FIELDS)


def test_the_round_trip_keeps_the_numbers():
    action = dict(zip(bu.FIELDS, (220, 0, 0, 0, 0, -2840)))
    twist = bu.action_to_twist(action)
    assert bu.twist_to_measured(twist[:3], twist[3:]) == action


def test_the_heading_of_a_quaternion():
    for heading in (0.0, 0.5, -1.2, math.pi / 2, 3.0):
        q = (0.0, 0.0, math.sin(heading / 2), math.cos(heading / 2))
        assert abs(bu.yaw_of(*q) - heading) < 1e-9
    assert bu.pose_state(1.2345, -0.5, 0.0, 0.0, math.sin(0.25), math.cos(0.25)) == \
        {"x_mm": 1234, "y_mm": -500, "heading_mrad": 500}
