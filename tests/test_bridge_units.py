"""The unit conversions between a record and a ROS 2 robot, and the timing read from
odometry's stamps (ros2/bridge_units.py), used by ros2/sim_bridge.py and
ros2/run_on_your_sim.py. No ROS needed: these run everywhere. The bridge and the runner
themselves run in tests/test_ros2.py, against a stand-in simulation."""
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


def test_a_reading_on_the_wall_clock_waits_for_wall_time_only():
    assert not bu.reading_due("wall", 100.9, 50.0, (100.0, 40.0), 1.0, 5.0)
    assert bu.reading_due("wall", 101.0, 40.1, (100.0, 40.0), 1.0, 5.0)


def test_a_reading_on_the_stamps_waits_for_the_robots_own_time():
    # The simulation runs at half speed: one wall second is half a second of its stamps.
    assert not bu.reading_due("stamp", 101.0, 40.5, (100.0, 40.0), 1.0, 5.0)
    assert not bu.reading_due("stamp", 101.9, 40.95, (100.0, 40.0), 1.0, 5.0)
    assert bu.reading_due("stamp", 102.0, 41.0, (100.0, 40.0), 1.0, 5.0)


def test_a_simulation_that_stalls_is_read_after_the_wall_clock_cap():
    assert not bu.reading_due("stamp", 104.9, 40.2, (100.0, 40.0), 1.0, 5.0)
    assert bu.reading_due("stamp", 105.0, 40.2, (100.0, 40.0), 1.0, 5.0)
    # Stamps that go backwards (a reset simulation) wait for the cap too.
    assert not bu.reading_due("stamp", 104.0, 3.0, (100.0, 40.0), 1.0, 5.0)


def test_with_no_stamp_the_wall_clock_decides():
    # No odometry yet, or stamps left at zero, now or when the action took effect.
    assert bu.reading_due("stamp", 101.0, None, (100.0, None), 1.0, 5.0)
    assert bu.reading_due("stamp", 101.0, 40.1, (100.0, None), 1.0, 5.0)
    assert not bu.reading_due("stamp", 100.5, None, (100.0, None), 1.0, 5.0)


def test_a_stamp_left_at_zero_is_no_stamp():
    assert bu.stamp_seconds(0, 0) is None
    assert bu.stamp_seconds(12, 500000000) == 12.5
    assert bu.stamp_seconds(0, 1) == 1e-9


def odometry(start, end, rate, hz=30.0, stamp_at_start=500.0):
    """Odometry arriving `hz` times a second of wall time from `start` to `end`, its stamps
    advancing `rate` seconds per wall second: (arrival, stamp) pairs."""
    n = int(round((end - start) * hz))
    return [(start + i / hz, stamp_at_start + rate * i / hz) for i in range(n + 1)]


def test_odometry_arriving_at_a_steady_rate_is_steady():
    assert bu.steady(odometry(10.0, 13.0, 1.0), 13.0, 2.0)
    # Slow is steady too, if it holds.
    assert bu.steady(odometry(10.0, 13.0, 0.3), 13.0, 2.0)


def test_odometry_that_has_not_been_arriving_for_the_whole_window_is_not_steady():
    assert not bu.steady(odometry(11.5, 13.0, 1.0), 13.0, 2.0)
    assert not bu.steady([], 13.0, 2.0)


def test_a_gap_in_the_odometry_is_not_steady():
    samples = [s for s in odometry(10.0, 13.0, 1.0) if not 11.8 < s[0] < 12.4]
    assert not bu.steady(samples, 13.0, 2.0)
    # Nothing since 12.4: odometry that has stopped is not steady either.
    assert not bu.steady(odometry(10.0, 12.4, 1.0), 13.0, 2.0)


def test_stamps_that_do_not_advance_are_not_steady():
    # Odometry published while the simulation's time stands still: nothing is being simulated.
    assert not bu.steady(odometry(10.0, 13.0, 0.0), 13.0, 2.0)


def test_stamps_whose_rate_changes_are_not_steady():
    first = odometry(10.0, 12.0, 0.2)
    then = odometry(12.0 + 1 / 30.0, 13.0, 1.0, stamp_at_start=first[-1][1] + 1 / 30.0)
    assert not bu.steady(first + then, 13.0, 2.0)
    # Once the new rate has held for the whole window, it is steady.
    later = then + odometry(13.0 + 1 / 30.0, 15.0, 1.0, stamp_at_start=then[-1][1] + 1 / 30.0)
    assert bu.steady(first + later, 15.0, 2.0)


def test_stamps_that_go_backwards_are_not_steady():
    samples = odometry(10.0, 12.0, 1.0) + odometry(12.0 + 1 / 30.0, 13.0, 1.0, stamp_at_start=3.0)
    assert not bu.steady(samples, 13.0, 2.0)


def test_unstamped_odometry_is_steady_if_it_arrives_steadily():
    samples = [(arrival, None) for arrival, _ in odometry(10.0, 13.0, 1.0)]
    assert bu.steady(samples, 13.0, 2.0)
    assert not bu.steady([s for s in samples if not 11.8 < s[0] < 12.4], 13.0, 2.0)
