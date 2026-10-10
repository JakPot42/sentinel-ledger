"""The gate's deadman, on its own: no valid record within the configured time means the
safe state. The gate is given clock readings by whoever holds it, so these tests need no
real waiting. The ROS scenario that shows it with a real robot process is scenario 10."""
import json
import os

from actuator_gate import Gate
from test_gate import OTHER_SEED, PUBLIC, Line

SAFE = {"speed_mm_s": 0}


def gate_and_line(tmp_path, deadman=4):
    line = Line(str(tmp_path))
    return Gate(os.path.join(str(tmp_path), "gate.state"), SAFE, PUBLIC, deadman), line


def test_silence_after_a_command_sends_the_safe_state_once(tmp_path):
    gate, line = gate_and_line(tmp_path)
    gate.handle(line.record("genesis"), now=100.0)
    assert gate.handle(line.command(500), now=100.5)["send"] == {"speed_mm_s": 500}
    assert gate.check_deadman(104.4) is None           # 3.9 s of silence: the command stands
    assert gate.check_deadman(104.5) is None           # exactly 4 s: not yet over
    tripped = gate.check_deadman(104.6)
    assert tripped["send"] == SAFE and tripped["why"] == "deadman" and tripped["silent_seconds"] == 4.1
    # It says so once, not on every check after.
    assert gate.check_deadman(110.0) is None and gate.check_deadman(1000.0) is None


def test_heartbeat_records_keep_the_last_command_in_force(tmp_path):
    """A recorder that is alive and has nothing to say sends a heartbeat record. Those
    count: the robot keeps doing what it was last told for as long as they keep coming."""
    gate, line = gate_and_line(tmp_path)
    gate.handle(line.record("genesis"), now=0.0)
    gate.handle(line.command(500), now=1.0)
    for at in (3.0, 5.0, 7.0, 9.0, 11.0):
        assert gate.check_deadman(at) is None
        assert gate.handle(line.record("heartbeat"), now=at)["send"] is None
    assert gate.check_deadman(14.9) is None
    assert gate.check_deadman(15.1)["why"] == "deadman"


def test_only_an_accepted_record_counts(tmp_path):
    """Another node cannot hold the deadman off: a record it cannot sign is refused, and a
    refused message does not count. Nor does a bare safe-state message, nor junk."""
    gate, line = gate_and_line(tmp_path)
    gate.handle(line.record("genesis"), now=0.0)
    gate.handle(line.command(500), now=1.0)
    forged = line.command(900, seed=OTHER_SEED)
    line.n, line.prev = line.n - 1, json.loads(forged["record"])["prev"]   # the real chain did not move
    assert gate.handle(forged, now=4.0)["reason"] == "the record is not signed by the recorder"
    gate.handle({"type": "safe_state", "why": "recorder_fault"}, now=4.5)
    gate.handle({"nonsense": True}, now=4.9)
    assert gate.check_deadman(5.1)["why"] == "deadman"


def test_after_a_trip_the_next_accepted_command_moves_the_robot_again_and_rearms_it(tmp_path):
    gate, line = gate_and_line(tmp_path)
    gate.handle(line.record("genesis"), now=0.0)
    gate.handle(line.command(500), now=1.0)
    assert gate.check_deadman(6.0)["why"] == "deadman"
    # A heartbeat arriving after the trip is accepted and moves nothing: still stopped.
    assert gate.handle(line.record("heartbeat"), now=7.0)["send"] is None
    assert gate.handle(line.command(300), now=8.0)["send"] == {"speed_mm_s": 300}
    assert gate.check_deadman(11.9) is None
    assert gate.check_deadman(12.1)["why"] == "deadman"


def test_it_does_not_run_before_the_first_record_or_without_a_configured_time(tmp_path):
    gate, line = gate_and_line(tmp_path)
    # Nothing accepted yet: the gate has passed nothing on, so there is nothing to stop.
    assert gate.check_deadman(10_000.0) is None
    (tmp_path / "off").mkdir()
    off, line = gate_and_line(tmp_path / "off", deadman=None)
    off.handle(line.record("genesis"), now=0.0)
    off.handle(line.command(500), now=1.0)
    assert off.check_deadman(10_000.0) is None


def test_handled_without_a_clock_the_gate_has_no_deadman(tmp_path):
    """The file demo's gate reads a file after the fact. It gives no clock readings, and
    the deadman never starts."""
    gate, line = gate_and_line(tmp_path)
    gate.handle(line.record("genesis"))
    gate.handle(line.command(500))
    assert gate.check_deadman(10_000.0) is None


# --- a command's age -----------------------------------------------------------------------

def aged_gate(tmp_path, limit=1000):
    line = Line(str(tmp_path))
    return Gate(os.path.join(str(tmp_path), "gate.state"), SAFE, PUBLIC, 4, limit), line


def test_a_command_older_than_the_limit_is_not_carried_out_and_the_chain_still_moves(tmp_path):
    gate, line = aged_gate(tmp_path)
    gate.handle(line.record("genesis"), now=0.0, wall_ms=1_000_000)
    fresh = gate.handle(line.command(500, received_ms=1_000_100), now=0.2, wall_ms=1_000_200)
    assert fresh["send"] == {"speed_mm_s": 500} and fresh["reason"] is None
    stale = gate.handle(line.command(200, received_ms=1_000_300), now=6.5, wall_ms=1_006_300)
    assert stale["send"] == SAFE and stale["why"] == "stale_command" and stale["accepted"] is False
    assert stale["reason"] == "the command is 6000 ms old; the limit is 1000 ms"
    # The stale record is still the gate's head, so the recorder's next record follows it.
    assert gate.state["n"] == 2
    after = gate.handle(line.command(300, received_ms=1_007_000), now=7.2, wall_ms=1_007_050)
    assert after["send"] == {"speed_mm_s": 300} and after["reason"] is None


def test_the_limit_itself_is_allowed_and_one_millisecond_more_is_not(tmp_path):
    gate, line = aged_gate(tmp_path)
    gate.handle(line.record("genesis"), now=0.0, wall_ms=5_000)
    assert gate.handle(line.command(100, received_ms=5_000), now=1.0, wall_ms=6_000)["why"] == "applied"
    assert gate.handle(line.command(100, received_ms=5_000), now=1.0, wall_ms=6_001)["why"] == "stale_command"


def test_a_command_dated_ahead_of_the_gates_clock_is_not_carried_out_either(tmp_path):
    """Two clocks that disagree by more than the limit: the gate cannot tell the command's
    age, and does not guess."""
    gate, line = aged_gate(tmp_path)
    gate.handle(line.record("genesis"), now=0.0, wall_ms=5_000)
    ahead = gate.handle(line.command(100, received_ms=9_000), now=1.0, wall_ms=5_000)
    assert ahead["why"] == "stale_command" and "ahead of the gate's clock" in ahead["reason"]


def test_a_command_that_does_not_say_when_it_was_received_is_not_carried_out(tmp_path):
    gate, line = aged_gate(tmp_path)
    gate.handle(line.record("genesis"), now=0.0, wall_ms=5_000)
    undated = gate.handle(line.command(100), now=1.0, wall_ms=5_100)
    assert undated["why"] == "stale_command" and undated["send"] == SAFE


def test_only_commands_have_an_age(tmp_path):
    """A heartbeat is never stale. A stale blocked command sends the safe state, as a
    blocked command would anyway."""
    gate, line = aged_gate(tmp_path)
    gate.handle(line.record("genesis"), now=0.0, wall_ms=5_000)
    assert gate.handle(line.record("heartbeat"), now=1.0, wall_ms=9_999_999)["reason"] is None
    blocked = gate.handle(line.record("command", applied=None, outcome="blocked", received_ms=5_000),
                          now=2.0, wall_ms=60_000)
    assert blocked["send"] == SAFE and blocked["why"] == "stale_command"


def test_without_a_limit_or_without_a_clock_no_command_is_refused_for_its_age(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    no_limit, line = aged_gate(tmp_path / "a", limit=None)
    no_limit.handle(line.record("genesis"), now=0.0, wall_ms=0)
    assert no_limit.handle(line.command(100, received_ms=0), now=1.0, wall_ms=10**12)["why"] == "applied"
    # The file demo's gate is given no clock reading at all.
    no_clock, line = aged_gate(tmp_path / "b")
    no_clock.handle(line.record("genesis"))
    assert no_clock.handle(line.command(100, received_ms=0))["why"] == "applied"
