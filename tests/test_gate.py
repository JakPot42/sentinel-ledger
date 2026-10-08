"""The actuator-side gate on its own: what it passes on and what it refuses."""
import hashlib
import json
import os
import re
import subprocess
import sys

import run_scenarios


def leaf(text):
    return hashlib.sha256(b"\x00" + text.encode("utf-8")).hexdigest()


class Line:
    """A hand-written link, so the gate is tested without the recorder."""

    def __init__(self, folder):
        self.link = os.path.join(folder, "link.jsonl")
        self.state = os.path.join(folder, "gate.state")
        self.actuator = os.path.join(folder, "actuator.jsonl")
        self.n, self.prev = 0, ""

    def record(self, kind, **fields):
        rec = dict({"kind": kind, "n": self.n, "prev": self.prev}, **fields)
        raw = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        message = {"type": "record", "n": self.n, "hash": leaf(raw), "record": raw}
        self.n, self.prev = self.n + 1, message["hash"]
        return message

    def command(self, speed):
        return self.record("command", applied={"speed_mm_s": speed}, outcome="unchanged")

    def send(self, *messages):
        with open(self.link, "a", encoding="utf-8", newline="\n") as fh:
            for m in messages:
                fh.write(json.dumps(m) + "\n")
        return subprocess.run([sys.executable, run_scenarios.GATE, "--link", self.link, "--state", self.state,
                               "--actuator", self.actuator, "--safe-state", run_scenarios.SAFE_STATE],
                              capture_output=True, text=True).returncode

    def sent(self):
        if not os.path.exists(self.actuator):
            return []
        with open(self.actuator, encoding="utf-8") as fh:
            return [(a["why"], a["sent"]["speed_mm_s"]) for a in map(json.loads, fh)]


def test_a_chain_of_records_is_accepted_and_commands_reach_the_actuator(tmp_path):
    line = Line(str(tmp_path))
    blocked = lambda: line.record("command", applied=None, outcome="blocked")
    assert line.send(line.record("genesis"), line.record("recorder_start"), line.command(500)) == 0
    assert line.send(blocked(), line.record("heartbeat"), line.command(700)) == 0
    assert line.sent() == [("applied", 500), ("blocked", 0), ("applied", 700)]


def test_a_command_with_no_record_is_refused(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"))
    assert line.send({"type": "record", "n": 1, "action": {"speed_mm_s": 900}}) == 2
    assert line.sent() == [("gate_refused", 0)]


def test_a_command_whose_record_skips_one_is_refused(tmp_path):
    """The recorder wrote a record and did not forward it, or forwarded one it did not
    keep. Either way the next record does not follow the gate's head."""
    line = Line(str(tmp_path))
    line.send(line.record("genesis"), line.command(500))
    line.command(600)  # built, never sent
    assert line.send(line.command(700)) == 2
    assert line.sent() == [("applied", 500), ("gate_refused", 0)]


def test_a_replayed_command_is_refused(tmp_path):
    line = Line(str(tmp_path))
    first = line.command
    genesis, fast = line.record("genesis"), first(1500)
    assert line.send(genesis, fast, line.command(100)) == 0
    assert line.send(fast) == 2
    assert line.sent() == [("applied", 1500), ("applied", 100), ("gate_refused", 0)]


def test_a_record_with_the_wrong_hash_or_an_edited_action_is_refused(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"))
    message = line.command(500)
    message["record"] = message["record"].replace("500", "1500")
    assert line.send(message) == 2
    assert line.sent() == [("gate_refused", 0)]


def test_the_action_comes_from_the_record_not_from_beside_it(tmp_path):
    line = Line(str(tmp_path))
    message = line.record("genesis"), dict(line.command(500), action={"speed_mm_s": 1500})
    assert line.send(*message) == 0
    assert line.sent() == [("applied", 500)]


def test_the_first_record_must_be_genesis_and_a_second_journal_is_refused(tmp_path):
    line = Line(str(tmp_path))
    assert line.send(Line(str(tmp_path)).command(500)) == 2
    assert line.send(line.record("genesis"), line.command(500)) == 0
    other = Line(str(tmp_path))
    assert other.send(other.record("genesis"), other.command(900)) == 2
    assert line.sent() == [("gate_refused", 0), ("applied", 500), ("gate_refused", 0), ("gate_refused", 0)]


def test_a_safe_state_message_needs_no_record(tmp_path):
    line = Line(str(tmp_path))
    assert line.send({"type": "safe_state", "why": "recorder_fault"}) == 0
    assert line.sent() == [("recorder_fault", 0)]


def test_after_a_refusal_the_gate_still_accepts_the_record_that_does_follow(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"))
    assert line.send({"type": "record", "n": 9, "hash": "00", "record": "{}"}) == 2
    assert line.send(line.command(300)) == 0
    assert line.sent() == [("gate_refused", 0), ("applied", 300)]


def test_the_gate_shares_no_code_with_anything_else():
    for path in (run_scenarios.GATE, run_scenarios.WITNESS):
        with open(path, encoding="utf-8") as fh:
            imports = set(re.findall(r"^(?:import|from)\s+([\w.]+)", fh.read(), flags=re.M))
        assert imports <= {"argparse", "datetime", "hashlib", "json", "os", "re", "socketserver", "sys"}, path
