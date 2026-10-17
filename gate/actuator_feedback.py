#!/usr/bin/env python3
"""What the actuator did after each command, signed. docs/SPEC.md section 4.6.

The gate's receipt (section 4.5) says what the gate sent to the actuator. It does not say
what the actuator then did. This is that half. After acting on each command record the
gate takes into the chain, the robot reads its controller's own report of the actuator
(wheel or joint velocities, odometry) and signs it with a key of its own, the feedback
key: neither the recorder's nor the gate's. The recorder writes each report into the
journal as a record, and the verifier checks that every command has exactly one, signed
with that key, naming that command by number and hash.

When the reading is taken: after the action has been given, and before the actuator is
given anything else. A reading taken later would describe the next action and be filed
under this one. So whoever holds the reporter must read the actuator while a reading is
still `due` before every new action, whatever its cause: a command, a refusal, a deadman
trip or a safe-state message. It signs the reading (`report`) after giving that action,
since signing and saving the number take time and the action may be a stop. Otherwise it
takes the reading on its next control step.

What a report holds, besides the command it follows:
  - `sent`: the action the actuator was given for that command, as the gate handed it over;
  - `measured`: what the controller reports the actuator doing, in the same terms and under
    the same keys as `sent`, or None when the controller reports nothing in those terms;
  - `state`: anything else the controller reports (a pose, joint positions), as an object
    of integers, or None;
  - `after_ms`: how long after the action was given the reading was taken, on the
    monotonic clock, or None where there is none; `at_ms`: the wall clock at the reading.

It shares no code with the recorder or the verifier. It uses the gate's signing code,
which is on the same side of the machine.

What it cannot say: whether the controller's report is true. It is the controller's own
account of the actuator, signed by whoever holds the feedback key. An actuator that fails
without its controller noticing is reported as the controller believes it to be. And,
like the gate's key, anyone who can read the feedback key's file can sign reports.
"""
import json
import os

from actuator_gate import ed25519_sign, load_gate_key

FEEDBACK_SCHEMA = "sentinel-ledger/actuator-feedback/0"
# The gate's reasons for an action that answers a command record it took into the chain:
# the record's action, the safe state for a blocked command, the safe state for a command
# too old to carry out. Every other action (a refusal, a deadman trip, a safe-state
# message) answers no command record and is followed by no report.
FOLLOWS_A_COMMAND = ("applied", "blocked", "stale_command")


def load_feedback_key(path):
    """The feedback key: a file of 64 hexadecimal characters, kept like the gate's."""
    return load_gate_key(path)


class FeedbackReporter:
    """Its kept state is the number of its next report, so numbers carry on across
    restarts with no gaps. A reading that is due when the process ends is lost, and the
    verifier then reports that command as having no feedback."""

    def __init__(self, state_path, key):
        self.state_path = state_path
        self.key = key   # the feedback key, 32 bytes
        self.state = {"seq": 0}
        if os.path.exists(state_path):
            with open(state_path, "r", encoding="utf-8") as fh:
                self.state = json.load(fh)
        self.pending = None

    def save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def follow(self, decision, now=None):
        """Call right after acting on a decision the gate returned. If the decision answers
        a command record the gate took into the chain, a reading of what the actuator then
        does is due, and this returns True. `now` is a monotonic clock reading in seconds."""
        if decision.get("why") not in FOLLOWS_A_COMMAND or decision.get("n") is None or not decision.get("hash"):
            return False
        self.pending = {"n": decision["n"], "hash": decision["hash"], "sent": decision["send"], "acted": now}
        return True

    def due(self, now=None, at_least=0.0):
        """True when a reading is due. With `now` and `at_least`: only once the action has
        been in force for at least that many seconds, so a control loop can wait one step."""
        if self.pending is None:
            return False
        acted = self.pending["acted"]
        return now is None or acted is None or now - acted >= at_least

    def report(self, measured, state=None, now=None, wall_ms=None):
        """The signed report for the reading now due, or None when none is due. The number
        is kept before the report is handed back, so it is never used twice."""
        about = self.pending
        if about is None:
            return None
        self.pending = None
        seq = self.state.get("seq", 0)
        self.state["seq"] = seq + 1
        after = None
        if now is not None and about["acted"] is not None:
            after = max(0, int(round((now - about["acted"]) * 1000)))
        body = {"schema": FEEDBACK_SCHEMA, "seq": seq, "n": about["n"], "hash": about["hash"],
                "sent": about["sent"], "measured": measured, "state": state, "after_ms": after, "at_ms": wall_ms}
        text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        signed = dict(body, sig=ed25519_sign(self.key, text.encode("utf-8")).hex())
        self.save()
        return signed
