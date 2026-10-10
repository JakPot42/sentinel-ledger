"""The actuator-side gate on its own: what it passes on and what it refuses."""
import hashlib
import json
import os
import re
import subprocess
import sys

import pure_ed25519 as ed
import run_scenarios

SEED = bytes(range(32))            # the "recorder" in these tests
PUBLIC = ed.public_key(SEED).hex()
OTHER_SEED = bytes(range(1, 33))   # someone else's key


def leaf(text):
    return hashlib.sha256(b"\x00" + text.encode("utf-8")).hexdigest()


class Line:
    """A hand-written link, so the gate is tested without the recorder."""

    def __init__(self, folder):
        self.link = os.path.join(folder, "link.jsonl")
        self.state = os.path.join(folder, "gate.state")
        self.actuator = os.path.join(folder, "actuator.jsonl")
        self.n, self.prev = 0, ""

    def record(self, kind, seed=SEED, sign=True, **fields):
        rec = dict({"kind": kind, "n": self.n, "prev": self.prev}, **fields)
        if sign:
            rec = ed.sign_record(seed, rec)
        raw = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        message = {"type": "record", "n": self.n, "hash": leaf(raw), "record": raw}
        self.n, self.prev = self.n + 1, message["hash"]
        return message

    def command(self, speed, **how):
        return self.record("command", applied={"speed_mm_s": speed}, outcome="unchanged", **how)

    def send(self, *messages):
        with open(self.link, "a", encoding="utf-8", newline="\n") as fh:
            for m in messages:
                fh.write(json.dumps(m) + "\n")
        return subprocess.run([sys.executable, run_scenarios.GATE, "--link", self.link, "--state", self.state,
                               "--actuator", self.actuator, "--safe-state", run_scenarios.SAFE_STATE,
                               "--public-key", PUBLIC], capture_output=True, text=True)

    def sent(self):
        if not os.path.exists(self.actuator):
            return []
        with open(self.actuator, encoding="utf-8") as fh:
            return [(a["why"], a["sent"]["speed_mm_s"]) for a in map(json.loads, fh)]


def test_a_chain_of_signed_records_is_accepted_and_commands_reach_the_actuator(tmp_path):
    line = Line(str(tmp_path))
    blocked = lambda: line.record("command", applied=None, outcome="blocked")
    assert line.send(line.record("genesis"), line.record("recorder_start"), line.command(500)).returncode == 0
    assert line.send(blocked(), line.record("heartbeat"), line.command(700)).returncode == 0
    assert line.sent() == [("applied", 500), ("blocked", 0), ("applied", 700)]


def test_a_command_with_no_record_is_refused(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"))
    assert line.send({"type": "record", "n": 1, "action": {"speed_mm_s": 900}}).returncode == 2
    assert line.sent() == [("gate_refused", 0)]


def test_a_correctly_chained_record_with_no_signature_is_refused(tmp_path):
    """The forgery that used to get through: right number, right `prev`, right hash."""
    line = Line(str(tmp_path))
    line.send(line.record("genesis"), line.command(500))
    done = line.send(line.command(1500, sign=False))
    assert done.returncode == 2 and "not signed by the recorder" in done.stdout
    assert line.sent() == [("applied", 500), ("gate_refused", 0)]


def test_a_correctly_chained_record_signed_with_another_key_is_refused(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"), line.command(500))
    done = line.send(line.command(1500, seed=OTHER_SEED))
    assert done.returncode == 2 and "not signed by the recorder" in done.stdout
    assert line.sent() == [("applied", 500), ("gate_refused", 0)]


def test_a_signature_lifted_from_another_record_is_refused(tmp_path):
    line = Line(str(tmp_path))
    real = line.command  # noqa: F841
    genesis, first = line.record("genesis"), line.command(500)
    line.send(genesis, first)
    forged = dict(json.loads(first["record"]), n=2, prev=first["hash"], applied={"speed_mm_s": 1500})
    raw = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    done = line.send({"type": "record", "n": 2, "hash": leaf(raw), "record": raw})
    assert done.returncode == 2 and "not signed by the recorder" in done.stdout
    assert line.sent() == [("applied", 500), ("gate_refused", 0)]


def test_a_command_whose_record_skips_one_is_refused(tmp_path):
    """The recorder wrote a record and did not forward it, or forwarded one it did not
    keep. Either way the next record does not follow the gate's head."""
    line = Line(str(tmp_path))
    line.send(line.record("genesis"), line.command(500))
    line.command(600)  # built, never sent
    done = line.send(line.command(700))
    assert done.returncode == 2 and "does not extend the chain" in done.stdout
    assert line.sent() == [("applied", 500), ("gate_refused", 0)]


def test_a_replayed_command_is_refused(tmp_path):
    line = Line(str(tmp_path))
    genesis, fast = line.record("genesis"), line.command(1500)
    assert line.send(genesis, fast, line.command(100)).returncode == 0
    assert line.send(fast).returncode == 2
    assert line.sent() == [("applied", 1500), ("applied", 100), ("gate_refused", 0)]


def test_a_record_with_an_edited_action_is_refused(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"))
    message = line.command(500)
    message["record"] = message["record"].replace("500", "1500")
    done = line.send(message)
    assert done.returncode == 2 and "hash does not belong" in done.stdout
    # And with the hash repaired, the signature no longer covers the edited text.
    message["hash"] = leaf(message["record"])
    done = line.send(message)
    assert done.returncode == 2 and "not signed by the recorder" in done.stdout
    assert line.sent() == [("gate_refused", 0), ("gate_refused", 0)]


def test_the_action_comes_from_the_record_not_from_beside_it(tmp_path):
    line = Line(str(tmp_path))
    message = line.record("genesis"), dict(line.command(500), action={"speed_mm_s": 1500})
    assert line.send(*message).returncode == 0
    assert line.sent() == [("applied", 500)]


def test_the_first_record_must_be_genesis_and_a_second_journal_is_refused(tmp_path):
    line = Line(str(tmp_path))
    assert line.send(Line(str(tmp_path)).command(500)).returncode == 2
    assert line.send(line.record("genesis"), line.command(500)).returncode == 0
    other = Line(str(tmp_path))
    assert other.send(other.record("genesis"), other.command(900)).returncode == 2
    assert line.sent() == [("gate_refused", 0), ("applied", 500), ("gate_refused", 0), ("gate_refused", 0)]


def test_a_safe_state_message_needs_no_record_and_no_signature(tmp_path):
    line = Line(str(tmp_path))
    assert line.send({"type": "safe_state", "why": "recorder_fault"}).returncode == 0
    assert line.sent() == [("recorder_fault", 0)]


def test_after_a_refusal_the_gate_still_accepts_the_record_that_does_follow(tmp_path):
    line = Line(str(tmp_path))
    line.send(line.record("genesis"))
    assert line.send({"type": "record", "n": 9, "hash": "00", "record": "{}"}).returncode == 2
    assert line.send(line.command(300)).returncode == 0
    assert line.sent() == [("gate_refused", 0), ("applied", 300)]


def test_three_separate_copies_of_the_signature_check_agree_with_rfc_8032():
    """The gate and the verifier each carry their own verification code, and the demo
    helper a third. RFC 8032 section 7.1, test 1 (the empty message) and test 2."""
    import actuator_gate
    import verify_journal
    vectors = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", b"",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
         "d25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", b"\x72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
         "387b2eaeb4302aeeb00d291612bb0c00"),
    ]
    for seed, public, message, signature in vectors:
        seed, public, signature = bytes.fromhex(seed), bytes.fromhex(public), bytes.fromhex(signature)
        assert ed.public_key(seed) == public and ed.sign(seed, message) == signature
        for verify in (ed.verify, actuator_gate.ed25519_verify, verify_journal.ed25519_verify):
            assert verify(public, message, signature)
            assert not verify(public, message + b"x", signature)
            assert not verify(public, message, signature[:63] + bytes([signature[63] ^ 1]))
            assert not verify(ed.public_key(OTHER_SEED), message, signature)


def test_the_gate_holds_no_private_key_and_shares_no_code_with_anything_else():
    for path in (run_scenarios.GATE, run_scenarios.WITNESS):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        imports = set(re.findall(r"^(?:import|from)\s+([\w.]+)", source, flags=re.M))
        assert imports <= {"argparse", "datetime", "hashlib", "json", "os", "re", "socketserver", "sys"}, path
    with open(run_scenarios.GATE, encoding="utf-8") as fh:
        gate = fh.read()
    assert "def sign(" not in gate and "seed" not in gate and "private" not in gate.split("def judge")[1]
