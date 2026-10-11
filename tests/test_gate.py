"""The actuator-side gate on its own: what it passes on and what it refuses."""
import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

import pure_ed25519 as ed
import run_scenarios
from actuator_gate import Gate

SEED = bytes(range(32))            # the "recorder" in these tests
PUBLIC = ed.public_key(SEED).hex()
OTHER_SEED = bytes(range(1, 33))   # someone else's key
GATE_SEED = bytes(range(100, 132))  # the gate's own key, for its receipts
SAFE = {"speed_mm_s": 0}


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


# --- the record's text must be its canonical form ----------------------------------------
#
# The gate checks a record's signature over a re-serialisation of the parsed record. Until
# it also compared the text it was sent with that canonical form, it accepted the same
# signed record in any other encoding, and its head became a hash the journal does not
# hold. The verifier already required the canonical form. docs/SPEC.md sections 4.2, 7.1.

# What a node with no key can do to a genuine record's text without changing what it says.
ENCODINGS = [
    ("spaces after the separators", lambda raw: json.dumps(json.loads(raw), sort_keys=True)),
    ("keys in another order",
     lambda raw: json.dumps(dict(reversed(list(json.loads(raw).items()))), separators=(",", ":"))),
    ("spread over several lines", lambda raw: json.dumps(json.loads(raw), sort_keys=True, indent=1)),
    ("a key given twice", lambda raw: raw[:-1] + ',"n":%d}' % json.loads(raw)["n"]),
    ("a key given twice, another action first", lambda raw: '{"applied":{"speed_mm_s":1500},' + raw[1:]),
    ("a trailing newline", lambda raw: raw + "\n"),
    ("trailing spaces", lambda raw: raw + "  "),
    ("a leading space", lambda raw: " " + raw),
    ("zero written as -0", lambda raw: raw.replace('"spare":0', '"spare":-0')),
    ("a letter written as an escape", lambda raw: raw.replace('"kind":"command"', '"kind":"comm\\u0061nd"')),
]
SPACED = ENCODINGS[0][1]


def in_another_encoding(message, encode):
    """The message a node with no key can make from a genuine one: the same record in other
    bytes, with the hash that belongs to those bytes. Nothing is signed again."""
    text = encode(message["record"])
    assert text != message["record"] and json.loads(text) == json.loads(message["record"])
    return dict(message, hash=leaf(text), record=text)


@pytest.mark.parametrize("encode", [encode for _, encode in ENCODINGS], ids=[name for name, _ in ENCODINGS])
def test_a_genuine_record_in_another_encoding_is_refused_and_the_gate_does_not_move(encode, tmp_path):
    line = Line(str(tmp_path))
    gate = Gate(line.state, SAFE, PUBLIC, gate_key=GATE_SEED)
    gate.handle(line.record("genesis"))
    first = line.command(500)
    assert gate.handle(first)["send"] == {"speed_mm_s": 500}
    genuine = line.command(700, spare=0)

    decision = gate.handle(in_another_encoding(genuine, encode))
    assert (decision["accepted"], decision["why"], decision["n"]) == (False, "gate_refused", None)
    assert decision["reason"] == "the record is not in canonical form"
    # The actuator gets the safe state, as for every refusal, and not the 700 in the record.
    assert decision["send"] == SAFE
    # The gate's head is still the last record it accepted.
    assert (gate.state["n"], gate.state["hash"]) == (1, first["hash"])
    receipt = gate.issue_receipt(decision)
    assert (receipt["decision"], receipt["reason"], receipt["detail"]) == (
        "refused", "form", "the record is not in canonical form")
    assert (receipt["n"], receipt["hash"], receipt["sent"]) == (None, None, SAFE)

    # The record as the recorder wrote it is still the next one, and it is carried out.
    after = gate.handle(genuine)
    assert (after["accepted"], after["why"], after["send"]) == (True, "applied", {"speed_mm_s": 700})
    assert (gate.state["n"], gate.state["hash"]) == (2, genuine["hash"])


def test_a_record_that_is_neither_canonical_nor_signed_by_the_recorder_is_refused_for_its_form(tmp_path):
    """One predictable reason. The checks on a message's form come before the signature."""
    line = Line(str(tmp_path))
    gate = Gate(line.state, SAFE, PUBLIC, gate_key=GATE_SEED)
    gate.handle(line.record("genesis"))
    decision = gate.handle(in_another_encoding(line.command(1500, seed=OTHER_SEED), SPACED))
    assert gate.issue_receipt(decision)["reason"] == "form"
    assert decision["send"] == SAFE and gate.state["n"] == 0


def test_a_whole_number_rewritten_as_a_decimal_is_refused_too_for_its_signature(tmp_path):
    """`0` written as `0.0` is written out again as `0.0`, so the check of the form passes
    it, and Python reads the two numbers as equal. The signature does not: the signed
    text has `0`. So this copy is refused one step later."""
    line = Line(str(tmp_path))
    gate = Gate(line.state, SAFE, PUBLIC, gate_key=GATE_SEED)
    gate.handle(line.record("genesis"))
    genuine = line.command(700, spare=0)
    decimal = in_another_encoding(genuine, lambda raw: raw.replace('"spare":0', '"spare":0.0'))
    decision = gate.handle(decimal)
    assert (decision["accepted"], decision["send"], gate.state["n"]) == (False, SAFE, 0)
    assert gate.issue_receipt(decision)["reason"] == "signature"
    assert gate.handle(genuine)["send"] == {"speed_mm_s": 700}


def test_text_nested_too_deeply_to_write_out_again_is_refused_and_is_not_an_error(tmp_path, monkeypatch):
    """Text can be parsed and still be nested too deeply to write out again: Python gives
    up with RecursionError. Seen with objects nested 10,000 deep on Windows and 50,000
    deep under WSL; the depth depends on the interpreter's stack. The check of the form
    must turn that into a refusal and not let it out of the gate. The failure is forced
    here, so the test does not depend on the size of anyone's stack."""
    import actuator_gate
    line = Line(str(tmp_path))
    gate = Gate(line.state, SAFE, PUBLIC)
    gate.handle(line.record("genesis"))
    nested = '{"a":' * 50 + "1" + "}" * 50
    genuine = line.command(500)

    def too_deep(*args, **kwargs):
        raise RecursionError("nested too deeply")

    with monkeypatch.context() as patched:
        patched.setattr(actuator_gate.json, "dumps", too_deep)
        decision = gate.handle({"type": "record", "n": 1, "hash": leaf(nested), "record": nested})
    assert (decision["accepted"], decision["reason"]) == (False, "the record is not in canonical form")
    assert decision["send"] == SAFE and gate.state["n"] == 0
    assert gate.handle(genuine)["send"] == {"speed_mm_s": 500}


def test_a_record_refused_for_its_encoding_does_not_count_for_the_deadman(tmp_path):
    """Only an accepted record holds the deadman off, and this one is not accepted."""
    line = Line(str(tmp_path))
    gate = Gate(line.state, SAFE, PUBLIC, 4)
    gate.handle(line.record("genesis"), now=0.0)
    gate.handle(line.command(500), now=1.0)
    quiet = in_another_encoding(line.record("heartbeat"), SPACED)
    assert gate.handle(quiet, now=4.0)["reason"] == "the record is not in canonical form"
    assert gate.check_deadman(5.1)["why"] == "deadman"


def test_the_gate_program_refuses_a_record_in_another_encoding_and_then_takes_the_genuine_one(tmp_path):
    line = Line(str(tmp_path))
    assert line.send(line.record("genesis"), line.command(500)).returncode == 0
    genuine = line.command(700)
    done = line.send(in_another_encoding(genuine, SPACED), genuine)
    assert done.returncode == 2 and "REFUSED: the record is not in canonical form" in done.stdout
    assert line.sent() == [("applied", 500), ("gate_refused", 0), ("applied", 700)]
    with open(line.state, encoding="utf-8") as fh:
        head = json.load(fh)
    assert (head["n"], head["hash"]) == (2, genuine["hash"])


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


def test_the_gate_holds_no_key_of_the_recorders_and_shares_no_code_with_anything_else():
    for path in (run_scenarios.GATE, run_scenarios.WITNESS):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        imports = set(re.findall(r"^(?:import|from)\s+([\w.]+)", source, flags=re.M))
        assert imports <= {"argparse", "datetime", "hashlib", "json", "os", "re", "socketserver", "sys"}, path
    with open(run_scenarios.GATE, encoding="utf-8") as fh:
        gate = fh.read()
    # The gate has a signing key of its own, for its receipts (tests/test_receipts.py).
    # The code that judges a record is given the recorder's public key and nothing that
    # can sign, and the gate's key is used to sign in one place only: a receipt.
    judging = gate.split("def judge")[1].split("class Gate")[0]
    assert "gate_key" not in judging and "sign(" not in judging and "private" not in judging
    assert gate.count("ed25519_sign(") == 2          # its definition, and issue_receipt
