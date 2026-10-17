"""The gate's receipts: what the gate signs, what the recorder writes down, and what the
verifier then reports. docs/SPEC.md section 4.5.

The first half is the gate on its own. The second half runs the real recorder program and
the real gate class with the test standing where the wire between them would be, so it
needs no ROS. The ROS scenarios show the same over topics, with a real robot process.
"""
import json
import os
import subprocess
import sys

import pytest

import pure_ed25519 as ed
import run_scenarios
import verify_journal as vj
from actuator_gate import RECEIPT_SCHEMA, Gate, ed25519_public, ed25519_sign
from test_gate import OTHER_SEED, PUBLIC, SEED, Line
from test_tamper import forge

SAFE = {"speed_mm_s": 0}
GATE_SEED = bytes(range(100, 132))            # the gate's own key: not the recorder's
GATE_PUBLIC = ed.public_key(GATE_SEED).hex()


def signed_by_the_gate(receipt, public=GATE_PUBLIC):
    body = {k: v for k, v in receipt.items() if k != "sig"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return vj.ed25519_verify(bytes.fromhex(public), text, bytes.fromhex(receipt["sig"]))


# --- the gate on its own ---------------------------------------------------------------

def gate_and_line(tmp_path, deadman=None, age_limit=None, key=GATE_SEED):
    line = Line(str(tmp_path))
    return Gate(os.path.join(str(tmp_path), "gate.state"), SAFE, PUBLIC, deadman, age_limit, gate_key=key), line


def take(gate, message, **clock):
    decision = gate.handle(message, **clock)
    return decision, gate.issue_receipt(decision, wall_ms=clock.get("wall_ms"))


def test_the_gates_signing_code_agrees_with_rfc_8032():
    """RFC 8032 section 7.1, tests 1 and 2, and the demo helper on a longer message."""
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
    for key, public, message, signature in vectors:
        assert ed25519_public(bytes.fromhex(key)).hex() == public
        assert ed25519_sign(bytes.fromhex(key), message).hex() == signature
    assert ed25519_sign(GATE_SEED, b"a receipt" * 40) == ed.sign(GATE_SEED, b"a receipt" * 40)
    assert ed25519_public(GATE_SEED).hex() == GATE_PUBLIC


def test_a_command_the_gate_carries_out_gets_a_receipt_naming_the_record(tmp_path):
    gate, line = gate_and_line(tmp_path)
    assert take(gate, line.record("genesis"))[1] is None            # not a command: no receipt
    message = line.command(500)
    decision, receipt = take(gate, message, wall_ms=1_700_000_000_000)
    assert decision["send"] == {"speed_mm_s": 500}
    assert receipt == dict(receipt, schema=RECEIPT_SCHEMA, seq=0, decision="applied", reason=None, detail=None,
                           n=1, hash=message["hash"], sent={"speed_mm_s": 500}, at_ms=1_700_000_000_000)
    assert signed_by_the_gate(receipt)
    # It is the gate's key, not the recorder's, and nobody else's.
    assert not signed_by_the_gate(receipt, PUBLIC)
    assert not signed_by_the_gate(dict(receipt, decision="blocked"))
    assert take(gate, line.record("heartbeat"))[1] is None
    blocked = line.record("command", applied=None, outcome="blocked")
    _, receipt = take(gate, blocked)
    assert (receipt["seq"], receipt["decision"], receipt["n"], receipt["sent"]) == (1, "blocked", 3, SAFE)


def test_every_refusal_gets_a_receipt_that_says_why(tmp_path):
    gate, line = gate_and_line(tmp_path, age_limit=1000)
    take(gate, line.record("genesis"), wall_ms=0)
    real = line.command(500, received_ms=1000)
    take(gate, real, wall_ms=1000)
    said = []
    # Not a record message at all, then a record whose text was changed.
    said.append(take(gate, {"type": "record", "n": 2, "action": {"speed_mm_s": 900}}, wall_ms=1000)[1])
    said.append(take(gate, dict(real, record=real["record"].replace("500", "900")), wall_ms=1000)[1])
    # The next record in the chain, made by someone without the recorder's key.
    forged = line.command(900, seed=OTHER_SEED, received_ms=1000)
    line.n, line.prev = line.n - 1, json.loads(forged["record"])["prev"]
    said.append(take(gate, forged, wall_ms=1000)[1])
    # A genuine record, sent a second time.
    said.append(take(gate, real, wall_ms=1000)[1])
    # A genuine record, next in the chain, six seconds old.
    late = line.command(200, received_ms=2000)
    decision, receipt = take(gate, late, wall_ms=8000)
    said.append(receipt)
    assert [r["reason"] for r in said] == ["form", "form", "signature", "chain", "age"]
    assert all(r["decision"] == "refused" and r["sent"] == SAFE and signed_by_the_gate(r) for r in said)
    assert [r["seq"] for r in said] == [1, 2, 3, 4, 5]
    # Only the refusal for age names a record: the others were never taken into the chain.
    assert [(r["n"], r["hash"]) for r in said[:4]] == [(None, None)] * 4
    assert (receipt["n"], receipt["hash"]) == (2, late["hash"]) and decision["why"] == "stale_command"
    assert receipt["detail"] == "the command is 6000 ms old; the limit is 1000 ms"


def test_a_deadman_trip_gets_a_receipt_naming_the_last_record_accepted(tmp_path):
    gate, line = gate_and_line(tmp_path, deadman=4)
    take(gate, line.record("genesis"), now=0.0)
    moving = line.command(500)
    take(gate, moving, now=1.0)
    tripped = gate.check_deadman(5.5)
    receipt = gate.issue_receipt(tripped, wall_ms=77)
    assert (receipt["decision"], receipt["n"], receipt["hash"], receipt["sent"]) == ("deadman", 1, moving["hash"], SAFE)
    assert receipt["detail"] == "no valid record for 4.500 s; the limit is 4 s" and signed_by_the_gate(receipt)


def test_a_gate_with_no_key_of_its_own_signs_nothing(tmp_path):
    gate, line = gate_and_line(tmp_path, deadman=4, key=None)
    assert take(gate, line.record("genesis"), now=0.0)[1] is None
    assert take(gate, line.command(500), now=1.0)[1] is None
    assert take(gate, {"junk": 1}, now=1.5)[1] is None
    assert gate.issue_receipt(gate.check_deadman(9.0)) is None
    assert "receipt_seq" not in gate.state


def test_receipt_numbers_carry_on_after_the_gate_restarts(tmp_path):
    gate, line = gate_and_line(tmp_path)
    take(gate, line.record("genesis"))
    assert take(gate, line.command(100))[1]["seq"] == 0
    assert take(gate, line.command(200))[1]["seq"] == 1
    gate.save()
    again = Gate(gate.state_path, SAFE, PUBLIC, gate_key=GATE_SEED)
    assert take(again, line.command(300))[1]["seq"] == 2


def test_a_refused_record_about_a_receipt_gets_no_receipt_of_its_own(tmp_path):
    """Once the chain is broken the gate refuses every record, and the recorder writes a
    record for every refusal. If those records were receipted too, it would never end."""
    gate, line = gate_and_line(tmp_path)
    take(gate, line.record("genesis"))
    lost = line.command(100)                      # the gate never sees this one
    about_a_receipt = line.record("gate_receipt", receipt={"seq": 0})
    decision, receipt = take(gate, about_a_receipt)
    assert decision["why"] == "gate_refused" and "does not extend the chain" in decision["reason"]
    assert receipt is None
    # Any other record refused for its place in the chain does get one.
    assert take(gate, line.command(200))[1]["reason"] == "chain"
    # And so does something that only claims to be such a record: it is not signed.
    fake = line.record("gate_receipt", sign=False, receipt={"seq": 1})
    assert take(gate, fake)[1]["reason"] == "signature"
    assert lost["n"] == 1


def test_the_gate_program_writes_its_receipts_to_a_file(tmp_path):
    line = Line(str(tmp_path))
    key_file, receipts = tmp_path / "gate.key", tmp_path / "receipts.jsonl"
    key_file.write_text(GATE_SEED.hex() + "\n", encoding="utf-8")
    os.chmod(key_file, 0o600)
    with open(line.link, "w", encoding="utf-8", newline="\n") as fh:
        for message in (line.record("genesis"), line.command(300), {"type": "record", "n": 9}):
            fh.write(json.dumps(message) + "\n")
    done = subprocess.run([sys.executable, run_scenarios.GATE, "--link", line.link, "--state", line.state,
                           "--actuator", line.actuator, "--safe-state", run_scenarios.SAFE_STATE,
                           "--public-key", PUBLIC, "--gate-key", str(key_file), "--receipts", str(receipts)],
                          capture_output=True, text=True)
    assert done.returncode == 2, done.stderr
    written = [json.loads(text) for text in receipts.read_text(encoding="utf-8").splitlines()]
    assert [(r["seq"], r["decision"], r["reason"]) for r in written] == [(0, "applied", None), (1, "refused", "form")]
    assert all(signed_by_the_gate(r) for r in written)


# --- the recorder, the gate and the verifier together ----------------------------------

class Machine:
    """The recorder (the program as shipped), the gate (the class as shipped, with a key
    of its own), and the test in place of the wire between them: it hands the gate each
    message the recorder sends, and hands the recorder each receipt the gate signs."""

    def __init__(self, tmp_path, recorder, age_limit=None, deadman=None, gate_key=GATE_SEED, more_config=""):
        """`gate_key=None`: a gate that signs no receipts, on a machine whose configuration
        names no gate key. `more_config`: further lines for the configuration file."""
        self.w = run_scenarios.Workspace(str(tmp_path), "receipts", recorder)
        config = os.path.join(self.w.installed, "config.json")
        named = '\n  "gate_public_key": "%s",' % GATE_PUBLIC if gate_key is not None else ""
        with open(config, encoding="utf-8") as fh:
            text = fh.read().replace('"anchor_every": 4,', '"anchor_every": 4,' + named + more_config)
        assert (GATE_PUBLIC in text) == (gate_key is not None)
        with open(config, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        self.gate = Gate(self.w.gate_state, SAFE, self.w.public_key, deadman, age_limit, gate_key=gate_key)
        self.proc = subprocess.Popen(self.w.run_args("2026-10-01T08:00:00Z"), stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True)
        self.offset, self.now, self.late_ms = 0, 0.0, 0
        self.drop = lambda receipt: False      # a test can make the gate lose some receipts
        self.receipts, self.replies = [], []
        self.deliver()

    def ask(self, op):
        self.proc.stdin.write(json.dumps(op) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def deliver(self):
        """Hand over everything new, both ways, until nothing more moves."""
        while os.path.exists(self.w.link):     # not there until the recorder has started
            with open(self.w.link, "rb") as fh:
                fh.seek(self.offset)
                new = fh.read()
            if not new:
                return
            self.offset += len(new)
            for text in new.decode("utf-8").splitlines():
                self.judge(json.loads(text))

    def judge(self, message):
        try:
            received = json.loads(message.get("record", "")).get("received_ms")
        except (ValueError, AttributeError):
            received = None
        # The gate's clock reads the time the command was received, plus any lateness.
        wall_ms = (received if type(received) is int else 0) + self.late_ms
        self.now += 0.1
        decision = self.gate.handle(message, now=self.now, wall_ms=wall_ms)
        self.hand_over(self.gate.issue_receipt(decision, wall_ms=wall_ms))
        return decision

    def hand_over(self, receipt):
        self.gate.save()
        if receipt is not None:
            self.receipts.append(receipt)
            if not self.drop(receipt):
                self.replies.append(self.ask({"op": "gate_receipt", "receipt": receipt}))

    def command(self, speed, inputs=run_scenarios.CLEAR, late_ms=0):
        self.late_ms = late_ms
        reply = self.ask(run_scenarios.command(speed, inputs))
        self.deliver()
        self.late_ms = 0
        return reply

    def rogue(self, message):
        """Another party puts a message on the gate's input."""
        decision = self.judge(message)
        self.deliver()
        return decision

    def silence(self, seconds):
        self.now += seconds
        tripped = self.gate.check_deadman(self.now)
        if tripped:
            self.hand_over(self.gate.issue_receipt(tripped, wall_ms=0))
            self.deliver()
        return tripped

    def stop(self):
        self.proc.stdin.close()
        last = [json.loads(text) for text in self.proc.stdout.read().splitlines() if text.strip()][-1]
        assert self.proc.wait(timeout=30) == 0
        self.proc.stdout.close()
        self.deliver()
        self.gate.save()
        self.root = last["root"]
        return self

    def verify(self, *extra, root=None):
        return self.w.verify("--gate-public-key", GATE_PUBLIC, *extra, root=root or self.root, witness=False)

    def records(self):
        with open(self.w.journal, encoding="utf-8") as fh:
            return [json.loads(json.loads(text)["raw"]) for text in fh]


def found(report):
    return sorted(f["finding"] for f in report["findings"])


@pytest.fixture()
def machine(recorder, tmp_path):
    made = []

    def make(**how):
        made.append(Machine(tmp_path, recorder, **how))
        return made[-1]
    yield make
    for m in made:
        if m.proc.poll() is None:
            m.proc.kill()
            m.proc.wait()
            m.proc.stdout.close()


def test_every_command_has_its_receipt_in_the_journal_and_the_journal_is_clean(machine):
    m = machine()
    replies = [m.command(400), m.command(1800), m.command(500, {"light_curtain_clear": 0}), m.command(300)]
    m.stop()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    counts = report["counts"]
    assert (counts["commands"], counts["gate_receipts"], counts["commands_without_receipt"]) == (4, 4, 0)
    assert (counts["gate_refusals"], counts["gate_deadman_trips"]) == (0, 0)
    records = m.records()
    held = [r["receipt"] for r in records if r["kind"] == "gate_receipt"]
    assert [h["decision"] for h in held] == ["applied", "applied", "blocked", "applied"]
    assert [h["n"] for h in held] == [r["n"] for r in replies]
    assert held[1]["sent"] == {"speed_mm_s": 1500}                 # what the gate applied: the clamped speed
    assert held == m.receipts and all(signed_by_the_gate(h) for h in held)
    # Each receipt is a record of the recorder's own: numbered, chained, signed.
    assert all(len(r["sig"]) == 128 for r in records if r["kind"] == "gate_receipt")
    assert records[0]["settings"]["gate_public_key"] == GATE_PUBLIC


def test_a_command_refused_for_its_age_is_in_the_journal_and_the_verifier_reports_it(machine):
    """The loop this closes. Before receipts, this journal read: recorded, forwarded,
    nothing to report."""
    m = machine(age_limit=1000)
    m.command(400)
    late = m.command(600, late_ms=6000)
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["GATE_REFUSED"]
    finding = report["findings"][0]
    assert (finding["reason"], finding["of_record"]) == ("age", late["n"])
    assert finding["detail"] == "the command is 6000 ms old; the limit is 1000 ms"
    # The command record itself has not changed: it still says recorded, and applied 600.
    assert m.records()[late["n"]]["applied"] == {"speed_mm_s": 600}
    # What a person reads.
    text = subprocess.run([sys.executable, run_scenarios.VERIFIER, m.w.journal, "--root", m.root, "--rulesets",
                           os.path.join(m.w.data, "rulesets"), "--gate-public-key", GATE_PUBLIC],
                          capture_output=True, text=True).stdout
    assert "gate receipts:    3 in the journal: 1 refusal(s), 0 deadman trip(s); 0 command(s) with no receipt" in text
    assert '  GATE_REFUSED n=%d gate_seq=1 reason="age" of_record=%d detail="the command is 6000 ms old; ' \
           'the limit is 1000 ms"' % (finding["n"], late["n"]) in text
    assert text.rstrip().endswith("1 FINDING(S)")


def test_a_refusal_of_something_another_party_sent_is_in_the_journal_too(machine):
    m = machine()
    m.command(400)
    assert m.rogue({"type": "record", "n": 99, "action": {"speed_mm_s": 1500}})["why"] == "gate_refused"
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["GATE_REFUSED"]
    assert (report["findings"][0]["reason"], report["findings"][0]["of_record"]) == ("form", None)


def test_a_deadman_trip_is_in_the_journal(machine):
    m = machine(deadman=4)
    moving = m.command(400)
    assert m.silence(3.0) is None
    assert m.silence(2.0)["why"] == "deadman"
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["GATE_DEADMAN"]
    # The last record the gate had accepted was the record of its own receipt for `moving`.
    assert report["findings"][0]["last_record_accepted"] == moving["n"] + 1


def test_a_gate_that_drops_a_receipt_leaves_a_command_without_one_and_a_gap_in_its_numbers(machine):
    m = machine(age_limit=1000)
    m.command(400)
    m.drop = lambda receipt: receipt["decision"] == "refused"      # the gate keeps its refusals to itself
    late = m.command(600, late_ms=6000)
    m.command(300)
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_RECEIPT", "RECEIPT_MISSING"]
    by_kind = {f["finding"]: f for f in report["findings"]}
    assert by_kind["COMMAND_WITHOUT_RECEIPT"]["n"] == late["n"]
    assert (by_kind["RECEIPT_MISSING"]["missing"], by_kind["RECEIPT_MISSING"]["first_missing"]) == (1, 1)
    assert "GATE_REFUSED" not in by_kind                           # the journal cannot say what was decided


def test_a_gate_that_sends_no_receipts_at_all_leaves_every_command_without_one(machine):
    m = machine()
    m.drop = lambda receipt: True
    sent = [m.command(400), m.command(500)]
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["COMMAND_WITHOUT_RECEIPT"] * 2
    assert [f["n"] for f in report["findings"]] == [r["n"] for r in sent]


def test_a_dropped_receipt_for_a_refusal_shows_only_as_a_gap_and_only_once_another_follows(machine):
    """What numbering can and cannot do. A refusal of a message that was never a record
    answers for no command, so nothing but the gap in the numbers shows it was dropped.
    And if it was the last receipt the gate ever issued, nothing shows it."""
    m = machine()
    m.command(400)
    m.drop = lambda receipt: receipt["decision"] == "refused"
    m.rogue({"type": "record", "n": 99})
    m.command(300)
    m.rogue({"type": "record", "n": 99})                           # the last receipt issued: dropped too
    m.stop()
    code, report = m.verify()
    assert code == 2 and found(report) == ["RECEIPT_MISSING"]
    assert len(m.receipts) == 4 and report["counts"]["gate_receipts"] == 2


def test_the_recorder_writes_down_only_what_the_gate_signed_and_only_once(machine):
    m = machine()
    first = m.command(400)
    genuine = m.receipts[0]
    # Signed with another key: the recorder's own, here, to show even that is not the gate's.
    body = {k: v for k, v in genuine.items() if k != "sig"}
    forged = ed.sign_record(SEED, dict(body, seq=1, decision="refused", reason="age", detail="made up"))
    for bad in (forged, dict(genuine, seq=1), genuine, "not a receipt", {"schema": RECEIPT_SCHEMA}):
        reply = m.ask({"op": "gate_receipt", "receipt": bad})
        assert reply["ok"] is False and reply["fault"] is False, reply
    m.stop()
    code, report = m.verify()
    assert (code, report["findings"]) == (0, [])
    assert report["counts"]["gate_receipts"] == 1 and first["ok"]


def test_the_verifier_is_given_the_gates_key_and_the_journal_must_name_that_one(machine):
    m = machine()
    m.command(400)
    m.stop()
    code, report = m.w.verify("--gate-public-key", PUBLIC, root=m.root, witness=False)
    assert code == 2 and found(report) == ["KEY_MISMATCH"]
    assert report["findings"][0]["journal_gate_key"] == GATE_PUBLIC


# --- the journal's keeper, who holds the recorder's key and not the gate's -------------

def refused_once(machine):
    m = machine(age_limit=1000)
    m.command(400)
    late = m.command(600, late_ms=6000)
    m.command(300)
    return m.stop(), late["n"]


def test_the_keeper_cannot_turn_a_refusal_into_an_applied_command(machine):
    """The keeper rewrites the receipt, signs the record again with the recorder's key and
    repairs every hash. The receipt inside it is no longer one the gate signed."""
    m, late_n = refused_once(machine)

    def rewrite(records):
        for record in records:
            if record["kind"] == "gate_receipt" and record["receipt"]["decision"] == "refused":
                record["receipt"].update(decision="applied", reason=None, detail=None, sent={"speed_mm_s": 600})
    code, report = m.w.verify("--gate-public-key", GATE_PUBLIC, root=forge(m.w, rewrite), witness=False, gate=False)
    assert code == 2 and "RECEIPT_INVALID" in found(report) and "GATE_REFUSED" not in found(report)
    assert "COMMAND_WITHOUT_RECEIPT" in found(report)              # and so that command has no receipt


def test_the_keeper_cannot_remove_a_refusal_without_it_showing(machine):
    """The keeper deletes the record of the refusal and repairs the chain. The command it
    was about now has no receipt, the gate's numbers skip one, and the receipts of later
    commands name hashes that have changed."""
    m, late_n = refused_once(machine)

    def remove(records):
        return [r for r in records if not (r["kind"] == "gate_receipt" and r["receipt"]["decision"] == "refused")]
    code, report = m.w.verify("--gate-public-key", GATE_PUBLIC, root=forge(m.w, remove), witness=False, gate=False)
    assert code == 2 and "GATE_REFUSED" not in found(report)
    assert {"COMMAND_WITHOUT_RECEIPT", "RECEIPT_MISSING", "RECEIPT_MISMATCH"} <= set(found(report))
    assert [f["n"] for f in report["findings"] if f["finding"] == "COMMAND_WITHOUT_RECEIPT"][0] == late_n


def test_a_receipt_that_does_not_belong_to_the_record_it_names_is_a_finding(machine):
    """Receipts the gate did sign, put where they do not belong: one naming a hash that is
    not the record's, one for a record that is not a command, a second one for a command
    that has one. Made here with the gate's key, which only the gate should hold."""
    def run(change):
        m = machine()
        m.command(400)
        m.command(500)
        m.stop()

        def edit(records):
            receipts = [r for r in records if r["kind"] == "gate_receipt"]
            change(receipts, records)
            for r in receipts:
                r["receipt"] = ed.sign_record(GATE_SEED, r["receipt"])
        code, report = m.w.verify("--gate-public-key", GATE_PUBLIC, root=forge(m.w, edit), witness=False, gate=False)
        return code, report

    def wrong_hash(receipts, records):
        receipts[0]["receipt"]["hash"] = "00" * 32

    def not_a_command(receipts, records):
        receipts[0]["receipt"]["n"] = 1                            # record 1 is recorder_start

    def twice(receipts, records):
        receipts[1]["receipt"].update(n=receipts[0]["receipt"]["n"], hash=receipts[0]["receipt"]["hash"],
                                      sent=receipts[0]["receipt"]["sent"])

    def says_blocked(receipts, records):
        receipts[0]["receipt"].update(decision="blocked", sent=SAFE)

    for change, reason in ((wrong_hash, "not the hash of record"), (not_a_command, "not a command"),
                           (twice, "already has a receipt"), (says_blocked, "it was not")):
        code, report = run(change)
        mismatch = [f for f in report["findings"] if f["finding"] == "RECEIPT_MISMATCH"]
        assert code == 2 and mismatch and reason in mismatch[0]["reason"], (change.__name__, report["findings"])


def test_a_malformed_receipt_record_is_a_finding(machine):
    for change in (lambda receipt: receipt.update(decision="looked away"),
                   lambda receipt: receipt.update(decision="refused", reason="mood"),
                   lambda receipt: receipt.update(seq=-1),
                   lambda receipt: receipt.pop("hash")):
        m = machine()
        m.command(400)
        m.stop()

        def edit(records):
            for r in records:
                if r["kind"] == "gate_receipt":
                    change(r["receipt"])
                    r["receipt"] = ed.sign_record(GATE_SEED, r["receipt"])
        code, report = m.w.verify("--gate-public-key", GATE_PUBLIC, root=forge(m.w, edit), witness=False, gate=False)
        assert code == 2 and "RECEIPT_INVALID" in found(report), report["findings"]


def test_a_machine_whose_configuration_names_no_gate_key_is_as_it_was(recorder, tmp_path):
    """The file demo: no gate key, no receipts, no finding for their absence."""
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = run_scenarios.Workspace(str(tmp_path), "scenario_2", recorder, fresh=False)
    with open(os.path.join(w.data, "logchain.state"), encoding="utf-8") as fh:
        root = json.load(fh)["merkle_root"]
    code, report = w.verify(root=root)
    assert (code, report["findings"]) == (0, [])
    assert report["counts"]["gate_receipts"] == 0 and report["counts"]["commands_without_receipt"] == 0
    # Asked to hold the journal to a gate key it does not name, the verifier says so.
    code, report = w.verify("--gate-public-key", GATE_PUBLIC, root=root)
    assert code == 2 and found(report) == ["KEY_MISMATCH"]
