#!/usr/bin/env python3
"""The actuator-side gate. docs/SPEC.md section 4.2.

    actuator_gate.py --link FILE --state FILE --actuator FILE --safe-state JSON --public-key HEX
                     [--gate-key FILE --receipts FILE]

It stands between the recorder and the actuator, on the actuator's side. It holds the
number and hash of the last record it accepted, and passes a command on only when the
command arrives inside a record that extends that chain by exactly one. The action it
passes on is read out of the record. Nothing the recorder says beside the record is
used.

It shares no code with the recorder or the verifier and uses only the Python standard
library. In a real machine this logic belongs in the actuator's own controller. It is
used two ways here:

  - as this program, which reads the messages the recorder wrote to a link file since it
    last ran (the file demo);
  - as the `Gate` class, held inside the simulated robot's own process and given each
    message as it arrives on a ROS topic (ros2/sim_robot.py).

What it checks for each record message:
  - the hash it carries is SHA-256(0x00 || record text), LogChain's leaf hash;
  - the record text is its own canonical form, byte for byte (docs/SPEC.md section 7.1),
    as the verifier requires of every record in the journal. The same signed record in
    any other encoding is refused: its hash would not be the one the journal holds;
  - the record is signed by the recorder: its `sig` is an Ed25519 signature, under the
    public key the gate was started with, of the record's other fields. The gate holds
    the public key only. It cannot sign;
  - the record's `n` is one more than the last accepted, and its `prev` is the last
    accepted hash. The first record ever accepted must be a genesis record with n = 0;
  - for a command record, the outcome and the applied command agree in form.

What it does:
  - an accepted command: the record's `applied` goes to the actuator. A blocked command:
    the safe-state action goes to the actuator;
  - a refused message: the safe-state action goes to the actuator, and the gate's state
    does not move;
  - a safe-state message from the recorder: always obeyed. Stopping needs no record;
  - the deadman, when the gate is given one (`deadman_seconds`, from the machine's
    configuration) and is run against a clock: once it has accepted a record, if no valid
    record follows within that many seconds, the safe-state action goes to the actuator.
    Heartbeat records count, so a quiet recorder that is alive keeps the actuator's last
    command in force and a silent one does not. Only an accepted record counts: refused
    messages and safe-state messages do not. The `Gate` class has this; whoever holds it
    must call `check_deadman` regularly. This program, reading a file after the fact, has
    no clock to run it against and does not;
  - a command that is too old, when the gate is given a limit (`max_command_age_ms`, from
    the machine's configuration) and a wall-clock reading: a command record carries
    `received_ms`, the time the recorder received the command. If that is more than the
    limit before the gate's own clock, or more than the limit after it, the command is
    not carried out and the safe-state action goes to the actuator. The record is still
    taken into the chain, because it is a genuine record and the ones after it follow
    it; only its action is refused. A command with no `received_ms` is refused the same
    way. The gate's clock and the recorder's are the same clock only on one machine:
    across machines this check needs them synchronized, which nothing here does;
  - a receipt, when the gate is given a signing key of its own (docs/SPEC.md section 4.5).
    For every command record it takes into the chain, and for every message it refuses,
    the gate signs a short statement of what it did: applied, blocked, or refused and
    why (`age`, `signature`, `chain` or `form`). A deadman trip gets one too. Receipts are
    numbered from 0 with no gaps. The recorder writes each one into the journal as a
    record, and the verifier reports every refusal, every deadman trip, every command
    with no receipt and every gap in the numbering. The gate signs after it has acted, so
    signing a receipt does not delay the stop that receipt is about. The gate's key is
    not the recorder's: the gate still holds only the public half of the recorder's key
    and cannot make a record.

What it cannot check: that the record it was shown was ever written to the journal. It
keeps its head (state file) so that can be compared with the journal afterwards. And a
signature shows who holds the private key, so anyone who can read the recorder's key file
can make records the gate accepts.

A receipt is the gate's own statement. Anyone who can read the gate's key file can make
one. And the gate sends each receipt once: one that never reaches the journal is noticed
by the verifier, not recovered.

Exit codes: 0 every message accepted, 2 at least one refused, 1 usage or I/O error.
"""
import argparse
import hashlib
import json
import os
import sys


RECEIPT_SCHEMA = "sentinel-ledger/gate-receipt/0"


def leaf_hash(text):
    return hashlib.sha256(b"\x00" + text.encode("utf-8")).hexdigest()


# --- Ed25519, RFC 8032: verification of the recorder's records, and signing of the gate's
# own receipts with the gate's own key. The recorder's private key is never here. ---

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P


def _point_add(a, b):
    f = (a[1] - a[0]) * (b[1] - b[0]) % _P
    g = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    d = 2 * a[2] * b[2] % _P
    e, ff, gg, h = g - f, d - c, d + c, g + f
    return (e * ff % _P, gg * h % _P, ff * gg % _P, e * h % _P)


def _point_mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_from_bytes(data):
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - x2) % _P != 0 or (x == 0 and sign):
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_BASE = _point_from_bytes((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(public, message, signature):
    """True only if `signature` (64 bytes) is a valid Ed25519 signature of `message` under
    the public key `public` (32 bytes)."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _point_from_bytes(public), _point_from_bytes(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    left, right = _point_mul(s, _BASE), _point_add(r, _point_mul(k, a))
    return ((left[0] * right[2] - right[0] * left[2]) % _P == 0
            and (left[1] * right[2] - right[1] * left[2]) % _P == 0)


def _point_to_bytes(point):
    inverse = pow(point[2], _P - 2, _P)
    x, y = point[0] * inverse % _P, point[1] * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(gate_key):
    digest = hashlib.sha512(gate_key).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    return scalar, digest[32:]


def ed25519_public(gate_key):
    """The public key for a 32-byte signing key."""
    return _point_to_bytes(_point_mul(_expand(gate_key)[0], _BASE))


def ed25519_sign(gate_key, message):
    """An Ed25519 signature of `message`, 64 bytes. Plain Python and not constant time: it
    is not written to hide the key from someone who can time it. Measured on one machine
    at about 4 ms a call when the machine is idle and about 11 ms with every processor
    busy (README, "Time spent in the gate"). It runs in the caller's thread, so whatever
    else that thread does waits for it."""
    scalar, prefix = _expand(gate_key)
    public = _point_to_bytes(_point_mul(scalar, _BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    big_r = _point_to_bytes(_point_mul(r, _BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % _L
    return big_r + ((r + k * scalar) % _L).to_bytes(32, "little")


def load_gate_key(path):
    """The gate's own signing key: a file of 64 hexadecimal characters. On Unix the file
    must not be readable by anyone but its owner."""
    if os.name == "posix" and os.stat(path).st_mode & 0o077:
        raise ValueError("gate key file %s is readable by other users" % path)
    with open(path, "r", encoding="utf-8") as fh:
        gate_key = bytes.fromhex(fh.read().strip())
    if len(gate_key) != 32:
        raise ValueError("the gate key file does not hold 32 bytes")
    return gate_key


def signature_ok(record, public_hex):
    """A record's `sig` must be a signature, under the recorder's public key, of the
    canonical form of every other field of the record."""
    sig = record.get("sig")
    if not isinstance(sig, str) or len(sig) != 128:
        return False
    body = {k: v for k, v in record.items() if k != "sig"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    try:
        return ed25519_verify(bytes.fromhex(public_hex), text.encode("utf-8"), bytes.fromhex(sig))
    except ValueError:
        return False


def in_canonical_form(raw, record):
    """True only if `raw` is, byte for byte, the canonical form (docs/SPEC.md section 7.1)
    of `record`, the value parsed from it."""
    try:
        return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) == raw
    except RecursionError:
        # Text can be parsed and still be nested too deeply to write out again. That is
        # no record's canonical form, and it is a refusal, not an error in the gate.
        return False


def judge(message, state, public_key):
    """Returns (record or None, reason for refusal or None, the kind of reason or None).
    The kind is `form` (not a well-formed record message, or a record whose text is not
    in canonical form), `signature` or `chain`."""
    raw, claimed = message.get("record"), message.get("hash")
    if not isinstance(raw, str) or not isinstance(claimed, str):
        return None, "the message carries no record", "form"
    if leaf_hash(raw) != claimed:
        return None, "the hash does not belong to the record", "form"
    try:
        record = json.loads(raw)
    except ValueError:
        return None, "the record is not JSON", "form"
    # The text must be the record's canonical form, byte for byte (docs/SPEC.md section
    # 7.1), which is what the verifier requires of every record in the journal. The
    # signature below is checked over a re-serialisation of the parsed record, so
    # without this line a genuine record sent in another encoding (extra spaces, another
    # key order, a key given twice) would pass it, and the gate's head would become a
    # hash the journal does not hold. It comes before the signature check, with the other
    # checks on the message's form, so a record wrong in both ways is refused for `form`.
    if not in_canonical_form(raw, record):
        return None, "the record is not in canonical form", "form"
    if not isinstance(record, dict) or type(record.get("n")) is not int:
        return None, "the record has no number", "form"
    if message.get("n") != record["n"]:
        return None, "the message's number is not the record's", "form"
    if not signature_ok(record, public_key):
        return record, "the record is not signed by the recorder", "signature"
    if state["n"] < 0:
        if record.get("kind") != "genesis" or record["n"] != 0 or record.get("prev") != "":
            return record, "the first record must be a genesis record", "chain"
    elif record["n"] != state["n"] + 1 or record.get("prev") != state["hash"]:
        return record, ("does not extend the chain: the gate holds record %d (%s...), this is record %d "
                        "after %s..." % (state["n"], state["hash"][:12], record["n"],
                                         str(record.get("prev"))[:12])), "chain"
    if record.get("kind") == "command":
        applied, outcome = record.get("applied"), record.get("outcome")
        if outcome == "blocked":
            if applied is not None:
                return record, "a blocked command that carries an action", "form"
        elif outcome not in ("unchanged", "changed") or not isinstance(applied, dict):
            return record, "a command with no usable action", "form"
    return record, None, None


class Gate:
    """The gate's whole kept state is `n` and `hash`, the last record it accepted, and,
    when it signs receipts, the number of its next receipt. The deadman's clock is not
    kept: it starts again with the process."""

    def __init__(self, state_path, safe_state, public_key, deadman_seconds=None, max_command_age_ms=None,
                 gate_key=None):
        self.state_path = state_path
        self.safe_state = safe_state
        self.public_key = public_key
        self.deadman_seconds = deadman_seconds
        self.max_command_age_ms = max_command_age_ms
        self.gate_key = gate_key   # the gate's own signing key, 32 bytes. None: no receipts
        self.last_valid = None   # when the last record was accepted, on the caller's monotonic clock
        self.tripped = False
        self.state = {"n": -1, "hash": "", "offset": 0}
        if os.path.exists(state_path):
            with open(state_path, "r", encoding="utf-8") as fh:
                self.state = json.load(fh)

    def save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def check_deadman(self, now):
        """Call this regularly with a monotonic clock reading, in seconds. Returns None,
        or, the first time the silence since the last accepted record has passed
        `deadman_seconds`, a decision that sends the safe state."""
        if self.deadman_seconds is None or self.last_valid is None or self.tripped:
            return None
        silent = now - self.last_valid
        if silent <= self.deadman_seconds:
            return None
        self.tripped = True
        detail = "no valid record for %.3f s; the limit is %d s" % (silent, self.deadman_seconds)
        return {"accepted": None, "n": None, "hash": None, "send": self.safe_state, "why": "deadman", "reason": None,
                "silent_seconds": round(silent, 3),
                # Its receipt names the last record the gate had accepted.
                "receipt": {"decision": "deadman", "reason": None, "detail": detail,
                            "n": self.state["n"], "hash": self.state["hash"]}}

    def too_old(self, record, wall_ms):
        """None, or why this command must not be carried out for its age."""
        if self.max_command_age_ms is None or wall_ms is None:
            return None
        received = record.get("received_ms")
        if type(received) is not int:
            return "the command does not say when it was received"
        age = wall_ms - received
        if age > self.max_command_age_ms:
            return "the command is %d ms old; the limit is %d ms" % (age, self.max_command_age_ms)
        if age < -self.max_command_age_ms:
            return "the command is dated %d ms ahead of the gate's clock; the limit is %d ms" % (
                -age, self.max_command_age_ms)
        return None

    def handle(self, message, now=None, wall_ms=None):
        """One message in, one decision out:
        {"accepted": bool, "n": record number or None, "hash": that record's leaf hash or
        None, "send": action for the actuator or None, "why": why that action is sent,
        "reason": why the message was refused, "receipt": what a receipt for this decision
        will say, or None when it gets none}.
        `now` is a monotonic clock reading, for the deadman; leave it out and there is none.
        `wall_ms` is the wall clock in milliseconds since 1970, for a command's age; leave
        it out and no command is refused for its age."""
        if not isinstance(message, dict):
            message = {}
        if message.get("type") == "safe_state":
            return {"accepted": True, "n": None, "hash": None, "send": self.safe_state, "why": "recorder_fault",
                    "reason": None, "receipt": None}
        record, reason, kind = judge(message, self.state, self.public_key)
        if reason:
            receipt = {"decision": "refused", "reason": kind, "detail": reason, "n": None, "hash": None}
            # A record about a receipt, signed by the recorder and out of place in the
            # chain, gets no receipt of its own. Otherwise, once the chain is broken, each
            # refusal would make a receipt, whose record would be refused, whose refusal
            # would make a receipt, without end.
            if kind == "chain" and record.get("kind") == "gate_receipt":
                receipt = None
            return {"accepted": False, "n": None, "hash": None, "send": self.safe_state, "why": "gate_refused",
                    "reason": reason, "receipt": receipt}
        self.state["n"], self.state["hash"] = record["n"], message["hash"]
        if now is not None:
            self.last_valid, self.tripped = now, False
        decision = {"accepted": True, "n": record["n"], "hash": message["hash"], "send": None, "why": None,
                    "reason": None, "receipt": None}
        if record.get("kind") == "command":
            named = {"n": record["n"], "hash": message["hash"]}
            stale = self.too_old(record, wall_ms)
            if stale is not None:
                # The record is in the chain. Its action is not carried out.
                decision.update(accepted=False, send=self.safe_state, why="stale_command", reason=stale,
                                receipt=dict(named, decision="refused", reason="age", detail=stale))
            elif record["outcome"] == "blocked":
                decision.update(send=self.safe_state, why="blocked",
                                receipt=dict(named, decision="blocked", reason=None, detail=None))
            else:
                decision.update(send=record["applied"], why="applied",
                                receipt=dict(named, decision="applied", reason=None, detail=None))
        return decision

    def issue_receipt(self, decision, wall_ms=None):
        """The signed receipt for a decision `handle` or `check_deadman` returned, or None
        when that decision gets none or the gate has no key of its own. Call it after
        acting on the decision and before `save`: the receipt's number is kept in the
        gate's state, so a number is never used twice."""
        about = decision.get("receipt")
        if self.gate_key is None or about is None:
            return None
        seq = self.state.get("receipt_seq", 0)
        self.state["receipt_seq"] = seq + 1
        body = dict(about, schema=RECEIPT_SCHEMA, seq=seq, sent=decision["send"], at_ms=wall_ms)
        text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        signed = dict(body, sig=ed25519_sign(self.gate_key, text.encode("utf-8")).hex())
        return signed


def main(argv=None):
    ap = argparse.ArgumentParser(description="Actuator-side gate for Sentinel Ledger.")
    ap.add_argument("--link", required=True, help="the file the recorder writes its messages to")
    ap.add_argument("--state", required=True, help="where the gate keeps the last accepted number and hash")
    ap.add_argument("--actuator", required=True, help="the simulated actuator: accepted actions are appended here")
    ap.add_argument("--safe-state", required=True, help="the safe-state action, as JSON, set on the actuator side")
    ap.add_argument("--public-key", required=True, help="the recorder's Ed25519 public key, 64 hex characters")
    ap.add_argument("--gate-key", help="the gate's own signing key file; with it the gate signs receipts")
    ap.add_argument("--receipts", help="the file signed receipts are appended to, one a line")
    args = ap.parse_args(argv)
    if bool(args.gate_key) != bool(args.receipts):
        print("error: --gate-key and --receipts go together", file=sys.stderr)
        return 1
    try:
        gate = Gate(args.state, json.loads(args.safe_state), args.public_key,
                    gate_key=load_gate_key(args.gate_key) if args.gate_key else None)
        with open(args.link, "rb") as fh:
            fh.seek(gate.state["offset"])
            pending = fh.read()
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    accepted = refused = 0
    with open(args.actuator, "a", encoding="utf-8", newline="\n") as actuator:
        # Only whole lines are consumed. A line still being written is left for next time.
        for line in pending.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                break
            gate.state["offset"] += len(line)
            try:
                message = json.loads(line.decode("utf-8"))
            except ValueError:
                message = {}
            decision = gate.handle(message)
            if decision["send"] is not None:
                actuator.write(json.dumps({"n": decision["n"], "sent": decision["send"], "why": decision["why"]},
                                          sort_keys=True, separators=(",", ":")) + "\n")
                actuator.flush()
            if decision["reason"]:
                refused += 1
                print("REFUSED: " + decision["reason"])
            elif decision["n"] is not None:
                accepted += 1
            receipt = gate.issue_receipt(decision)
            gate.save()
            if receipt is not None:
                with open(args.receipts, "a", encoding="utf-8", newline="\n") as out:
                    out.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")

    print("gate: %d record(s) accepted, %d refused, head is record %d" % (accepted, refused, gate.state["n"]))
    return 2 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
