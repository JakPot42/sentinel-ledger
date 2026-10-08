#!/usr/bin/env python3
"""The actuator-side gate. docs/SPEC.md section 4.2.

    actuator_gate.py --link FILE --state FILE --actuator FILE --safe-state JSON

It stands between the recorder and the actuator, on the actuator's side. It holds the
number and hash of the last record it accepted, and passes a command on only when the
command arrives inside a record that extends that chain by exactly one. The action it
passes on is read out of the record. Nothing the recorder says beside the record is
used.

It shares no code with the recorder or the verifier and uses only the Python standard
library. In a real machine this logic belongs in the actuator's own controller. Here it
is a program that reads the messages the recorder wrote to the link file since it last
ran, which gives the same answers as running in line because the gate's decisions depend
only on the order of the messages.

What it checks for each record message:
  - the hash it carries is SHA-256(0x00 || record text), LogChain's leaf hash;
  - the record's `n` is one more than the last accepted, and its `prev` is the last
    accepted hash. The first record ever accepted must be a genesis record with n = 0;
  - for a command record, the outcome and the applied command agree in form.

What it does:
  - an accepted command: the record's `applied` goes to the actuator. A blocked command:
    the safe-state action goes to the actuator;
  - a refused message: the safe-state action goes to the actuator, and the gate's state
    does not move;
  - a safe-state message from the recorder: always obeyed. Stopping needs no record.

What it cannot check: that the record it was shown was ever written to the journal. It
keeps its head (state file) so that can be compared with the journal afterwards.

Exit codes: 0 every message accepted, 2 at least one refused, 1 usage or I/O error.
"""
import argparse
import hashlib
import json
import os
import sys


def leaf_hash(text):
    return hashlib.sha256(b"\x00" + text.encode("utf-8")).hexdigest()


def load_state(path):
    if not os.path.exists(path):
        return {"n": -1, "hash": "", "offset": 0}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def judge(message, state):
    """Returns (record or None, reason for refusal or None)."""
    raw, claimed = message.get("record"), message.get("hash")
    if not isinstance(raw, str) or not isinstance(claimed, str):
        return None, "the message carries no record"
    if leaf_hash(raw) != claimed:
        return None, "the hash does not belong to the record"
    try:
        record = json.loads(raw)
    except ValueError:
        return None, "the record is not JSON"
    if not isinstance(record, dict) or type(record.get("n")) is not int:
        return None, "the record has no number"
    if message.get("n") != record["n"]:
        return None, "the message's number is not the record's"
    if state["n"] < 0:
        if record.get("kind") != "genesis" or record["n"] != 0 or record.get("prev") != "":
            return record, "the first record must be a genesis record"
    elif record["n"] != state["n"] + 1 or record.get("prev") != state["hash"]:
        return record, ("does not extend the chain: the gate holds record %d (%s...), this is record %d "
                        "after %s..." % (state["n"], state["hash"][:12], record["n"], str(record.get("prev"))[:12]))
    if record.get("kind") == "command":
        applied, outcome = record.get("applied"), record.get("outcome")
        if outcome == "blocked":
            if applied is not None:
                return record, "a blocked command that carries an action"
        elif outcome not in ("unchanged", "changed") or not isinstance(applied, dict):
            return record, "a command with no usable action"
    return record, None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Actuator-side gate for Sentinel Ledger.")
    ap.add_argument("--link", required=True, help="the file the recorder writes its messages to")
    ap.add_argument("--state", required=True, help="where the gate keeps the last accepted number and hash")
    ap.add_argument("--actuator", required=True, help="the simulated actuator: accepted actions are appended here")
    ap.add_argument("--safe-state", required=True, help="the safe-state action, as JSON, set on the actuator side")
    args = ap.parse_args(argv)
    try:
        safe = json.loads(args.safe_state)
        state = load_state(args.state)
        with open(args.link, "rb") as fh:
            fh.seek(state["offset"])
            pending = fh.read()
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    accepted = refused = 0
    with open(args.actuator, "a", encoding="utf-8", newline="\n") as actuator:
        def send(n, action, why):
            actuator.write(json.dumps({"n": n, "sent": action, "why": why}, sort_keys=True,
                                      separators=(",", ":")) + "\n")
            actuator.flush()

        # Only whole lines are consumed. A line still being written is left for next time.
        for line in pending.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                break
            state["offset"] += len(line)
            try:
                message = json.loads(line.decode("utf-8"))
            except ValueError:
                message = {}
            if isinstance(message, dict) and message.get("type") == "safe_state":
                send(None, safe, "recorder_fault")
            else:
                record, reason = judge(message if isinstance(message, dict) else {}, state)
                if reason:
                    refused += 1
                    send(None, safe, "gate_refused")
                    print("REFUSED: " + reason)
                else:
                    accepted += 1
                    state["n"], state["hash"] = record["n"], message["hash"]
                    if record.get("kind") == "command":
                        if record["outcome"] == "blocked":
                            send(record["n"], safe, "blocked")
                        else:
                            send(record["n"], record["applied"], "applied")
            save_state(args.state, state)

    print("gate: %d record(s) accepted, %d refused, head is record %d" % (accepted, refused, state["n"]))
    return 2 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
