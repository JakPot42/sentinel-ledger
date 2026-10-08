#!/usr/bin/env python3
"""Compare the demo actuator's log with the journal.

    check_actuator.py JOURNAL ACTUATOR_LOG

The demo actuator is a file the recorder appends every forwarded action to. This script
checks the one-way claim in docs/SPEC.md section 4: every action the actuator received
for a command has a record in the journal that says the same thing.

It is a demo aid and not part of the verifier. A real actuator keeps no such log, which is
why the specification says the verifier cannot establish what reached the actuator.

Exit codes: 0 every forwarded action has its record, 2 at least one does not, 1 error.
"""
import json
import sys


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 1
    try:
        records = {}
        with open(argv[1], "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(json.loads(line)["raw"])
                    records[rec["n"]] = rec
        with open(argv[2], "r", encoding="utf-8") as fh:
            sent = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    problems = []
    counts = {"applied": 0, "blocked": 0, "recorder_fault": 0}
    for position, action in enumerate(sent):
        why = action.get("why")
        counts[why] = counts.get(why, 0) + 1
        if why == "recorder_fault":
            continue
        rec = records.get(action.get("n"))
        if rec is None or rec.get("kind") != "command":
            problems.append("action %d (%s): no command record %r in the journal"
                            % (position, json.dumps(action["sent"]), action.get("n")))
        elif why == "applied" and rec["applied"] != action["sent"]:
            problems.append("action %d: the actuator got %s, record %d says %s"
                            % (position, json.dumps(action["sent"]), rec["n"], json.dumps(rec["applied"])))
        elif why == "blocked" and rec["outcome"] != "blocked":
            problems.append("action %d: sent as a block, record %d says %s" % (position, rec["n"], rec["outcome"]))

    print("actions sent to the actuator: %d applied, %d safe state after a block, %d safe state after a fault"
          % (counts["applied"], counts["blocked"], counts["recorder_fault"]))
    for p in problems:
        print("  FORWARDED_WITHOUT_RECORD " + p)
    print("EVERY FORWARDED ACTION HAS ITS RECORD" if not problems else "%d PROBLEM(S)" % len(problems))
    return 2 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
