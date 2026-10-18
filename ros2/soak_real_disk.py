#!/usr/bin/env python3
"""Run the ROS 2 scenarios on a real disk, in rounds, and report what was measured.

    . /opt/ros/lyrical/setup.sh
    python3 ros2/soak_real_disk.py --node /path/to/sentinel_recorder_node [--rounds 10] [--dir DIR]

This is not a pass/fail test. The pass/fail runs keep the journal in RAM so that their
result does not depend on the disk (see ros2/run_ros_scenarios.py). This program does the
opposite on purpose: the journal goes to DIR on a real disk, and the report says how long
the disk took to confirm each write, how often that went past the heartbeat threshold, and
what the recorder, the gate and the verifier did about it. Its exit code is 0 whenever it
could run, whatever it measured.

What it reports:
  - flush times, per step, from the node's own trace (SL_TRACE_FILE): how many, the
    median, the 99th percentile, the longest, how many over 0.5 s and over the threshold;
  - storage_stall records the recorder wrote, and the durations they state;
  - deadman trips on the robot's side, and commands the gate refused for their age;
  - the gate's receipts as the journals hold them: how many, what they say, and how many
    of the robot's refusals for age and deadman trips have a receipt in the journal;
  - the actuator's feedback as the journals hold it: how many reports, and how many
    command records have none;
  - verifier findings per scenario, and how many scenarios were not as the pass/fail
    run expects;
  - the independent clock watchdog (ros2/clock_watchdog.py): its largest step, which says
    whether the machine itself paused.
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.path.join(HERE, "run_ros_scenarios.py")
WATCHDOG = os.path.join(HERE, "clock_watchdog.py")
SCENARIOS = list(range(1, 11))   # 11 needs a test build that fakes a slow flush; here the disk is real


def filesystem_of(path):
    best = ("", "unknown", "unknown")
    with open("/proc/mounts", encoding="utf-8") as fh:
        for line in fh:
            device, mount, kind = line.split()[:3]
            if (path == mount or path.startswith(mount.rstrip("/") + "/")) and len(mount) > len(best[0]):
                best = (mount, kind, device)
    return best


def spread(values):
    values = sorted(values)
    if not values:
        return {"count": 0}
    return {"count": len(values), "median_ms": values[len(values) // 2],
            "p99_ms": values[min(len(values) - 1, int(len(values) * 0.99))], "max_ms": values[-1]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Measure the ROS scenarios on a real disk. Not a pass/fail test.")
    ap.add_argument("--node", required=True, help="path to the sentinel_recorder_node binary")
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--dir", default=os.path.join(HERE, "out", "soak"), help="a folder on the disk to measure")
    args = ap.parse_args(argv)
    folder = os.path.abspath(args.dir)
    os.makedirs(folder, exist_ok=True)
    mount, kind, device = filesystem_of(folder)
    print("journal folder: %s (%s on %s, mounted at %s)" % (folder, kind, device, mount))
    if kind in ("tmpfs", "ramfs"):
        print("warning: that is RAM, not a disk. The numbers below will say nothing about a disk.")

    scratch = tempfile.mkdtemp(prefix="sentinel-ledger-soak-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None)
    trace_path, watch_path = os.path.join(scratch, "trace.log"), os.path.join(scratch, "watchdog.log")
    watchdog = subprocess.Popen([sys.executable, WATCHDOG, watch_path])
    env = dict(os.environ, SL_TRACE_FILE=trace_path)
    with open(os.path.join(HERE, "installed", "config.json"), encoding="utf-8") as fh:
        threshold_ms = 2 * json.load(fh)["heartbeat_seconds"] * 1000

    rounds, findings, stalls, receipts = [], collections.Counter(), [], collections.Counter()
    deadman_trips = stale_commands = unexpected = scenarios_run = 0
    commands = reports = unreported = 0
    started = time.monotonic()
    try:
        for number in range(1, args.rounds + 1):
            out = os.path.join(folder, "round_%02d" % number)
            done = subprocess.run([sys.executable, DRIVER, "--node", args.node, "--out", out] +
                                  [], capture_output=True, text=True, env=env)
            with open(os.path.join(out, "driver_output.txt"), "w", encoding="utf-8") as fh:
                fh.write(done.stdout + done.stderr)
            try:
                with open(os.path.join(out, "results.json"), encoding="utf-8") as fh:
                    results = json.load(fh)
            except (OSError, ValueError):
                results = {"scenarios": {}, "not_as_expected": None}
            off = [line.split(":")[0].replace("ROS scenario ", "") for line in done.stdout.splitlines()
                   if "NOT AS EXPECTED" in line]
            for name, observed in results["scenarios"].items():
                scenarios_run += 1
                for key in ("findings", "findings_after_restart"):
                    for finding in observed.get(key) or []:
                        findings["scenario %s: %s" % (name, finding)] += 1
                where = os.path.join(out, "ros_scenario_%s" % name)
                try:
                    with open(os.path.join(where, "data", "logchain.journal"), encoding="utf-8") as fh:
                        journal = [json.loads(json.loads(line)["raw"]) for line in fh]
                        reported = {r["feedback"]["n"] for r in journal if r.get("kind") == "actuator_feedback"}
                        mine = [r["n"] for r in journal if r.get("kind") == "command"]
                        commands += len(mine)
                        reports += sum(r.get("kind") == "actuator_feedback" for r in journal)
                        unreported += sum(n not in reported for n in mine)
                        for record in journal:
                            if record.get("kind") == "storage_stall":
                                stalls.append({"round": number, "scenario": int(name), "step": record["step"],
                                               "stalled_ms": record["stalled_ms"]})
                            if record.get("kind") == "gate_receipt":
                                said = record["receipt"]
                                receipts[said["decision"] + (":" + said["reason"] if said["reason"] else "")] += 1
                    with open(os.path.join(where, "robot_side", "actuator.jsonl"), encoding="utf-8") as fh:
                        whys = [json.loads(line).get("why") for line in fh]
                    deadman_trips += whys.count("deadman")
                    stale_commands += whys.count("stale_command")
                except (OSError, ValueError, KeyError):
                    pass
            unexpected += len(off)
            rounds.append({"round": number, "driver_exit": done.returncode, "not_as_expected": off})
            print("round %2d: %d scenario(s) run, not as the pass/fail run expects: %s"
                  % (number, len(results["scenarios"]), ", ".join(off) or "none"), flush=True)
    finally:
        watchdog.terminate()
        watchdog.wait()

    # The node's trace: one line per storage step, with how long it took.
    steps, waits, last = collections.defaultdict(list), [], {}
    try:
        with open(trace_path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(" ", 4)
                if len(parts) != 5 or parts[3] != "step":
                    continue
                detail = json.loads(parts[4])
                steps[detail["step"]].append(detail["ms"])
                if detail["step"] == "journal_fsync":
                    if parts[2] in last:
                        waits.append(float(parts[0]) - last[parts[2]])
                    last[parts[2]] = float(parts[0])
    except OSError:
        pass
    flush = {}
    for step, values in sorted(steps.items()):
        flush[step] = dict(spread(values), over_500_ms=sum(v > 500 for v in values),
                           over_threshold=sum(v > threshold_ms for v in values))
    clock_rows = []
    try:
        with open(watch_path, encoding="utf-8") as fh:
            clock_rows = [[float(x) for x in line.split()] for line in fh if len(line.split()) == 4]
    except OSError:
        pass
    clock_steps = [b[1] - a[1] for a, b in zip(clock_rows, clock_rows[1:])]
    report = {
        "what": "measurements on a real disk; not a pass/fail result",
        "folder": folder, "filesystem": kind, "device": device, "rounds": args.rounds,
        "seconds": round(time.monotonic() - started), "scenarios_run": scenarios_run,
        "threshold_ms": threshold_ms, "flush_times": flush,
        "longest_waits_between_records_s": [round(w, 3) for w in sorted(waits, reverse=True)[:5]],
        "waits_between_records_over_threshold": sum(w * 1000 > threshold_ms for w in waits),
        "storage_stall_records": stalls, "deadman_trips": deadman_trips, "stale_commands_refused": stale_commands,
        "gate_receipts_in_the_journals": dict(sorted(receipts.items())),
        "command_records": commands, "feedback_reports": reports, "commands_without_feedback": unreported,
        "verifier_findings": dict(sorted(findings.items())),
        "scenarios_not_as_the_pass_fail_run_expects": unexpected, "per_round": rounds,
        "watchdog": {"lines": len(clock_rows), "largest_step_s": round(max(clock_steps), 3) if clock_steps else None,
                     "steps_over_300_ms": sum(s > 0.3 for s in clock_steps)},
    }
    with open(os.path.join(folder, "soak_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, sort_keys=True)

    print("\nMEASURED over %d round(s), %d scenario run(s), %d s, on %s:" % (args.rounds, scenarios_run, report["seconds"], kind))
    for step, f in flush.items():
        print("  %-20s %5d times: median %.1f ms, 99th %.1f ms, longest %.1f ms; over 0.5 s: %d; over %d s: %d"
              % (step, f["count"], f["median_ms"], f["p99_ms"], f["max_ms"], f["over_500_ms"], threshold_ms // 1000,
                 f["over_threshold"]))
    print("  longest waits between one record and the next: %s s; over %d s: %d"
          % (report["longest_waits_between_records_s"], threshold_ms // 1000, report["waits_between_records_over_threshold"]))
    print("    (scenario 10 freezes the recorder for ten seconds on purpose, once a round)")
    print("  storage_stall records written by the recorder: %d %s"
          % (len(stalls), [s["stalled_ms"] for s in stalls] if stalls else ""))
    print("  deadman trips on the robot: %d (scenario 10 causes one in every round on purpose)" % deadman_trips)
    print("  commands the gate refused for their age: %d" % stale_commands)
    print("  the gate's receipts in the journals: %d %s" % (sum(receipts.values()), dict(sorted(receipts.items()))))
    print("    of the %d refusals for age the robot logged, %d have a receipt in a journal; of the %d deadman trips, %d"
          % (stale_commands, receipts["refused:age"], deadman_trips, receipts["deadman"]))
    print("  command records: %d; actuator feedback reports: %d; commands with none: %d" % (commands, reports, unreported))
    print("  verifier findings (expected every round: HEARTBEAT_GAP in scenarios 5 and 10, GATE_DEADMAN in 10,")
    print("  GATE_REFUSED in 6 to 9, ANCHOR_FAILED in 12; anything else is the disk):")
    for name, count in sorted(findings.items()):
        print("    %-34s %d" % (name, count))
    print("  scenarios not as the pass/fail run expects: %d of %d" % (unexpected, scenarios_run))
    print("  clock watchdog: %d lines, largest step %s s, steps over 0.3 s: %d"
          % (report["watchdog"]["lines"], report["watchdog"]["largest_step_s"], report["watchdog"]["steps_over_300_ms"]))
    print("report: %s" % os.path.join(folder, "soak_report.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
