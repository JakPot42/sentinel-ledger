#!/usr/bin/env python3
"""Run the five demo scenarios on the simulated one-axis conveyor and judge each one by
exit codes.

    python demo/run_scenarios.py [--recorder PATH] [--out DIR] [--only N]

Each scenario runs four separate programs, the way a deployment would:

  recorder   writes the journal and sends each record down the link
  gate       on the actuator's side: passes a command on only if its record extends the chain
  witness    a process that stores the roots it is sent (stands in for another party)
  verifier   checks the journal against the witness's roots, the gate's head and the rules

Exit 0 only if every observation of every scenario is the expected one.

  1  clean run: commands inside the limits, a quiet period covered by heartbeats
  2  the speed clamp changes commands
  3  the light curtain blocks commands and the actuator gets the safe state
  4  a declared ruleset upload, an undeclared firmware change found by measurement,
     decision data, the EU profile, a receipt
  5  the recorder cannot write: the command is not forwarded, the actuator gets the
     safe state; then the recorder is restarted
"""
import argparse
import json
import os
import shutil
import stat
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EXE = "sentinel-recorder.exe" if os.name == "nt" else "sentinel-recorder"
DEFAULT_RECORDER = os.path.join(REPO, "recorder", "target", "debug", EXE)
VERIFIER = os.path.join(REPO, "verifier", "verify_journal.py")
GATE = os.path.join(REPO, "gate", "actuator_gate.py")
WITNESS = os.path.join(REPO, "witness", "witness.py")
ANCHOR = os.path.join(REPO, "anchor", "anchor_roots.py")
CHECK_ACTUATOR = os.path.join(HERE, "check_actuator.py")
PROFILE = os.path.join(REPO, "profiles", "eu_2023_1230_annex_iii.json")
RULESET_V2 = os.path.join(HERE, "changes", "ruleset_v2.json")
CLEAR = {"light_curtain_clear": 1}
# Set on the actuator's side. The gate does not take the recorder's word for it.
SAFE_STATE = '{"speed_mm_s": 0}'


def python(*args):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True)


class Workspace:
    """One scenario's own copy of the installed files, an empty data directory, a gate
    and a witness. `fresh=False` attaches to a scenario that has already run."""

    def __init__(self, out, name, recorder, fresh=True):
        self.recorder = recorder
        self.dir = os.path.join(out, name)
        self.installed = os.path.join(self.dir, "installed")
        self.data = os.path.join(self.dir, "data")
        self.journal = os.path.join(self.data, "logchain.journal")
        self.link = os.path.join(self.dir, "link.jsonl")
        self.gate_state = os.path.join(self.dir, "actuator_side", "gate.state")
        self.actuator = os.path.join(self.dir, "actuator_side", "actuator.jsonl")
        self.witness_store = os.path.join(self.dir, "witness_side", "roots.jsonl")
        self.gate_exits = []
        self.witness = self.witness_port = None
        if fresh:
            if os.path.isdir(self.dir):
                for folder, _, files in os.walk(self.dir):
                    for f in files:
                        os.chmod(os.path.join(folder, f), stat.S_IWRITE | stat.S_IREAD)
                shutil.rmtree(self.dir)
            shutil.copytree(os.path.join(HERE, "installed"), self.installed)
            os.makedirs(os.path.dirname(self.gate_state))
            os.makedirs(os.path.dirname(self.witness_store))

    # -- the witness: a separate process, started before the recorder -------------------

    def start_witness(self):
        self.witness = subprocess.Popen([sys.executable, WITNESS, "serve", "--store", self.witness_store],
                                        stdout=subprocess.PIPE, text=True)
        self.witness_port = json.loads(self.witness.stdout.readline())["listening"]

    def stop_witness(self):
        if self.witness is not None:
            self.witness.kill()
            self.witness.wait()
            self.witness.stdout.close()
            self.witness = None

    def submit_anchors(self):
        """Send any new anchor statements to the witness. Returns the exit code."""
        if self.witness is None:
            return None
        return python(ANCHOR, "submit", "--dir", self.data, "--witness",
                      "127.0.0.1:%d" % self.witness_port).returncode

    def anchors_held_by_witness(self):
        if not os.path.exists(self.witness_store):
            return 0
        with open(self.witness_store, "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    # -- the recorder and the gate ----------------------------------------------------

    def run_args(self, start_at):
        return [self.recorder, "run", "--dir", self.data, "--installed", self.installed,
                "--link", self.link, "--start-at", start_at]

    def gate(self):
        """Let the gate process whatever the recorder has sent. Returns its exit code."""
        code = python(GATE, "--link", self.link, "--state", self.gate_state, "--actuator", self.actuator,
                      "--safe-state", SAFE_STATE).returncode
        self.gate_exits.append(code)
        return code

    def record(self, ops, start_at):
        """One run of the recorder, then the gate, then delivery of anchors.
        Returns (recorder exit code, the recorder's replies)."""
        text = "".join(json.dumps(op) + "\n" for op in ops)
        done = subprocess.run(self.run_args(start_at), input=text, capture_output=True, text=True)
        self.gate()
        self.submit_anchors()
        return done.returncode, [json.loads(line) for line in done.stdout.splitlines() if line.strip()]

    # -- checks -----------------------------------------------------------------------

    def verify(self, *extra, root=None, witness=True, gate=True):
        """Run the verifier. Returns (exit code, its JSON report or {})."""
        args = [VERIFIER, self.journal, "--rulesets", os.path.join(self.data, "rulesets"),
                "--decisions", os.path.join(self.data, "decisions"), "--json"]
        if root is not None:
            args += ["--root", str(root)]
        if witness:
            args += ["--witness-store", self.witness_store]
        if gate:
            args += ["--gate-state", self.gate_state]
        done = python(*args, *extra)
        try:
            return done.returncode, json.loads(done.stdout)
        except ValueError:
            return done.returncode, {}

    def check_actuator(self):
        return python(CHECK_ACTUATOR, self.journal, self.actuator).returncode

    def actuator_lines(self):
        if not os.path.exists(self.actuator):
            return []
        with open(self.actuator, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def sent(self):
        return [(a["why"], a["sent"]["speed_mm_s"]) for a in self.actuator_lines()]


def command(speed, inputs=CLEAR, **more):
    return dict({"op": "command", "requested": {"speed_mm_s": speed}, "safety_inputs": inputs}, **more)


def kinds(report):
    return sorted({f["finding"] for f in report.get("findings", [])})


def common(w, recorder_exit, v_exit, report):
    return {"recorder_exit": recorder_exit, "gate_exit": max(w.gate_exits), "verifier_exit": v_exit,
            "findings": kinds(report), "anchors_held_by_witness": w.anchors_held_by_witness()}


def scenario_1(w):
    ops = [command(s) for s in (200, 400, 600, 800, 1000)]
    ops += [{"op": "tick", "seconds": 150}, command(900), command(300)]
    exit_code, replies = w.record(ops, "2026-10-01T08:00:00Z")
    v_exit, report = w.verify(root=replies[-1].get("root"))
    counts = report.get("counts", {})
    return dict(common(w, exit_code, v_exit, report), commands=counts.get("commands"),
                unchanged=counts.get("unchanged"), heartbeats=counts.get("heartbeats"))


def scenario_2(w):
    exit_code, replies = w.record([command(s) for s in (800, 1800, -50, 1500)], "2026-10-01T08:00:00Z")
    v_exit, report = w.verify(root=replies[-1].get("root"))
    counts = report.get("counts", {})
    return dict(common(w, exit_code, v_exit, report), changed=counts.get("changed"),
                unchanged=counts.get("unchanged"), sent=w.sent())


def scenario_3(w):
    ops = [command(500), command(500, {"light_curtain_clear": 0}), command(700, {}), command(500)]
    exit_code, replies = w.record(ops, "2026-10-01T08:00:00Z")
    v_exit, report = w.verify(root=replies[-1].get("root"))
    return dict(common(w, exit_code, v_exit, report), blocked=report.get("counts", {}).get("blocked"),
                sent=w.sent())


def scenario_4(w):
    def decision(obstacle_mm):
        return {"model": "demo-planner", "model_version": "0.3.1", "nearest_obstacle_mm": obstacle_mm,
                "confidence_per_mille": 970, "inputs_used": ["lidar_front", "encoder_belt"]}

    first = [command(400, decision=decision(2400)), command(600, decision=decision(3100)),
             {"op": "declare", "target": "ruleset", "file": RULESET_V2,
              "operator": "demo-operator-1", "reference": "CHG-0001"},
             command(1200)]
    exit_a, replies_a = w.record(first, "2026-10-01T08:00:00Z")

    # Between the two runs someone changes the installed firmware without telling the
    # recorder. Nothing is declared.
    with open(os.path.join(w.installed, "software", "conveyor_safety_fw.bin"), "ab") as fh:
        fh.write(b"patched outside the change process\n")

    exit_b, replies_b = w.record([command(900, decision=decision(1800)), command(500)], "2026-10-02T08:00:00Z")
    root = replies_b[-1].get("root")
    profile = ("--profile", PROFILE, "--anchors", os.path.join(w.data, "anchors"))
    v_exit, report = w.verify(*profile, "--as-of", "2026-12-01", root=root)
    counts = report.get("counts", {})
    obs = dict(common(w, max(exit_a, exit_b), v_exit, report), level_reached=report.get("level_reached"),
               declared=counts.get("interventions_declared"), detected=counts.get("interventions_detected"),
               changed=counts.get("changed"), decisions_checked=counts.get("decisions_checked"))

    # A receipt for the declared intervention (record 4), checked with and without the
    # right root.
    receipt = os.path.join(w.dir, "receipt-4.json")
    made = subprocess.run([w.recorder, "receipt", "--dir", w.data, "--n", "4"], capture_output=True, text=True)
    with open(receipt, "w", encoding="utf-8") as fh:
        fh.write(made.stdout)
    for name, with_root in (("receipt_exit", root), ("receipt_exit_old_root", replies_a[-1].get("root"))):
        obs[name] = python(VERIFIER, "--receipt", receipt, "--root", str(with_root)).returncode

    # Retention: remove one decision file. Inside its one-year period that is a
    # finding. After the period it is not.
    with open(w.journal, encoding="utf-8") as fh:
        first_decision = json.loads(json.loads(fh.readlines()[2])["raw"])
    os.remove(os.path.join(w.data, "decisions", first_decision["decision_sha256"] + ".json"))
    inside, report_inside = w.verify(*profile, "--as-of", "2026-12-01", root=root)
    after, _ = w.verify(*profile, "--as-of", "2028-01-01", root=root)
    obs.update({"missing_decision_inside_period_exit": inside, "missing_decision_findings": kinds(report_inside),
                "missing_decision_after_period_exit": after})
    return obs


def scenario_5(w):
    proc = subprocess.Popen(w.run_args("2026-10-01T08:00:00Z"), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)

    def send(op):
        proc.stdin.write(json.dumps(op) + "\n")
        proc.stdin.flush()
        reply = json.loads(proc.stdout.readline())
        w.gate()
        return reply

    replies = [send(command(500)), send(command(700))]
    # The journal becomes unwritable while the recorder is running. This is a real
    # failed write, not a simulated one.
    os.chmod(w.journal, stat.S_IREAD)
    try:
        replies += [send(command(900)), send(command(300))]
        proc.stdin.close()
        exit_code = proc.wait(timeout=30)
        proc.stdout.close()
    finally:
        os.chmod(w.journal, stat.S_IWRITE | stat.S_IREAD)
    w.gate()
    w.submit_anchors()
    v_exit, report = w.verify()
    obs = dict(common(w, exit_code, v_exit, report), replies_ok=[r.get("ok") for r in replies],
               commands_recorded=report.get("counts", {}).get("commands"))

    # The fault is cleared and the recorder is started again. The gate lets it carry on
    # only if its first record follows the last one the gate accepted.
    restart_exit, restart_replies = w.record([command(400)], "2026-10-01T08:01:00Z")
    v_after, report_after = w.verify(root=restart_replies[-1].get("root"))
    obs.update({"restart_exit": restart_exit, "gate_exit_after_restart": w.gate_exits[-1],
                "verifier_exit_after_restart": v_after, "findings_after_restart": kinds(report_after),
                "sent": w.sent()})
    return obs


SCENARIOS = {1: scenario_1, 2: scenario_2, 3: scenario_3, 4: scenario_4, 5: scenario_5}

CLEAN = {"recorder_exit": 0, "gate_exit": 0, "verifier_exit": 0, "findings": []}
EXPECTED = {
    1: dict(CLEAN, anchors_held_by_witness=3, commands=7, unchanged=7, heartbeats=2),
    2: dict(CLEAN, anchors_held_by_witness=2, changed=2, unchanged=2,
            sent=[("applied", 800), ("applied", 1500), ("applied", 0), ("applied", 1500)]),
    3: dict(CLEAN, anchors_held_by_witness=2, blocked=2,
            sent=[("applied", 500), ("blocked", 0), ("blocked", 0), ("applied", 500)]),
    4: dict(CLEAN, anchors_held_by_witness=4, level_reached=3, declared=1, detected=1, changed=1,
            decisions_checked=3, receipt_exit=0, receipt_exit_old_root=2,
            missing_decision_inside_period_exit=2, missing_decision_findings=["RETENTION_SHORTFALL"],
            missing_decision_after_period_exit=0),
    5: dict(CLEAN, recorder_exit=3, anchors_held_by_witness=2, replies_ok=[True, True, False, False],
            commands_recorded=2, restart_exit=0, gate_exit_after_restart=0, verifier_exit_after_restart=0,
            findings_after_restart=[],
            sent=[("applied", 500), ("applied", 700), ("recorder_fault", 0), ("recorder_fault", 0),
                  ("applied", 400)]),
}
# The witness holds 1 anchor when scenario 5 is first verified and 2 after the restart;
# the count is read at the first verification.
EXPECTED[5]["anchors_held_by_witness"] = 1


def run_scenario(number, recorder=DEFAULT_RECORDER, out=None):
    w = Workspace(out or os.path.join(HERE, "out"), "scenario_%d" % number, recorder)
    w.start_witness()
    try:
        return SCENARIOS[number](w)
    finally:
        w.stop_witness()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the five demo scenarios and judge them by exit code.")
    ap.add_argument("--recorder", default=DEFAULT_RECORDER, help="path to the sentinel-recorder binary")
    ap.add_argument("--out", default=os.path.join(HERE, "out"), help="where scenario files are written")
    ap.add_argument("--only", type=int, choices=sorted(SCENARIOS), help="run one scenario")
    args = ap.parse_args(argv)
    args.recorder = os.path.abspath(args.recorder)
    if not os.path.exists(args.recorder):
        print("error: no recorder at %s. Build it first: cargo build (in recorder/)." % args.recorder,
              file=sys.stderr)
        return 1

    numbers = [args.only] if args.only else sorted(SCENARIOS)
    failed = 0
    for number in numbers:
        observed = run_scenario(number, args.recorder, args.out)
        wrong = {k: v for k, v in EXPECTED[number].items() if observed.get(k) != v}
        print("scenario %d: %s" % (number, "as expected" if not wrong else "NOT AS EXPECTED"))
        for key, value in observed.items():
            print("  %s%-38s %s" % ("! " if key in wrong else "  ", key, json.dumps(value)))
            if key in wrong:
                print("    %-38s %s" % ("expected", json.dumps(wrong[key])))
        failed += bool(wrong)
    print("%d of %d scenario(s) as expected" % (len(numbers) - failed, len(numbers)))
    return 0 if not failed else 2


if __name__ == "__main__":
    sys.exit(main())
