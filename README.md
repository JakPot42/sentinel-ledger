# Sentinel Ledger

Sentinel Ledger is a recorder designed to sit in a machine's command path. It writes a
signed record of each command, waits for the disk to confirm it, and only then sends the
record on. A gate on the actuator's side passes a command to the actuator only if it
arrives inside a record the recorder signed and that follows the last record the gate
accepted. The journal is tamper-evident, and its roots can be anchored outside the
operator's control, with a witness that stores them or an RFC 3161 timestamp.

That is the design. What exists is a first build on a simulated machine, and in this
build:

- the file demo's gate is not in line. It reads the recorder's messages from a file after
  they are written. In the ROS 2 version the gate is inside a simulated robot whose only
  command input goes through it;
- the witness is a local process on the same machine, and the timestamp path was tested
  with a throwaway authority made by openssl. FreeTSA has not been called. No root in any
  run here was held outside the operator's control;
- the ROS 2 scenarios use no witness and no timestamps.

The record of what was commanded is complete by construction, without trusting the
operator to log, only under two conditions: the gate is in line, and the actuator has no
other input. Neither has been shown on a real machine. Even then the gate cannot see
whether a record reached the disk. That is checked afterwards, and it is the first limit
below.

It is not certified, it is not a safety system, and it cannot see anything that does not
pass through it. The limits are listed below, before any result is reported.

I designed Sentinel Ledger and directed its build. The code was written with an AI coding
assistant; I reviewed the specification, the results and this README.

## What it does

For every command, in this order: take the command the controller requested, get the
command the safety layer applied and the rules that acted, write one record, flush it to
disk, and only then send the record to a gate on the actuator's side. The gate passes the
command on only if the record is signed by the recorder, is written in its one canonical
form, and extends the chain of records it has already seen. In the ROS 2 version the gate
also has a deadman (no valid record for a configured time means the safe state) and a
limit on a command's age (a command that reaches it too long after the recorder received
it is not carried out). And the gate answers: for every command record, and for every
message it refuses, it signs a receipt saying what it did, with a key of its own, and the
recorder writes that receipt into the journal. A command the gate refused is in the
journal as refused, with the reason. And the robot reports back: after each command the
gate takes in, the robot reads what its wheels then did and where odometry puts it, signs
that with a third key, and the recorder writes it into the journal under the command it
follows.

Each record holds:

- the requested command and the applied command, both, and which safety rule changed or
  blocked it. A request for 1800 mm/s clamped to 1500 is recorded as 1800 requested, 1500
  applied;
- a hash naming the software versions, ruleset and configuration in force at that moment;
- optionally, the data an autonomous decision was based on, stored beside the journal;
- an Ed25519 signature made with the recorder's private key. The gate and the verifier
  hold only the public key.

Changes to safety software, rules or configuration are records too. A change made through
the recorder is one kind. A change the recorder finds by hashing the installed files is
another. The recorder does not say which changes were proper.

A verifier, written in a different language from the recorder and sharing no code with it,
checks the chain, every signature and every anchored root, replays the journal to work
out what was in force for each command, and recomputes which rule acted. Where the gate
signs receipts, it reports every refusal, every deadman trip, and every command that no
receipt answers for. Where the robot signs feedback, it reports every command with no
report, and every report that is not genuine or is filed under a command it does not
belong to. It does not judge whether the actuator did what it was told.

The journal is a [LogChain](https://github.com/JakPot42/logchain) version 2 journal,
unchanged. `docs/SPEC.md` is the full specification, written so that someone can build a
second verifier from it without reading the code.

## Limits

Read these before relying on anything above.

- **The gate cannot see whether a record reached the disk.** With this recorder, one
  unrecorded command can pass before the gap shows: the recorder stops at the first failed
  write, and when it restarts the gate refuses it. It would be wrong to say "never more
  than one" of the gate itself. A recorder that forwarded first, ignored failed writes and
  kept its chain in memory would get every command through until the gate's head was
  compared with the journal. Both cases are tests here, and in both the comparison catches
  it afterwards.
- **The gate is not yet in line.** It is a Python program that reads the recorder's
  messages from a file after they are written. In a real machine this logic belongs in the
  actuator's controller.
- **The safety layer is inside the recorder.** The demo recorder evaluates the declared
  rules itself. A real safety layer is a separate component, and the check that compares
  what it reported with what the rules give has only been exercised on forged journals.
- **The witness runs on the same machine in the demo.** That shows the mechanism and
  nothing about custody. A witness proves something only when someone other than the
  journal's keeper runs it.
- **No power-loss test.** The recorder asks the operating system to flush after every
  record. Whether a flush that reports success survives a power cut on a given disk has
  not been tested.
- **A slow disk stops the recorder for as long as it is slow.** A record is not written
  until the disk confirms it, and nothing else can be recorded while the recorder waits.
  On WSL 2 we measured confirmations of up to 7.8 seconds on an otherwise idle machine.
  See "When the disk is slow" below for what the robot does and what the journal shows.
- **The limit on a command's age compares two clocks.** The gate refuses a command older
  than `gate_max_command_age_ms`, measured from the time the recorder received it, which
  is in the record, to the gate's own clock. On one machine those are the same clock.
  Across separate machines the check is only as good as the clocks agree, and it needs
  them synchronized. We do not build or test clock synchronization.
- **Command age does not count time spent queued before the node saw the command.** The
  age starts when the recorder's own code first sees the Twist, not when the controller
  sent it. A Twist carries no time stamp, so time it spent waiting in the controller or in
  a ROS 2 queue before that is invisible to the gate.
- **A stall while writing the stop record is never stated.** Nothing is written after the
  stop record, so a slow write of the stop record itself gets no `storage_stall` record.
- **Loss of the last anchor is never stated.** The last anchor statement is written after
  the stop record. If it cannot be written there is no `anchor_failed` record for it,
  for the same reason. The verifier still reports how many records come after the last
  anchor it found.
- **Anyone who can read the private key file can forge.** Records are signed, and that
  stops a node or a person without the key. It does not stop the operator, or anything
  running as the recorder's user. The key is an ordinary file. Key rotation and hardware
  key storage are out of scope. On Windows the recorder does not check who can read it.
- **The gate's and the verifier's Ed25519 is written here, in plain Python.** It is not a
  reviewed library. The tests check it against two test vectors from RFC 8032 (section
  7.1, tests 1 and 2) and altered copies of those two, and against nothing else. It is
  not constant time: the gate signs its receipts with it, and nothing hides the gate's
  key from someone who can time those signatures. The recorder signs with the
  `ed25519-dalek` library.
- **Without the machine's public key, a journal re-signed with any key verifies.** The
  verifier then takes the key from the journal's first record. See "Tampering, and what
  anchoring changes" below.
- **A rewrite by someone who holds the key verifies if nothing outside is consulted.**
  Rewrite a record, sign it again, repair every hash, the root and the local anchor
  statements, and the journal has no findings, unless the verifier is given a root, a
  witness's store or the gate's state that the rewriter could not reach. See the table
  below.
- **A feedback report is the controller's word.** It says what the robot's controller
  reports the actuator did, signed with the feedback key. An actuator that fails without
  its controller noticing is reported as working. No real encoder or odometry has been
  read: in the ROS 2 demo the wheels are simulated and do exactly what they are given,
  unless a test switch makes them stick.
- **The verifier does not judge whether the actuator obeyed.** It checks that each report
  is genuine and filed under the right command. Where what was measured differs from what
  was sent, the journal shows it and the verifier says nothing: scenario 13, whose wheels
  never turn, exits 0. Judging it needs a tolerance for each machine, and none is set.
- **One reading per command.** It is taken about one control step after the command was
  given. What the actuator did later, while the same command stayed in force, is not
  recorded.
- **The check for a late reading assumes one clock.** A report read after the gate's next
  action is a finding, judged by comparing the report's time with the time on the gate's
  next receipt. In every test both come from one process. On separate clocks, a late
  reading could pass and a timely one could be reported as late.
- **Each command is now three records and three flushes to disk:** the command, the
  gate's receipt and the actuator's report. In the soak of 18 October 2026 (below) the
  journal was flushed 1,437 times, against 993 on 10 October, when a command was two
  records. The median flush was 4.1 ms; 57 took over half a second (37 on 10 October)
  and none reached the 4 second threshold. That is one soak on one disk.
- **All three keys are files on one machine, owned by one user, in every test.** The
  recorder's key, the gate's key and the feedback key separate components, not
  custodians. Anyone who can read the feedback key's file can sign reports.
- **Hashing says nothing about truth or omission.** A journal that was never written, a
  safety input that was wrong, decision data that left something out: none of these is
  detectable from the journal.
- **Not built:** key rotation, hardware key storage, more than one witness, a witness
  that signs what it stores, consistency proofs between roots, journal rotation. FreeTSA has not been called; the timestamp path was tested with a
  throwaway authority made by openssl.
- The file demo runs on Windows 11 and on Ubuntu 26.04 under WSL 2. The ROS 2 part has
  run only on Ubuntu 26.04 under WSL 2, with ROS 2 Lyrical and rclrs 0.8. No real robot,
  no second machine, no other ROS distribution.

### Limits of the ROS 2 version

What it covers: a recorder node that takes `geometry_msgs/Twist` on `cmd_vel_in` and
publishes only recorded commands on `cmd_vel_out`, each carrying its record's text,
number and hash; a simulated robot, in a separate process, with the gate inside it; a
heartbeat on its own thread; a deadman in the gate, so that a silent recorder means a
stopped robot; a limit on a command's age, so that a command held up for seconds is not
carried out late; signed receipts from the gate, written into the journal, so that what
the gate refused and when its deadman tripped are findings in the verifier's report.

What it does not cover:

- **A node that can read the recorder's private key file can forge records the robot
  accepts.** A node without it cannot: scenarios 7 to 9 are a forged, correctly chained
  record with a lifted signature, with the forger's own key, and with no signature, and
  the robot refuses all three.
- **A robot that exposes a plain Twist topic is outside what the gate can protect.** ROS 2
  topics have no access control unless SROS 2 is set up, so any node could publish to it.
  The demo robot has no such input: its only command input goes into the gate. SROS 2 is
  still not built, set up or tested here.
- **Any node can stop the robot.** Every message the gate refuses sends the safe state.
  Each refusal is now in the journal. A bare safe-state message is not: it is not a
  record, the gate signs no receipt for it, and any node can send one.
- **A receipt is the gate's word, and it is sent once.** It says what the gate sent to
  the robot. It does not show that the robot obeyed. If the recorder is stopped, in the
  safe state or not running when a receipt arrives, the receipt is lost. The verifier
  then reports a command with no receipt, or a gap in the gate's numbering. That says
  the journal does not account for something. It does not say what the gate decided.
- **A dropped receipt is not always seen.** One about a command always is. One for a
  refusal of a message that was never a record shows only as a gap in the gate's
  numbering, and only once a later receipt is in the journal. If it was the last
  receipt the gate issued, nothing shows it.
- **The gate's key is a second file on the same machine.** Anyone who can read it can
  make receipts. In every test here both keys belong to one user, so the two signatures
  separate two components, not two custodians. Kept where the journal's keeper cannot
  read it, the gate's key would make a refusal something the keeper cannot remove or
  rewrite unseen. That has not been set up or tested.
- **Receipts double the writes.** With receipts a command is two records and two flushes
  to disk, and with feedback three (see the known limits above). Every message the gate
  refuses costs it a signature and the journal a record, and nothing limits how fast
  another node can cause them.
- **The gate's signature work runs in the robot's one thread.** On an idle machine it
  takes about 4 ms to check a record's signature and about 4 ms to sign a receipt, and
  about three times that with every processor busy. The deadman check and the motion
  step wait while it runs. No delay from command in to actuator out has been measured,
  and no maximum command rate has been tested. The figures are in "Time spent in the
  gate".
- **The file demo has no receipts.** Its configuration names no gate key, and nothing
  carries a receipt back while that recorder runs.
- **The deadman is only as good as the robot's own timer.** The simulated robot is one
  thread and checks twenty times a second. Anything slow on the robot's side delays the
  check. In a real controller the deadman belongs on a timer of its own. The file demo's
  gate reads a file after the fact and has no deadman.
- **One deadman test failed once, and why is not known.** On 18 October 2026, in a full
  Linux run, `test_planted_bug_gate_has_no_deadman` failed in its second half: with the
  real gate, scenario 10 did not end as expected. Rerun alone it passed, as it did in the
  other runs that day, and its files were gone before anyone looked. Two causes fit. The
  scenario's check asked for a trip after more than four seconds, while the gate states
  the silence to the millisecond, so a correct trip a fraction of a millisecond after four
  seconds read as 4.000 and failed it; the check now accepts 4.000. Or the command after
  the trip reached the gate more than a second old and was refused for its age, which a
  loaded machine can cause: the soak that day had it once in ten runs of scenario 10. That
  second cause can still turn any run judged on timing red.
- **The deadman watches the recorder, not the controller.** It trips when the gate has
  accepted no record for `gate_deadman_seconds`, and heartbeat records count. If the
  controller dies or hangs while the recorder keeps writing heartbeats, the robot keeps
  its last commanded velocity with no time limit. Nothing here times out a command that
  is not renewed. An ordinary ROS 2 base controller does: the diff drive controller of
  ros2_control stops when no command has arrived for `cmd_vel_timeout`, half a second by
  default. The behaviour is in `Gate.handle` and `Gate.check_deadman` in
  `gate/actuator_gate.py` and is pinned by
  `test_heartbeat_records_keep_the_last_command_in_force` in `tests/test_deadman.py`.
- **Every stop ends by itself.** After a deadman trip, a command refused for its age, a
  blocked command or a refused message, the next accepted command moves the robot again.
  Nothing latches the stop and there is no deliberate reset. For the deadman that is
  pinned by `test_after_a_trip_the_next_accepted_command_moves_the_robot_again_and_rearms_it`
  in `tests/test_deadman.py`. Machinery practice expects a deliberate reset before a
  machine restarts after a protective stop. Annex III, 1.2.3 of the regulation profiled
  below requires "voluntary actuation of a control device provided for the purpose" to
  start, and says "The same requirement applies" when "restarting the machinery or
  related product after a stoppage, whatever the cause", with an exception for automatic
  mode where that "does not lead to a hazardous situation". This build has no such
  device and makes no such assessment, and the profile does not map 1.2.3.
- **The pass/fail runs keep the journal in RAM.** That is for tests only. See "When the
  disk is slow".
- **Safety inputs are not checked for age or origin.** The last `safety_inputs` message
  stays in force however old it is, and any node can publish one.
- **A Twist is rounded to whole millimetres and milliradians per second** before it is
  recorded. NaN, infinity and values above the configured limit are refused and leave
  no record.
- **Decision data, the witness and timestamps are not wired into the ROS scenarios.**
- **Follow-up, not built:** a custom message type for `cmd_vel_out` in place of JSON in a
  `std_msgs/String`.
- **Follow-up, not built:** the gate re-checking speed limits itself, independent of the
  recorder's ruleset. Today the gate applies whatever a validly signed record says.
- Tested with ROS 2 Lyrical and rclrs 0.8 only, in simulation, on one machine.

## The five scenarios

A simulated one-axis conveyor: a speed command, a clamp at 0 to 1500 mm/s, a light curtain
that blocks, and a safe state of speed 0. Each scenario runs the recorder, the gate, the
witness and the verifier as separate programs and is judged by their exit codes.

| | what happens | what it shows | recorder | gate | verifier |
|---|---|---|---|---|---|
| 1 | 7 commands inside the limits, then 150 quiet seconds | a quiet recorder writes heartbeats, so silence is visible as a gap | 0 | 0 | 0 |
| 2 | 1800 and -50 mm/s requested | both the request and the clamped command (1500, 0) are recorded with the rule that acted, and the verifier recomputes it | 0 | 0 | 0 |
| 3 | light curtain broken, then its signal missing | both are blocked, the actuator gets speed 0, and a missing safety signal is treated as unsafe | 0 | 0 | 0 |
| 4 | a ruleset upload through the recorder, then firmware changed behind its back | the first is a declared change, the second is found by measurement at the next start; every command names the state in force; the EU profile and a receipt are checked | 0, 0 | 0 | 0 |
| 5 | the journal becomes unwritable while the recorder is running | the next command is not forwarded and the actuator gets speed 0; after a restart the gate accepts the recorder again | 3, then 0 | 0 | 0 |

Scenario 5's failure is a real failed write: the journal file is made read-only mid-run.

## Tampering, and what anchoring changes

`tests/test_tamper.py` and `tests/test_anchoring.py`. A forger rewrites one request and its
outcome, then repairs every hash, the root, the state file and the anchor statements kept
beside the journal.

A forger without the recorder's key is caught when the verifier is given the machine's
public key. In each row below the verifier was given the forger's own root and the public
key from the machine's configuration (`--public-key`), and no witness's store, gate state
or timestamp. Every scenario and every tamper test here passes that key.

| the forger | what the verifier is given | exit | finding |
|---|---|---|---|
| leaves the old signatures on the changed records | the forger's own root and the machine's public key | 2 | `SIGNATURE_INVALID` |
| removes a signature | the forger's own root and the machine's public key | 2 | `SIGNATURE_MISSING`, and `SIGNATURE_INVALID` for the records after it |
| re-signs the whole journal with a key of their own and writes that key into the first record | the forger's own root and the machine's public key | 2 | `KEY_MISMATCH` |

The public key is something from outside the journal, and the third row depends on it.
Without `--public-key` the verifier takes the key from the journal's first record, so a
journal re-signed from end to end with a forger's key, with that key written into the
first record, verifies clean: exit 0, no findings. That was run by hand on 10 October
2026 and is not a test in the suite. In the same run the first two rows gave the same
findings without the key. That is no protection: a forger with no key can do what the
third row does. So the public key has to reach the verifier from somewhere the journal's
keeper cannot write.

A forger who holds the key, as the operator does, signs the rewritten records again.
The verifier is given the machine's public key in these rows too, and it changes
nothing, because the forger signs with that key. Then it depends on what else the
verifier is given:

| what the verifier is given | exit | finding |
|---|---|---|
| only things the forger can reach: their root, their statements | 0 | none |
| the witness's store of roots | 2 | `ANCHOR_MISMATCH` |
| the gate's last accepted hash | 2 | `GATE_HEAD_NOT_IN_JOURNAL` |
| the original timestamped statements | 2 | `ANCHOR_MISMATCH` |
| the forger's statements with the original timestamp tokens | 2 | `TOKEN_INVALID` |

The witness also refuses the forger's attempt to submit the rewritten roots, because it
already holds different roots for that journal at those record counts.

A timestamp alone does not stop a rewrite, since an authority will stamp a rewritten root
later. `anchor_roots.py verify --max-lag-seconds N` makes a token issued long after the
records it covers a finding.

## Planted bugs

Each row is a Cargo feature, off by default, that breaks the recorder in one way. The clean
recorder passes the scenario. The broken one must turn the named check red.

| planted bug | scenario | caught by | exit | finding |
|---|---|---|---|---|
| no heartbeats in a quiet period | 1 | verifier | 2 | `HEARTBEAT_GAP` |
| clamps to the limit plus 100 | 2 | verifier | 2 | `RULE_MISMATCH` |
| the light-curtain rule never fires | 3 | verifier | 2 | `RULE_MISMATCH` |
| commands keep naming the old state after a change | 4 | verifier | 2 | `IN_FORCE_MISMATCH` |
| forwards the command before recording it | 5 | verifier with the gate's state, then the gate on restart | 2, 2 | `GATE_HEAD_NOT_IN_JOURNAL` |
| the same, and ignores the failed write | 5 | verifier with the gate's state, then the gate on restart | 2, 2 | `GATE_HEAD_NOT_IN_JOURNAL` |

In the last two rows the unrecorded commands do reach the actuator: one in the first case,
two in the second. The gate does not prevent them. It makes them visible and stops the
recorder carrying on after a restart.

One more planted bug on the file path is in the gate, not the recorder. The gate is
Python, so the test runs a copy of the gate program with one line changed, after proving
the line was there to change (`tests/test_planted_bugs.py`).

| planted bug | how it is exercised | what turns red |
|---|---|---|
| the gate does not check that a record's text is in canonical form | the recorder as shipped records four commands. A copy of the third command's record with spaces added, carrying the hash of that text, is put in front of the genuine one, as a node with no key could put it | the copy is accepted and its command carried out. The gate's head becomes a hash that is in no journal, so the genuine record and every record after it are refused. The verifier with the gate's state exits 2 (`GATE_HEAD_NOT_IN_JOURNAL`) on a journal that is clean without it. This is what the gate did before it had the check: it was laxer than the verifier, which already required the canonical form |

With the check, the copy is refused for `form`, the genuine record and the ones after it
are carried out, and the verifier exits 0. A refusal still sends the safe state, as every
refusal does, so a node that sends such copies can stop the machine. It can no longer
leave the gate holding a hash that the journal does not hold. `tests/test_gate.py`
covers ten ways of writing the same record in other bytes: added spaces, another key
order, several lines, a key given twice (two ways), a trailing newline, trailing spaces,
a leading space, zero written as -0, and a letter written as an escape. One more, a whole
number written as a decimal, passes the check of the form and is refused one step later,
for its signature.

## ROS 2

The same recorder as a ROS 2 node, with a simulated robot. `ros2 launch` starts the two
as separate processes. The scenario driver then plays the other nodes: a controller, a
safety sensor and, in scenarios 6 to 9, a node publishing straight onto the robot's
input.

| | what happens | recorder node | robot (gate) | verifier |
|---|---|---|---|---|
| 1 | commands inside the limits, one using all six Twist fields, five quiet seconds with heartbeats | 0 | 0 | 0 |
| 2 | 1.8 and -1.8 m/s clamped to 1.5; NaN, infinity and 6 m/s refused with no record | 0 | 0 | 0 |
| 3 | a command before any safety signal, then a broken light curtain: both blocked, robot gets zero velocity | 0 | 0 | 0 |
| 4 | a ruleset upload through the node; firmware changed between two launches and found at the second start | 0, 0 | 0, 0 | 0 |
| 5 | the journal becomes unwritable: the command is not published; then both are restarted | 3, then 0 | 0, 0 | 0, then 2 (`HEARTBEAT_GAP`: the time the recorder was down) |
| 6 | another node publishes to `cmd_vel_out`: no record, not JSON, a replay, a tampered record, a gap | 0 | 2: all five refused | 2 (`GATE_REFUSED` five times: the journal holds the gate's receipt for each, reasons `form`, `form`, `chain`, `form`, `signature`) |
| 7 | another node forges a correctly chained record, with a signature lifted from a real one | 0 | 2: refused, the robot does not move | 2 (`GATE_REFUSED`, reason `signature`) |
| 8 | the same, signed with a key of the forger's own | 0 | 2: refused, the robot does not move | 2 (`GATE_REFUSED`, reason `signature`) |
| 9 | the same, with the signature removed | 0 | 2: refused, the robot does not move | 2 (`GATE_REFUSED`, reason `signature`) |
| 10 | the recorder goes silent for ten seconds while the robot is moving at 0.5 m/s (its process is frozen) | 0 | 0: the deadman stops the robot after four seconds | 2 (`HEARTBEAT_GAP`: nothing the recorder wrote explains the silence; `GATE_DEADMAN`: the gate's receipt for the trip, written once the recorder is back) |
| 11 | one record takes six seconds to reach the disk (a test build of the node that can be told to do this) | 0 | 2: the deadman stops the robot at four seconds; the command, six seconds old when its record lands, is refused for its age and the robot stays stopped | 2 (`STORAGE_STALL`: the recorder's next record states the stall and its measured length; `GATE_DEADMAN`; `GATE_REFUSED`, reason `age`, naming the record that was refused) |
| 12 | the folder for anchor statements becomes unwritable | 0: not a fault, every command goes out | 0 | 2 (`ANCHOR_FAILED`: a signed record states each statement that could not be written) |
| 13 | the wheels do not turn (a test switch in the simulated robot) | 0 | 0: the gate applies both commands | 0: the receipts say `applied`, the feedback says the wheels did not move, and the verifier does not judge between them |

In scenarios 6 to 9 the recorder's own next command is still accepted after the refusals.
The robot exits 2 in those scenarios because exit 2 means the gate refused something,
which is the expected result there, and in scenario 11 because it refused a stale
command. The verifier exits 2 in the same scenarios for the same reason: the journal now
holds the gate's signed receipt for each refusal, and a refusal is a finding. The
journal's chain, signatures and rules are sound in all of them. In scenarios 10 to 12
the verifier exits 2 because that is what happened: the recorder could not record for a
time, or lost an anchor, and the journal says so.

Every scenario also checks the receipts the journal ends up holding, in order: one
`applied` or `blocked` for each command in scenarios 1 to 5, 12 and 13, and the refusals
and deadman trips in the others. And for each command record, what the report signed with
the feedback key says the wheels did: the speed the gate sent in every scenario but 13,
zero in 13.

### Receipts from the gate

Until this was built, a command the gate refused for its age still read in the journal
as recorded and forwarded, and the verifier had no finding for it. The refusal was only
in the robot's own log.

Now the gate signs a receipt for every command record it takes in (`applied`, `blocked`,
or `refused` for `age`), for every message it refuses (`refused` for `signature`, `chain`
or `form`, meaning not a well-formed record message, or a record whose text is not in
canonical form), and for every deadman trip. It signs with a key of its own, whose public
half is `gate_public_key` in the machine's configuration. The robot publishes each
receipt on `gate_receipts`. The recorder checks that the gate signed it and that it is
newer than the last one, and writes it into the journal as a record of its own, signed
and chained like the rest. The gate acts first and signs afterwards, so a stop is not
delayed by the signature on its own receipt. It can still wait behind other signature
work in the same thread: see "Time spent in the gate".

Those four reasons are the four checks the gate makes. It has no speed limit of its own:
limits are the ruleset's, applied before the record is written and recomputed by the
verifier.

Scenario 11's journal, from one run:

```
 2  command        applied 500 mm/s
 3  gate_receipt   receipt 0: applied, record 2
 4  command        applied 200 mm/s           (this record took six seconds to write)
 5  storage_stall  record 4, 6000 ms
 6  gate_receipt   receipt 1: deadman, "no valid record for 4.041 s; the limit is 4 s"
 7  gate_receipt   receipt 2: refused, age, record 4, "the command is 6003 ms old; the limit is 1000 ms"
 8  command        applied 300 mm/s
 9  gate_receipt   receipt 3: applied, record 8
```

and the end of the verifier's report on it:

```
gate receipts:    4 in the journal: 1 refusal(s), 1 deadman trip(s); 0 command(s) with no receipt
storage stalls:   1 stated by the recorder (each is a finding below)
  STORAGE_STALL n=5 step="journal_write" of_record=4 stalled_ms=6000 previous="2026-10-10T14:27:45Z" at="2026-10-10T14:27:51Z"
  GATE_DEADMAN n=6 gate_seq=1 last_record_accepted=3 detail="no valid record for 4.041 s; the limit is 4 s"
  GATE_REFUSED n=7 gate_seq=2 reason="age" of_record=4 detail="the command is 6003 ms old; the limit is 1000 ms"
3 FINDING(S)
```

Record 4 reads as it always did: 200 requested, 200 applied. Record 7 is what says the
robot never did it.

What the verifier reports about receipts:

| finding | when |
|---|---|
| `GATE_REFUSED` | a receipt says the gate refused something, with the reason and, for `age`, the record refused |
| `GATE_DEADMAN` | a receipt says the gate's deadman tripped |
| `COMMAND_WITHOUT_RECEIPT` | a command record that no receipt answers for |
| `RECEIPT_MISSING` | the gate's receipt numbers skip one or more |
| `RECEIPT_INVALID` | a receipt record that is malformed or not signed with the gate's key |
| `RECEIPT_MISMATCH` | a receipt the gate signed that does not belong to the record it names |

`tests/test_receipts.py` runs the recorder and the gate with no ROS and covers the rest:
someone who holds the recorder's key and not the gate's rewrites a refusal as `applied`
(`RECEIPT_INVALID`), or deletes it and repairs the chain (`COMMAND_WITHOUT_RECEIPT`,
`RECEIPT_MISSING`); a receipt signed with another key, or sent twice, is not written.

Nine planted bugs on the ROS path. Three are Cargo features of the node. Five are in the
gate and one in the feedback reporter, which are Python: the test hands the robot a copy
of the file with one line changed. A sixth planted bug in the gate, the check of a record's canonical form
removed, needs no robot and is listed under "Planted bugs" above.

| planted bug | scenario | what turns red |
|---|---|---|
| the node stops refusing NaN, infinity and over-limit values | 2 | the scenario driver exits 2: seven commands recorded where four were expected |
| the node records a command and never publishes it | 1 | the robot exits 2: the gate sees a gap and refuses everything after it. No unrecorded command reaches the robot. The verifier exits 2 as well (`GATE_REFUSED`, `COMMAND_WITHOUT_RECEIPT`, `COMMAND_WITHOUT_FEEDBACK`, `GATE_DEADMAN`): the journal says the commands after the gap were not carried out and that the deadman tripped |
| the node publishes before it writes, and the write fails | 5 | the verifier exits 2 (`GATE_HEAD_NOT_IN_JOURNAL`). One unrecorded command reaches the robot, the same bound as the file demo |
| the gate skips the signature check | 7 | the scenario driver exits 2: the forged record is accepted and the robot moves at the forger's 1500 mm/s. This is what happened before records were signed |
| the gate has no deadman | 10 | the scenario driver exits 2: the robot keeps moving at 0.5 m/s for the whole ten seconds the recorder is silent. This is what the gate did before it had one |
| the gate does not check a command's age | 11 | the scenario driver exits 2: stopped by the deadman at four seconds, the robot starts moving again at six on a command six seconds old. This is what the gate did before it had the check. Its receipt for that command says `applied` |
| the gate drops the receipt for every refusal | 11, 7 | the robot behaves exactly as it should, and the verifier exits 2. Scenario 11: `COMMAND_WITHOUT_RECEIPT` for the command refused for its age, and `RECEIPT_MISSING` for the skipped number. Scenario 7: `RECEIPT_MISSING` only, since the forged record was never one of the recorder's commands |
| the gate signs no receipts | 3 | the verifier exits 2: `COMMAND_WITHOUT_RECEIPT` for every command. This is the gate as it was before receipts |
| the feedback reporter reports only on commands that were applied | 3 | the robot moves as before, and the verifier exits 2: `COMMAND_WITHOUT_FEEDBACK` for the two blocked commands, where the wheels were given the safe state |

### Feedback from the actuator

A receipt says what the gate sent to the wheels. It does not say what the wheels then did.
A motor can stall, a wheel can slip, a drive can be faulted, and the journal would still
read: requested, applied, sent.

Now the robot reports back. After acting on each command record the gate takes in
(applied, blocked, or refused for its age), the robot reads what its wheels are doing and
where odometry puts it, and signs that reading with a third key, the feedback key, whose
public half is `feedback_public_key` in the machine's configuration. It publishes the
report on `actuator_feedback`. The recorder checks that the feedback key signed it and that
it is newer than the last one, and writes it into the journal as a record of its own,
next to the command it follows. Each report names that command by number and hash, and
holds what the wheels were given (`sent`), what they did (`measured`, under the same
keys), the pose (`state`), and when the reading was taken.

The reading is taken after the action has been given and before the wheels are given
anything else, so it never describes a later command. The simulated robot takes it on its
first motion step at least 50 ms after the action, or at once if something else is about
to be sent first.

Scenario 13 makes the wheels stick. The gate applies both commands and its receipts say
so. The reports say the wheels did not move. Its journal, from one run:

```
 2  command            requested 500 mm/s, applied 500
 3  gate_receipt       receipt 0: applied, record 2, sent 500
 4  actuator_feedback  report 0: record 2, sent 500, measured 0, pose x 0 mm, read 73 ms after
 5  command            requested 300 mm/s, applied 300
 6  gate_receipt       receipt 1: applied, record 5, sent 300
 7  actuator_feedback  report 1: record 5, sent 300, measured 0, pose x 0 mm, read 100 ms after
```

In scenario 11, the same reports show what the deadman did. The command whose record took
six seconds to land was refused for its age, and its report reads: sent 0, measured 0,
pose x 2050 mm, which is where the deadman had stopped the robot.

The verifier exits 0 on that journal, and that is deliberate. It checks that every report
is genuine and is filed under the command it names. It does not judge whether the robot
did what it was told: how fast a motor should reach a speed, and how far off is normal,
depend on the machine, and no tolerance is set. The journal now holds the answer for a
person, or a later check, to read.

What the verifier reports about feedback:

| finding | when |
|---|---|
| `COMMAND_WITHOUT_FEEDBACK` | a command record that no report answers for |
| `FEEDBACK_MISSING` | the reporter's numbers skip one or more |
| `FEEDBACK_INVALID` | a report record that is malformed, not signed with the feedback key, or numbered at or below an earlier one |
| `FEEDBACK_MISMATCH` | a report the feedback key signed that does not belong to the command it names: not an earlier command, not that command's hash, a second report for one command, a report after a later command's, an action that is neither the record's applied command nor the safe state, an action the gate's receipt does not agree with, or a reading taken after the gate's next action |

`tests/test_feedback.py` runs the recorder, the gate and the reporter with no ROS and shows
each way a report can go wrong being caught: lost by the robot (`COMMAND_WITHOUT_FEEDBACK`,
and `FEEDBACK_MISSING` once a later report follows); deleted, changed, or moved to another
command by someone who holds the recorder's key and not the feedback key
(`FEEDBACK_INVALID`, `COMMAND_WITHOUT_FEEDBACK`); and, signed with the feedback key itself,
filed under a command it does not belong to in nine different ways (`FEEDBACK_MISMATCH`).
A robot whose control loop takes each reading only after the next action, and files it
under the command before, is caught by the time of its readings. The recorder will not
write a report that the feedback key did not sign, or one it has already written.


### Time spent in the gate

The gate checks the signature on every record and signs every receipt with Ed25519
written in plain Python (`gate/actuator_gate.py`). Timed on one machine on 10 October
2026 with nothing else running: 300 calls of each of the gate's own two functions, on a
933-byte command record and a 331-byte receipt shaped like the ROS node's. Mean, then
the fastest and slowest single call:

| | Windows 11, CPython 3.14.2 | Ubuntu 26.04 under WSL 2, CPython 3.14.4 |
|---|---|---|
| check one signature (`ed25519_verify`) | 4.4 ms, 4.1 to 5.0 | 4.1 ms, 3.7 to 5.4 |
| sign one receipt (`ed25519_sign`) | 3.9 ms, 3.7 to 6.6 | 3.8 ms, 3.3 to 8.2 |

A second run of each gave means within 4 percent of these. With every processor kept
busy by eight spinning processes (Windows, 100 calls each) the means were 12.2 ms to
check and 11.2 ms to sign, and the slowest single calls took 39 ms and 36 ms. A machine
that is busy or throttled will be slower than the table.

Both functions run in the simulated robot's one thread, the same thread as the deadman
check and the motion step, which are due twenty times a second. What follows is worked
out from the figures above. It is not a measured delay from command in to actuator out,
and no maximum command rate has been tested.

- A command waits for one signature check at the gate before the robot acts on it: about
  4 ms on an idle machine, on top of the recorder's wait for the disk.
- With receipts, one command costs the gate two checks and one signature, about 12 to
  13 ms of that thread: the command record, the receipt for it, and the recorder's record
  of that receipt, which the gate checks like any other record. From that alone the gate
  cannot take more than about 80 commands a second on an idle machine, or about 26 with
  every processor busy. The gate also writes its state file after every message, and
  that time is not in these figures.
- While the gate is checking or signing, the deadman check and the motion step wait. On
  an idle machine one command's work is shorter than one 50 ms step. With every
  processor busy, single calls took most of a step.

### When the disk is slow

The recorder writes a record and waits for the disk to confirm it before it forwards the
command. That wait is the point of the design, and it has a cost.

What we measured, on WSL 2 (an ext4 virtual disk on an NVMe SSD), 9 October 2026:

- One confirmation of an anchor file took 7.8 seconds. One of the journal took 4.0 seconds.
  The usual figure is about 10 milliseconds.
- For 8.2 seconds the recorder wrote nothing. The verifier reported a `HEARTBEAT_GAP`,
  and on that disk 3 of 12 runs of the scenarios failed for that reason.
- A separate program that only reads the clock every 100 ms never saw a step over 0.105
  seconds. The machine did not pause. The time went in the disk.
- A separate program that only writes and flushes a small file saw the same thing with
  the recorder not running: bursts of about 15 seconds in which every flush took 0.5 to
  2 seconds. We do not know why that disk does this.

What happens now when a write takes longer than twice the heartbeat interval (4 seconds
in the demo):

- **The robot stops.** The gate has a deadman: no valid record for
  `gate_deadman_seconds` (4 in the demo) means the safe state. Before this, the robot
  carried on at its last commanded velocity for as long as the recorder was silent.
  Heartbeat records count, so a quiet recorder that is alive keeps the last command in
  force for as long as its heartbeats arrive. That is a limit and not a safeguard: the
  deadman covers a recorder that has gone silent, not a controller that has stopped
  sending commands (see the limits of the ROS 2 version).
- **The robot stays stopped until the next accepted command.** When the slow write
  completes, the command in it is late. Every command record carries the time the
  recorder received it. The gate refuses to carry out a command more than
  `gate_max_command_age_ms` old (1 second in the demo) and keeps the safe state. The
  record still counts as the next in the chain, so the recorder's later commands are
  accepted as usual, and the first of them moves the robot again. Nothing latches the
  stop.
- **The journal says the command was not carried out.** The gate's receipt for that
  record says `refused`, reason `age`, and the verifier reports `GATE_REFUSED`. Its
  receipt for the deadman trip is there too (`GATE_DEADMAN`). Both were issued during the
  stall and written when the recorder could write again.
- **The journal says why.** When the slow write completes, the recorder's next record is
  a `storage_stall` record: which step, which record, and how long, measured on the
  monotonic clock. The verifier then reports `STORAGE_STALL` in place of `HEARTBEAT_GAP`.
  It is still a finding and the exit code is still 2. The threshold has not moved. A
  silence with no such record, or one the stated stall is too short to account for, is
  still a `HEARTBEAT_GAP`.
- **The recorder and the verifier use the same test for a gap.** The verifier compares
  two records' times in whole seconds. The recorder applies that same comparison, on the
  same clock, before deciding to write a stall record. So a gap is never left unexplained
  because one side measured in milliseconds and the other in seconds. A slow write that
  leaves no gap by that measure gets no stall record, because there is nothing to explain.
- **The stall record is the recorder's own statement.** It is signed like every record,
  so someone without the key cannot add one. The verifier cannot confirm the disk was
  the cause.
- **Anchor files are no longer flushed while the recorder holds its lock** in the ROS
  node. A slow anchor no longer holds up a record. An anchor can now be written a little
  after the records it covers.
- **An anchor that cannot be written is not a fault, and it is in the journal.** The
  recorder carries on and writes a signed `anchor_failed` record naming the statement
  that was lost. The verifier reports `ANCHOR_FAILED`, a finding, exit 2. Scenario 12.
  The one exception is the last anchor, written after the stop record: nothing is
  written after a stop, so its loss is not stated.

What a late or missing anchor can and cannot do (`tests/test_stalls.py`):

- A rewrite of a record that any delivered anchor covers never verifies, however many
  later anchors are missing.
- A journal with no anchor at all, checked against a witness, is a finding. A missing
  anchor is never taken as agreement.
- Records written after the last anchor that arrived are not protected by anchors. That
  was already so. A late anchor makes that stretch longer. The verifier reports how many
  such records there are, and the gate's head still covers them.

Tests. The pass/fail runs of the ROS scenarios keep the journal in a RAM-backed folder
(`/dev/shm`), so their result depends on the code and not on the disk. **That is for
tests only.** A journal in RAM is gone at power-off. `ros2/soak_real_disk.py` runs the
same scenarios on a real disk and reports flush times, stalls and deadman trips as
measurements, with no pass or fail.

One soak on the same WSL 2 disk, on the code as it is now, receipts and actuator feedback
included: ten rounds of scenarios 1 to 10, 12 and 13, 120 scenario runs in 948 seconds,
18 October 2026. 1,437 journal flushes, median 4.1 ms, the longest 2.98 s. The soak of
10 October, before feedback, had 993, and the one before receipts 545: each command is now
three records. 57 took over half a second (37 on 10 October) and none went past the 4
second threshold, so no `storage_stall` record was written and the verifier reported no
stall. The limit on a command's age is 1,000 ms. The gate took in 370 command records. It
applied 345, 19 were blocked commands, and it refused 6 for their age and kept the safe
state each time. Those 6 are why 6 of the 120 scenario runs did not end as the pass/fail
run expects, one each in scenarios 1, 3, 5, 8, 10 and 13. The deadman tripped 11 times:
ten on purpose in scenario 10, and once in a run of scenario 1, after a command there had
been refused for its age. The longest anchor flush was 2.91 s and held nothing up. The
clock log's largest step was 0.103 s.

All 6 refusals for age and all 11 deadman trips are in those journals as receipts signed
by the gate, and the verifier, run over each of the 120 journals, reported every one:
`GATE_REFUSED` in each of the 6 runs with a refusal for age, `GATE_DEADMAN` in each of the
11 with a trip. No command record was left without a receipt and no receipt number was
skipped. The robot's controller filed a feedback report for each of the 370 command
records, and the verifier reported no `COMMAND_WITHOUT_FEEDBACK`, `FEEDBACK_MISSING`,
`FEEDBACK_INVALID` or `FEEDBACK_MISMATCH`. In the soak before receipts, 8 refusals for age
and one deadman trip nobody planned left no finding at all.

To run it, on Ubuntu 26.04 with ROS 2 Lyrical, Rust, `libclang-dev` and pytest installed:

```
. /opt/ros/lyrical/setup.sh
cd ros2/sentinel_recorder_node && cargo build && cd ../..
python3 ros2/run_ros_scenarios.py --node ros2/sentinel_recorder_node/target/debug/sentinel_recorder_node
python3 -m pytest tests            # with ROS sourced: 259 tests
python3 ros2/soak_real_disk.py --node ros2/sentinel_recorder_node/target/debug/sentinel_recorder_node
```

The second line runs scenarios 1 to 10, 12 and 13 with the journal in RAM. Scenario 11 needs the
test build (`cargo build --features test-slow-flush`, passed with `--slow-flush-node`);
pytest builds it itself. The last line is the real-disk measurement and always exits 0.

Two diagnostic aids are off unless asked for: set `SL_TRACE_FILE` and the node logs how
long each write took and how long each thread waited, against the monotonic clock;
`ros2/clock_watchdog.py` is the independent clock log used above.

### A signed log on your simulation

`ros2/run_on_your_sim.py` puts the recorder and the gate in front of a ROS 2 robot
simulation that someone else built, so a robot maker can see the signed journal and the
verifier's report on their own robot model. It starts three processes: the simulation
(whatever command is given with `--sim`), the recorder node, and `ros2/sim_bridge.py`,
which is the same gate, receipts and feedback reporter as the simulated robot above,
standing between the recorder and the simulation's velocity command topic
(`geometry_msgs/Twist` or `TwistStamped`). The runner plays the controller and the safety
sensor. Once the robot publishes odometry and three more seconds have passed, it sends
five commands: forward, turn on the spot, forward with the light curtain interrupted,
forward more slowly, stop. After each one, once the action has been in force for one
second, the bridge reads the simulation's odometry and signs it as the actuator's feedback.

**Here the gate sits in front of the robot's command topic, not inside the robot.** Any
other program that publishes to that topic moves the robot, and nothing of it is in the
journal. In the simulated robot above the gate is the only way to the wheels; a simulation
built by someone else has its own way in, the plain velocity topic that SPEC 15.7 names as
a limit. What this shows is the journal, the receipts and the feedback on your model, not
a protected robot.

Measured on a TurtleBot3 Burger (ROBOTIS, `turtlebot3_gazebo` 2.3.7 on ROS 2 Lyrical,
Gazebo's empty world with no window, WSL 2), 20 October 2026, starting with nothing of
Gazebo's running:

```
python3 ros2/run_on_your_sim.py --node ros2/sentinel_recorder_node/target/debug/sentinel_recorder_node \
    --sim "ros2 launch ros2/examples/turtlebot3_headless.launch.py" --env TURTLEBOT3_MODEL=burger \
    --cmd-type twist_stamped
```

This run used the next version of the bridge, which is not published here yet. It reads
the odometry once the action has been in force for one second of the simulation's own
time, or after five seconds of wall time if the simulation's time has not advanced a
second by then. The version published here reads after one second of wall time. That is
why the times below are a little over one second, and why the first one is 5,218 ms.

| record | asked for (mm/s, mrad/s) | the record's outcome | the gate's receipt | the robot was given | odometry measured, and how long after |
|---|---|---|---|---|---|
| 6 | (200, 0) | unchanged | refused: age | (0, 0) | (0, 0), 5218 ms (0.00 s simulated) |
| 12 | (0, 500) | unchanged | applied | (0, 500) | (0, 500), 1061 ms (1.04 s simulated) |
| 16 | (200, 0) | blocked | blocked | (0, 0) | (0, 0), 1039 ms (1.03 s simulated) |
| 20 | (100, 0) | unchanged | applied | (100, 0) | (100, 0), 1032 ms (1.01 s simulated) |
| 24 | (0, 0) | unchanged | applied | (0, 0) | (0, 0), 1033 ms (1.00 s simulated) |

**The first command was refused.** It reached the gate 1,544 ms after the recorder
received it, over the 1,000 ms limit, so the gate refused it, kept the robot still and
signed a receipt saying so. The verifier checked all 29 records and their signatures and
reported one finding, `GATE_REFUSED`, for that command; the bridge exited 2 because of it.
The offline check of the syslog export passed. The journal is complete, ending with the
recorder's stop record, but the recorder process then crashed (segmentation fault) as it
shut down. The version published here does that in about one launch in ten, always after
its journal and the exit code it writes for the launcher are complete, so the runner and
the tests, which read that file, took it for a clean exit. The cause is found: the node
exited without first shutting down its middleware, whose threads were still running when
its libraries were unloaded. The fix is in the next version, not published here yet. For
the other four commands the last two columns agree. The verifier does not compare them
(SPEC 4.6); the table is there for a person to read.

**A correction.** Until 20 October 2026 this section showed a table measured on 19
October, in which all five commands were applied and every reading agreed with the
command. That table did not measure what it said it measured. The first run that day left
its Gazebo server running after it ended, and the later runs, including the one in that
table, drove the robot in that leftover server, not in the one they had started (Gazebo's
log said "Another world of the same name is running"). They met a simulation that had
been running for minutes. This section also presented waiting three seconds after the
first odometry (`--settle`) as the answer to a late first command. That wait was only ever
tried against the leftover server, never from a clean start. The run above is the first
with that wait to start from nothing of Gazebo's running, and its first command was
refused.

What the run showed about timing:

- The machine stalled at the start. The first command took 1,544 ms to get from the
  recorder to the gate, and the runner's own record of `/clock` shows no advance of the
  simulation's time in the five seconds that followed. That does not fit the factor of
  0.98 below unless the simulation caught up afterwards, which has not been checked. Around
  the same time the recorder's own two-second heartbeats came up to three seconds late, so
  the recorder was held up too, not only Gazebo. Windows had as little as 1.5 GB of memory
  free during the run. The cause is not established. On 19 October, in the one run that
  started Gazebo fresh, with no wait after the first odometry, the first command reached
  the wheels about 0.8 s late and its reading caught the robot at 134 mm/s, still
  accelerating. On 20 October the three seconds of waiting did not prevent a late first
  command.
- Simulated time ran at 0.98 of real time while the commands were sent (measured from
  `/clock`). A bridge that times its reading on the wall clock reads a simulation that runs
  slower than real time before one second of the robot's own time has passed, and can
  catch the robot before it has finished responding; its feedback then shows less than the
  robot went on to do. `SUMMARY.md` states the factor for every run.
- TurtleBot3's own `empty_world.launch.py` always opens Gazebo's window.
  `ros2/examples/turtlebot3_headless.launch.py` starts the same world and robot without
  it, through ROBOTIS's own launch files for the robot. Gazebo's server takes longer to stop
  than its launch waits, which is how the server of 19 October was left running. The runner
  now stops anything of the simulation that is still running when it is done.

Each run leaves, in one folder: the journal (`data/logchain.journal`), the verifier's
report as text and as JSON, the journal exported as RFC 5424 syslog with the offline
checker's report on it, and `SUMMARY.md` with the table above.

For another robot: give `--sim` the command that starts its simulation; `--cmd-topic`,
`--cmd-type` and `--odom-topic` where they differ from `/cmd_vel`, `twist` and `/odom`;
and `--env` for any variable it needs. It should work with any simulator that takes velocity
commands on a topic and publishes `nav_msgs/Odometry`, but only the Burger has been tried.
In the tests, `ros2/stand_in_sim.py` stands in for a simulation (a two-wheeled base with a
lag and no physics), so the runner is tested without a simulator: with `Twist`, and with
`TwistStamped`, wheels that never turn and a process left behind that ignores SIGINT and
SIGTERM.

## The EU Machinery Regulation profile

A profile maps one rule to the records it needs and how long to keep them. One is built:
Regulation (EU) 2023/1230 on machinery, Annex III, Part B. The regulation as published
says it applies from 14 January 2027. A corrigendum (OJ L 169, 4.7.2023, p. 35) changes
that: **it applies from 20 January 2027.**

| provision | words of the provision | records mapped to it | kept for |
|---|---|---|---|
| 1.1.9, fifth paragraph | "shall collect evidence of a legitimate or illegitimate intervention in the software or a modification of the software installed on the machinery or related product or its configuration" | the first record, declared changes, changes found by measurement | no period stated |
| 1.2.1, second paragraph, point (f) | "the tracing log of the data generated in relation to an intervention and of the versions of safety software uploaded after the machinery or related product has been placed on the market or put into service is enabled for five years after such upload" | the same, plus the state named by every command | five years |
| 1.2.1, third paragraph, point (b) | "recording of data on the safety related decision-making process" ... "such data is retained for one year after its collection" | commands that carry decision data, and the decision files | one year |

The full text of each provision is in `profiles/eu_2023_1230_annex_iii.json`, and a test
fails if any quotation there is not found word for word in the copy of the regulation in
`sources/eu/`.

What the profile is not: a statement that any machine conforms to the regulation. The
duties in it fall on the manufacturer. The verifier reports which records exist and is
written never to print "compliant". 1.1.9 also covers intervention in a hardware
component, which this recorder does not measure, and the profile marks that as not mapped.
Nothing here is legal advice.

Three more profiles are listed in the specification and not built: California Vehicle Code
38750(c)(1)(G), insurance and billing use, and the 2022 draft ethical black box standard
(arXiv:2205.06564).

## Exporting to syslog or CEF

A site that watches a SIEM or a syslog server can have the journal there too, without
losing the means to check it. `export/export_journal.py` writes one RFC 5424 syslog line or
one CEF event per record, with the record's exact signed text inside the line and an end line
holding the record count and the Merkle root. `export/check_export.py` reads an exported file
on its own, with nothing else from this repository, and checks each line against the record
inside it, the order and the hash chain, every record's signature and every gate receipt's
signature. The format, and what the checker does not establish, are in `docs/EXPORT.md`.

```
python export/export_journal.py demo/out/scenario_4/data/logchain.journal --format syslog --out s4.syslog
python export/check_export.py s4.syslog --public-key KEY --root ROOT
```

A record altered, dropped, repeated or moved is a finding, and so is a line whose severity or
event name was changed after export. The end line is in the same file as the records, so
someone who drops the last record and rewrites the end line leaves a file that is consistent
with itself; only `--root`, from an anchor or the gate's head, shows that. A test shows both.

## Run it

The file demo needs Rust (cargo), Python 3 with pytest, and openssl on the PATH for the
timestamp tests. The ROS 2 part has its own section above.
The first build downloads crates and LogChain from GitHub. After that nothing uses the
network: the witness listens on localhost.

```
git clone https://github.com/JakPot42/sentinel-ledger
cd sentinel-ledger
cd recorder && cargo build && cargo test && cd ..
python demo/run_scenarios.py      # exit 0 only if all five scenarios are as expected
python -m pytest tests            # 230 tests without ROS 2 (29 more are skipped); builds six deliberately broken recorders
```

To read one journal's report after the scenarios have run:

```
python verifier/verify_journal.py demo/out/scenario_4/data/logchain.journal \
    --rulesets demo/out/scenario_4/data/rulesets --decisions demo/out/scenario_4/data/decisions \
    --witness-store demo/out/scenario_4/witness_side/roots.jsonl \
    --gate-state demo/out/scenario_4/actuator_side/gate.state \
    --profile profiles/eu_2023_1230_annex_iii.json --as-of 2026-12-01
```

Exit codes everywhere: 0 nothing found, 2 a finding, 1 a usage or input error. The
recorder exits 3 when it ends in the safe state.

The one command that contacts another machine is
`python anchor/anchor_roots.py fetch --dir DATA --freetsa`. It refuses to run without the
flag.

## Layout

| path | what | language |
|---|---|---|
| `docs/SPEC.md` | the specification | |
| `recorder/` | the recorder, on the `logchain` crate | Rust |
| `gate/actuator_gate.py` | the actuator-side gate; signs receipts when given a key of its own | Python, standard library |
| `gate/actuator_feedback.py` | on the robot's side beside the gate: signs what the actuator did after each command, with the feedback key | Python, standard library and the gate's signing code |
| `witness/witness.py` | a witness: stores the roots it is sent and never changes one | Python, standard library |
| `anchor/anchor_roots.py` | delivers root statements to a witness, or timestamps them (needs openssl) | Python, standard library |
| `verifier/verify_journal.py` | the verifier | Python, standard library |
| `export/` | export of a journal to RFC 5424 syslog or CEF, and an offline checker for an exported file (`docs/EXPORT.md`) | Python, standard library |
| `profiles/` | the EU profile | |
| `sources/eu/` | the regulation and its corrigendum as retrieved from the Publications Office of the European Union | |
| `demo/` | the simulated conveyor and the five scenarios; `pure_ed25519.py` lets the tests play a forger | |
| `ros2/` | the recorder as a ROS 2 node, a simulated robot with the gate inside it, a launch file, thirteen scenarios, the real-disk soak, the clock watchdog; the gate in front of another simulation's command topic (`sim_bridge.py`), the runner for it (`run_on_your_sim.py`), a stand-in simulation for its tests and a headless TurtleBot3 launch (`examples/`) | Rust, Python |
| `tests/` | scenarios, planted bugs, tampering, the gate, its deadman and its receipts, the actuator's feedback, anchoring, storage stalls, the profile, export | |

The gate, the witness and the verifier import nothing from each other or from the
recorder, and tests check their import lists. The same holds for the exporter and the export
checker. The feedback reporter uses the gate's signing code, since both are on the robot's
side, and nothing else of the gate's.

## Licence

MIT, see `LICENSE`. The two files in `sources/eu/` are European Union documents
(© European Union), included unchanged so the quotations can be checked; only the version
published in the Official Journal is authentic.

The recorder is built on [LogChain](https://github.com/JakPot42/logchain), which Cargo
fetches from GitHub at a pinned revision, and on Rust crates from crates.io. The ROS 2 node
also needs ROS 2, installed separately. None of these is included here, and none is covered
by this licence.
