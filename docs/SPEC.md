# Sentinel Ledger: specification (draft 1)

Status: the first build exists and follows this document. It is a recorder for a simulated
machine, a verifier, one profile and five demo scenarios. Section 12 records the decisions
taken, section 13 what remains unverified, and section 14 the limits of this build.

This build covers the append-only journal, sequence gaps, the heartbeat and recording with
no selection step. Anchoring is covered in a first form: a witness that stores roots, and
RFC 3161 timestamps (section 7.5). Signed checkpoints, witness cosigning and consistency
proofs are not built.

This document is meant to be complete enough that someone can write a second verifier from
it without reading the recorder's source. That is the same test the format document of
LogChain (github.com/JakPot42/logchain, `docs/FORMAT.md`) and the specification of asof-gate
(github.com/JakPot42/asof-gate, `docs/SPEC.md`) set for themselves, and it is the reason the
byte-level parts below are spelled out.

Keywords MUST, MUST NOT, SHOULD and MAY are used in the RFC 2119 sense.

## 1. What it is

A recorder that sits between whatever decides a machine's commands and the actuator that
carries them out. Every command goes through it. For each command it writes one record,
waits until the record is on disk, and only then passes the command on.

There are two layers.

- **The core** (sections 2 to 9) knows nothing about any law. It defines the records, the
  order of operations, the file format and the checks.
- **Profiles** (section 10) sit on top. A profile takes one specific rule, quotes it, and
  says which core records it needs and how long they must be kept. One profile is specified
  here. Three more are listed and not built.

Two programs, as in LogChain and asof-gate:

- the **recorder**, which writes the journal;
- the **verifier**, a second implementation written from this document. It imports nothing
  from the recorder and uses only the Python standard library.

## 2. Terms

| term | meaning in this document |
|---|---|
| controller | whatever produces a command: a planner, a model, a remote operator |
| safety layer | the component that may change or block a command before it is carried out |
| actuator | whatever carries a command out |
| requested command | the command as the controller issued it |
| applied command | the command the recorder passes to the actuator, after the safety layer |
| ruleset | the safety rules in force, as one JSON file (section 5) |
| intervention | any change to safety-critical software, to the ruleset, or to configuration |
| journal | the file of records, in LogChain journal format version 2 |
| root | the Merkle root over the journal, as LogChain defines it |
| safe-state action | what the recorder sends to the actuator when it cannot record (section 4) |

## 3. Where the recorder sits

```
controller --requested--> [ recorder ] --requested--> safety layer
                          [ recorder ] <--applied, rules that acted-- safety layer
                          [ recorder ] --record written and synced to disk
                          [ recorder ] --the record, its number, its hash--> [ gate ] --applied--> actuator
```

The gate is on the actuator's side and is a separate program (section 4.2). It owns the
last hop. Nothing reaches the actuator from the recorder except through it. That is a
property of how the machine is wired, and the software cannot prove it. See section 11.

## 4. Core rule 1: record first, then forward

For every command, in this order:

1. receive the requested command;
2. obtain the applied command and the list of rules that acted (section 5);
3. build the command record (section 7.2);
4. append it to the journal and flush it to stable storage (`fsync` or the platform's
   equivalent);
5. only if step 4 reported success, send the record, with its number and its hash, to the
   gate on the actuator's side (section 4.2). The gate passes the applied command on.

If any of steps 2 to 4 fails, the recorder MUST NOT send the record. It sends a safe-state
message instead, and keeps doing so until an operator restarts it.

What this gives, stated exactly:

- **Every command the actuator received from the recorder has a record.** There is no code
  path from input to actuator that skips step 4. Section 4.2 is what holds the recorder to
  this from the other side.
- **The reverse does not hold.** If power is lost between step 4 and step 5, the journal
  holds a record of a command that never arrived. The journal can contain more than what
  happened. It cannot contain less, for commands that went through the recorder.

Why the order is this way round: writing the record after forwarding would let a crash
produce a command with no record, which is the one failure this tool exists to rule out.

### 4.1 Stopping must never depend on the recorder

A recorder that blocks commands when it cannot write could block a stop command. That is
not acceptable for a machine, and the regulation in section 10 says so directly (Annex III,
1.2.1: "the machinery or related product shall not be prevented from stopping if the stop
command has already been given").

So:

- the safe-state action is fixed in configuration before the machine runs, and for most
  machines it is a stop;
- when recording fails, a stop command and a failed recorder therefore lead to the same
  place;
- a hardware emergency stop MUST act on the actuator directly and MUST NOT pass through the
  recorder. The recorder does not see it. That is a deliberate gap and section 11 names it.

For a machine where stopping is not the safe state (an aircraft in flight, for example),
the integrator chooses the safe-state action. This specification does not choose it for
them and does not claim any choice is safe.

### 4.2 The gate: what is enforced at the actuator

Section 4 is a promise the recorder makes about itself. The gate is there so that the
promise does not have to be taken on trust.

The gate (`gate/actuator_gate.py`) is a small program on the actuator's side. It shares no
code with the recorder. It keeps two things: the number and the hash of the last record it
accepted. The recorder sends it every record, of every kind, as
`{"type": "record", "n": <number>, "hash": <leaf hash>, "record": <the record's text>}`.

For each message the gate checks that:

- the hash is `SHA-256(0x00 || record text)`;
- the record's `n` is one more than the last accepted, and its `prev` is the last accepted
  hash. The first record it ever accepts must be a genesis record;
- a command record's outcome and applied command agree in form.

Then:

- for an accepted command it passes the record's own `applied` to the actuator. The action
  is read out of the record. Anything sent beside the record is ignored;
- for an accepted blocked command it sends the safe-state action;
- for a refused message it sends the safe-state action and its state does not move;
- a `{"type": "safe_state"}` message is always obeyed. Stopping needs no record.

The safe-state action is set on the gate's side. The gate does not take it from the
recorder.

**What this enforces.** No command reaches the actuator unless it arrives inside a record
that extends the chain the gate has seen. A command with no record, a replayed command, a
record out of order, a record from a different journal and a record whose text was changed
are all refused. A recorder that drops, skips or loses a record cannot continue: its next
record does not follow the gate's head, so the gate refuses it and everything after it.

**What this cannot enforce.** The gate sees a record. It cannot see whether that record
reached the disk. A recorder that forwards before it writes, and then fails to write, gets
that one command through. The gate's head is then a record the journal does not hold. Two
things follow, and both are tested:

- the verifier, given the gate's state file, reports `GATE_HEAD_NOT_IN_JOURNAL`;
- on restart the recorder's first record does not follow the gate's head, and the gate
  refuses it. The machine stays in the safe state until someone resolves the difference.

So the completeness claim is this. For every command the actuator received, the gate
accepted a record. Whether every record the gate accepted is in the journal is checked by
comparing the gate's head with the journal.

**How many unrecorded commands can pass before that comparison is made.** With this
recorder, one. It stops at the first failed write, and when it is restarted it takes its
head from the journal, which the gate then refuses. That is the
`planted-bug-forward-first` test.

The gate alone does not guarantee that number. A recorder that forwarded first, ignored
failed writes and kept its chain in memory would show the gate a well-formed chain for as
long as it ran, and every one of those commands would pass. That is the
`planted-bug-forward-and-ignore-failed-write` test: two unrecorded commands reach the
actuator. The comparison still catches it afterwards, with the same finding. An earlier
draft of this section said more than one could not pass. That was wrong, and the second
test exists because of it.

Closing this would need the gate to see evidence that a record is on disk, or held by a
witness, before passing the command on. That is not built.

The gate's head has a second use. Each record names the hash of the one before it, so the
head covers the whole history up to that point. It is a copy of the chain's head held
outside the journal's directory, on a different component.

In this build the gate reads the messages from a file and runs after the recorder, a
message at a time in scenario 5. Its decisions depend only on the order of the messages,
so the answers are the ones an in-line gate would give. An in-line gate is not built.

## 5. Core rule 2: requested and applied, and which rule acted

### 5.1 Integers only

A command is a JSON object whose values are integers or strings, in fixed units named in
the configuration (millimetres per second, not metres per second as a decimal). Floats and
booleans are rejected. Reason, taken from asof-gate: two implementations can write the same
float differently, and then their hashes disagree for no real reason.

A command that is not in this form is refused: no record is written, nothing is sent to the
actuator, and the recorder carries on. This is the one case where an input leaves no
record, and it is safe for the completeness claim because nothing was forwarded.

### 5.2 The ruleset

A ruleset is a JSON file: a `ruleset_id`, a `kind`, and an ordered list of rules. Draft 0
defines two kinds of rule, both checkable by arithmetic:

| rule `type` | fields | effect |
|---|---|---|
| `clamp` | `field`, `min`, `max` | if the command's `field` is outside `[min, max]`, set it to the nearer bound |
| `block_when` | `input`, `op` (`lt`, `le`, `eq`, `ge`, `gt`), `value` | if the named safety input compares true, block the command |

Every rule also has an `id`, a string. `min` MUST NOT be above `max`. A ruleset holding any
other rule type is not usable: the recorder goes to the safe state and the verifier reports
`RULESET_UNAVAILABLE`.

Rules are applied in file order to the requested command. A `block_when` that fires ends
evaluation: the result is `blocked`, and the recorder sends the safe-state action. Every
rule that changed the command or blocked it is listed by `id`, in order, as `rules_acted`.

Two edge cases, fixed here so both implementations agree:

- a `block_when` whose input is absent from the safety inputs, or is not an integer, fires.
  A missing safety signal is treated as unsafe;
- a `clamp` whose field is absent from the command, or is not an integer, does nothing.

The `outcome` of a command is `unchanged`, `changed` or `blocked`.

### 5.3 Two kinds of ruleset

- `"kind": "declared"`: the ruleset file is the real rule. The verifier recomputes the
  applied command and `rules_acted` from the requested command, the recorded safety inputs
  and the ruleset, and compares.
- `"kind": "opaque"`: the real safety layer cannot be written in the table above (a
  certified safety controller, say). The recorder records what the safety layer reported.
  The verifier checks the record is well formed and says the outcome was **not recomputed**.
  It never reports an opaque command as verified.

In both cases the record also carries `reported`, what the safety layer itself said it did.
For a declared ruleset, a difference between `reported` and the recomputed result is a
finding (section 8).

## 6. Core rules 3 and 4: versions, interventions, decision data

### 6.1 State in force

At any point in the journal, three things are in force:

- `software`: a map from component name to `{version, sha256}` for each safety-critical
  component;
- `ruleset_sha256`: the SHA-256 of the ruleset file's bytes;
- `config_sha256`: the SHA-256 of the configuration file's bytes.

The first record in a journal is a `genesis` record that states all three. After that, they
change only through intervention records.

The genesis record also carries `settings`: `heartbeat_seconds`, `measure_every` and
`safe_state_action`, copied from the configuration file. An intervention that changes the
configuration carries the new `settings`. This is how the verifier knows the heartbeat
interval without being handed the configuration file.

The set of software components is fixed at genesis. A change found by measurement keeps the
last declared version string, because nobody told the recorder a new one; only the hash
changes.

### 6.2 Interventions

Two record kinds, kept apart on purpose:

- `intervention_declared`: a change made through the recorder's own change command. It
  carries what changed, the old and new hashes, who the operator said they were, and a
  free-text reference (a ticket number, for example).
- `intervention_detected`: the recorder measured the installed files (at start, and every
  `measure_every` commands) and a hash did not match the state in force. No one declared
  it. It carries what was measured and what was expected.

The recorder does not label an intervention legitimate or illegitimate. It records which of
the two kinds it was. Whether an undeclared change was an attack, a mistake or a routine
update done the wrong way is for a person to decide, and reports from this tool MUST NOT
say which.

After a detected intervention the recorder treats the measured hashes as in force, so every
later command names the software that was actually running.

### 6.3 Every command names what was in force

Each command record carries `in_force`: the SHA-256 of the canonical form (section 7.1) of
the state in section 6.1 at that moment. The verifier replays the journal from genesis,
tracks the state itself, and checks each command's `in_force` against its own.

### 6.4 Decision data

When the controller is autonomous, a command MAY carry `decision`: what the safety-related
decision was based on. Draft 0 does not define its contents. It is a JSON object the
integrator supplies (sensor readings used, model version, thresholds, confidence as an
integer).

It is stored outside the journal as a file named by its SHA-256. The command record holds
only `decision_sha256` and `decision_bytes`. Two reasons:

- decision data is large, and can be personal data;
- section 10 needs it kept for one year while other records are kept for five. A file
  outside the journal can be deleted without breaking the Merkle root. A record inside it
  cannot.

The integrator decides what goes in `decision`. The recorder commits to whatever it was
given. It has no way to know something was left out.

## 7. Core rule 5: the journal and receipts

### 7.1 Canonical form

`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)` encoded as
UTF-8. This is asof-gate's canonical form, unchanged.

### 7.2 Records

The journal is a LogChain version 2 journal, exactly as `logchain/docs/FORMAT.md` defines
it. Each LogChain entry's `raw` field is the canonical form of one record. Nothing in
LogChain's format changes, so the two existing LogChain verifiers can check the chain of
any journal this recorder writes.

LogChain's own `seq` and `ingested_at` are not covered by any hash (FORMAT.md section 7).
So every record repeats what it needs inside `raw`, where the leaf hash covers it:

```
common to every record:
  "schema": "sentinel-ledger/record/0"
  "kind":   "genesis" | "recorder_start" | "recorder_stop" | "command"
            | "intervention_declared" | "intervention_detected" | "heartbeat"
            | "recorder_fault"
  "n":      position in the journal, from 0
  "prev":   hex leaf hash of record n-1, or "" for n = 0
  "at":     recorder clock, UTC, whole seconds, exactly YYYY-MM-DDTHH:MM:SSZ

genesis:
  "machine", "state" (section 6.1), "settings"

command:
  "requested", "applied" (null when blocked), "outcome", "rules_acted",
  "reported" (an object with the same three fields: "applied", "outcome",
  "rules_acted"), "safety_inputs", "in_force", and optionally "decision_sha256",
  "decision_bytes"

intervention_declared:
  "target" ("ruleset", "config" or "software:<name>"), "old", "new", "operator",
  "reference", "authorisation" (null; reserved for a signature, not checked), and
  "settings" when the target is "config". For "ruleset" and "config", old and new are
  SHA-256 hex strings. For software they are {"version", "sha256"}.

intervention_detected:
  "changes": a list of {"target", "expected", "measured"} in the same forms, and
  "settings" when the configuration changed.

recorder_start, recorder_stop:
  written when the recorder starts and when it shuts down in an orderly way. A long gap
  between a stop and the next start is time the recorder was switched off. A long gap
  anywhere else is a finding.

heartbeat:
  written every `heartbeat_seconds` when no record has been written. It shows the
  recorder was running. A silent journal with no heartbeats is then visible as a gap.

recorder_fault:
  "step", "detail". Written, when possible, on entering the safe state.
```

The data directory holds `logchain.journal` and `logchain.state` (LogChain's names),
`rulesets/<sha256>.json` (every ruleset that was ever in force, by the hash of its bytes),
`decisions/<sha256>.json` and `anchors/` (section 7.5).

`at` is the recorder's own clock. It is covered by the hash, so it cannot be edited later
without detection. It is still only what the recorder's clock said. It is not a trusted
timestamp.

### 7.3 Receipts

A receipt for record `n` is a LogChain inclusion proof (FORMAT.md section 9) plus the
record itself: `{"receipt_schema": "sentinel-ledger/receipt/0", "record": <the raw text>,
"proof": <the LogChain proof object>}`. A receipt is tied to the root it was cut against. It
does not verify against an earlier or later root. Someone who holds a root can confirm that record was in the journal the root
covers, without the rest of the journal.

### 7.4 Where the root comes from

LogChain's limits apply here in full and are restated because everything depends on them: a
root kept beside the journal proves only that two files agree. Whoever can edit the journal
can recompute the root. The verifier warns when the root is read from the state file.

### 7.5 Anchoring

Anchoring means getting a root to somewhere the journal's keeper cannot rewrite it.

**Statements.** Every `anchor_every` records (a setting in the configuration file), and at
an orderly stop, the recorder writes a statement to `anchors/<entry count, 8 digits>.json`,
in canonical form:

```
{"schema": "sentinel-ledger/anchor/0",
 "journal_id":  <leaf hash of record 0>,
 "entry_count": <number of records the root covers>,
 "root":        <Merkle root of the first entry_count records>,
 "last_at":     <the "at" of the last record covered>}
```

The recorder does nothing else. It makes no network call, so a slow or absent witness
cannot hold up a command. A separate program, `anchor/anchor_roots.py`, delivers the
statements.

**A witness.** `witness/witness.py` is a separate process. It stores the statements it is
sent, with the time it received each, and never changes or removes one. It refuses a
statement that gives a different root for a journal and entry count it already holds. It
has never seen the journal and checks nothing about the root.

**RFC 3161 timestamps.** `anchor_roots.py request` makes a timestamp request for each
statement; the request carries the statement's SHA-256 and nothing else. `anchor_roots.py
fetch --freetsa` sends the requests to FreeTSA and saves the tokens. It is the only command
in this repository that contacts another machine, and it refuses to run without the flag.
`anchor_roots.py verify --ca FILE` checks, with openssl, that each statement has a token
valid for that statement under that authority, and reports how long after the last record
the token was issued. The openssl calls are `ts -query -digest ... -sha256 -cert` and
`ts -verify -data ... -in ... -CAfile ...`.

**What the verifier does with them.** Given a witness's store (`--witness-store`) or a
directory of statements (`--anchors`), the verifier recomputes the root of the first
`entry_count` records for every anchor that names this journal and requires each to match.
A journal with no anchor at all in the store it was given is a finding too. The findings
are in section 8.

**What each one buys, and what it does not.**

- A witness's store catches a rewrite of any record an anchor covers, provided the witness
  is run by someone other than whoever keeps the journal. Run by the same party it proves
  nothing. In the demo it runs on the same machine, which shows the mechanism and nothing
  about custody.
- A timestamp shows a statement existed at a time. It does not stop someone rewriting the
  journal and having the new root stamped later, because an authority will stamp anything.
  Two things narrow that: `--max-lag-seconds` makes a token issued long after the records
  it covers a finding, and tokens held by another party cannot be replaced. The verifier
  itself does not check tokens. It uses only the standard library and does not parse RFC
  3161. Checking a journal against timestamps is two steps: the verifier with `--anchors`,
  and `anchor_roots.py verify`.
- Records written after the last anchor are covered by nothing outside the journal. The
  verifier reports how many there are.
- Neither says anything about a record that was never written, or about what a record left
  out.

**The test an anchor has to pass.** Can a skeptical third party, who does not trust whoever
runs the recorder or whoever wrote it, verify the result without trusting either? For the witness the answer is yes only when the third party, or someone they
trust, runs it. For timestamps the party trusted is the timestamping authority. Not built:
more than one witness, witnesses that sign what they store, and RFC 6962 consistency proofs
between successive roots. Until they are, a witness must keep every root and the verifier
must check every one. A witness run only by whoever supplies the recorder would make that
supplier the one party everyone has to trust, which is what anchoring is meant to avoid.

## 8. The verifier

```
python verifier/verify_journal.py JOURNAL --rulesets DIR [--root HEX]
                                  [--witness-store FILE] [--anchors DIR] [--gate-state FILE]
                                  [--decisions DIR] [--profile FILE --as-of YYYY-MM-DD] [--json]
python verifier/verify_journal.py --receipt FILE --root HEX
```

`--state FILE` may replace `--root`. The verifier then prints a warning that the root came
from beside the journal.

It does three things, in order, and stops at the first level that fails.

**Level 1, the chain.** LogChain FORMAT.md section 8: every leaf hash, then the root. Its
own implementation of RFC 6962, not LogChain's code. Then, if they were given, the anchors
and the gate's head:

| finding | condition |
|---|---|
| `NO_ANCHOR_FOR_JOURNAL` | the witness store or statement directory holds no anchor whose `journal_id` is the leaf hash of record 0 |
| `ANCHOR_MISMATCH` | an anchor's root is not the root of the journal's first `entry_count` records, or its `last_at` is not the time of the last record covered |
| `ANCHOR_BEYOND_JOURNAL` | an anchor covers more records than the journal holds |
| `GATE_HEAD_NOT_IN_JOURNAL` | the record the gate last accepted is not at that position in the journal |

When a witness store is given, `--root` may be left out. The journal is then checked
against the witness's anchors alone.

**Level 2, the records.** For each record, in order:

| finding | condition |
|---|---|
| `RECORD_MALFORMED` | `raw` is not canonical JSON of a known kind, or holds a float or boolean |
| `POSITION_MISMATCH` | `n` is not the record's position |
| `PREV_MISMATCH` | `prev` is not the leaf hash of the record before |
| `CLOCK_BACKWARDS` | `at` is earlier than the record before |
| `NO_GENESIS` | record 0 is not a genesis record |
| `IN_FORCE_MISMATCH` | a command's `in_force` is not the hash of the replayed state |
| `RULESET_UNAVAILABLE` | the ruleset in force is not in `--rulesets`, or its bytes do not hash to `ruleset_sha256` |
| `RULE_MISMATCH` | declared ruleset: recomputed `applied`, `outcome` or `rules_acted` differs from the record |
| `REPORTED_MISMATCH` | declared ruleset: `reported` differs from the recomputed result. Opaque ruleset: the record's own outcome differs from `reported` |
| `HEARTBEAT_GAP` | more than `2 * heartbeat_seconds` between consecutive records, unless the first is a `recorder_stop` and the second a `recorder_start` |
| `DECISION_MISMATCH` | a decision file is present and does not hash to `decision_sha256`, or is not `decision_bytes` long |

A receipt is checked for `RECEIPT_LEAF_MISMATCH` (the record is not the leaf the proof is
about) and `RECEIPT_ROOT_MISMATCH` (the proof does not lead to the supplied root).

Informational, never findings: commands under an opaque ruleset are counted as
`not_recomputed`; decision files that are absent are counted as `decision_absent`; time
between a stop and a start is listed as stopped time; a `recorder_start` that does not
follow a `recorder_stop` is counted, since it means the recorder ended without an orderly
shutdown.

**Level 3, a profile**, only when `--profile` is given. Section 10.4.

Exit codes follow LogChain: `0` clean, `2` a finding, `1` usage or I/O error.

The verifier never reads the wall clock. Anything that depends on a date takes `--as-of`,
as asof-gate does, so the same inputs always give the same output.

### 8.1 What the verifier establishes

- No record was altered, added, removed or reordered after the root was taken, **if** the
  root came from somewhere the journal's keeper cannot reach. With a witness's store, the
  same for every record an anchor covers, **if** the keeper cannot reach the witness.
- With the gate's state, that the last record the actuator's side accepted is in the
  journal.
- Each command names the state the journal's own interventions put in force.
- Under a declared ruleset, the recorded outcome is what that ruleset gives for the
  recorded request and the recorded safety inputs.

### 8.2 What it does not establish

- That the safety inputs were true.
- That the real safety layer ran the declared ruleset. `REPORTED_MISMATCH` catches a
  disagreement. Agreement does not prove the layer is correct.
- That the command reached the actuator, or that the actuator obeyed.
- That nothing happened outside the recorder.

### 8.3 Showing the checks can fail

Before any result is trusted, the build plants bugs in the recorder (wrong clamp bound,
skipped rule, stale `in_force`, record written after forwarding, the same with failed
writes ignored, heartbeats not written) and confirms a check exits non-zero for each. Each
bug is a Cargo feature that is off by default. The table of planted bugs and which check
caught each is in the README.

The recorder that forwards before it records is the instructive one. Its journal is a
clean journal: the verifier given the journal alone finds nothing. It is caught by the
gate, in the two ways section 4.2 describes: the verifier given the gate's state exits 2,
and after a restart the gate refuses the recorder. Neither uses the demo actuator's own
log. The gate does not prevent the one unrecorded command, and the test says so.

Two implementations agreeing means little until the comparison has been shown to fail.
LogChain's version 1 root collision passed both of its implementations.

## 9. Language

Recorder in Rust (`recorder/`), using the `logchain` crate for hashing, the journal and
inclusion proofs. Verifier in Python (`verifier/verify_journal.py`), standard library only,
with its own RFC 6962 code. Two languages keep the two implementations from sharing code
by construction. A test checks the verifier's import
list.

The recorder reads one JSON operation per line on standard input (`command`, `declare`,
`tick`, `measure`) and answers each with one JSON line. The link to the gate is a file it
appends messages to, and the actuator is a file the gate appends accepted actions to. There
is no real transport yet. The gate, the witness and the anchoring tool are Python, standard
library only, and import nothing from each other, the verifier or the recorder.

## 10. Profiles

### 10.1 What a profile is

A JSON file. For each provision of one rule it holds:

- the citation and the provision's text, quoted exactly;
- the SHA-256 of the source document the quote was taken from;
- which core record kinds the provision is mapped to;
- the retention period and what it is counted from;
- `reading`: one or two sentences saying how this profile reads the provision, marked as
  this project's reading.

A profile adds no record kinds and changes no core rule. If a rule needs something the core
does not record, the profile says so. It does not stretch a core record to fit.

### 10.2 Profile built now: Regulation (EU) 2023/1230, Annex III

Source: Regulation (EU) 2023/1230 of the European Parliament and of the Council of 14 June
2023 on machinery, OJ L 165, 29.6.2023, p. 1. English text retrieved 2026-10-08 from the
Publications Office (`publications.europa.eu/resource/celex/32023R1230`), kept at
`sources/eu/32023R1230_OJ_L165_2023-06-29_en.xhtml`, SHA-256
`45172093d5547c21c9f7d5da2628e5c630b5e7e586e163aff6b7c936ded17b48`.

Application date. Article 54, second paragraph, as published: "It shall apply from 14
January 2027." The Corrigendum to the Regulation (OJ L 169, 4.7.2023, p. 35), item 10,
replaces "14 January 2027" in that paragraph with "20 January 2027". **The Regulation
applies from 20 January 2027.** The corrigendum was retrieved 2026-10-08 from the
Publications Office (`publications.europa.eu/resource/celex/32023R1230R(01)`), kept at
`sources/eu/32023R1230R01_OJ_L169_2023-07-04_en.xhtml`, SHA-256
`8ccfcc43b3a86d102bc711d4f2c14d3be44ae2c2d8cb3e32e44d2bb933f44bf8`. Its 14 items change
dates in Articles 6, 47 and 50 to 54. None changes Annex III.

All three provisions are in Annex III, Part B. The quotes are verbatim from the first file,
and `tests/test_profile.py` fails if any quotation in the profile is not found in it word
for word. The profile is `profiles/eu_2023_1230_annex_iii.json`.

**Provision A. Annex III, 1.1.9 (Protection against corruption), second paragraph, second
sentence, and fifth paragraph.**

> The machinery or related product shall collect evidence of a legitimate or illegitimate
> intervention in that hardware component, when relevant for connection or access to
> software that is critical for the compliance of the machinery or related product.

> The machinery or related product shall collect evidence of a legitimate or illegitimate
> intervention in the software or a modification of the software installed on the machinery
> or related product or its configuration.

- Records: `intervention_declared`, `intervention_detected`, and the `genesis` record they
  are measured against.
- Retention: 1.1.9 states no period. The profile sets none of its own. Where the same
  record also falls under provision B, B's period applies.
- Reading: "legitimate or illegitimate" is covered by recording both declared changes and
  changes found by measurement. The recorder does not decide which word applies.
- Not covered: the first quote concerns a hardware component "transmitting signal or data".
  The core measures software, the ruleset and configuration files. It records nothing about
  hardware. This profile maps the fifth paragraph and marks the second as **not mapped**.

**Provision B. Annex III, 1.2.1 (Safety and reliability of control systems), second
paragraph, point (f).**

> the tracing log of the data generated in relation to an intervention and of the versions
> of safety software uploaded after the machinery or related product has been placed on the
> market or put into service is enabled for five years after such upload, exclusively to
> demonstrate the conformity of the machinery or related product with this Annex further to
> a reasoned request from a competent national authority.

- Records: `intervention_declared`, `intervention_detected`, `genesis`, and the `in_force`
  field of every command, which ties each command to a software version.
- Retention: five years, counted from the `at` of each intervention record that changes a
  software version.
- Reading: "enabled for five years after such upload" is read as: the records about an
  upload must still be present and verifiable five years after it.

**Provision C. Annex III, 1.2.1, third paragraph, point (b).** The third paragraph opens:
"Control systems of machinery or related products with fully or partially self-evolving
behaviour or logic that are designed to operate with varying levels of autonomy shall be
designed and constructed in such a way that:"

> recording of data on the safety related decision-making process for software based safety
> systems ensuring safety function including safety components, after the machinery or
> related product has been placed on the market or put into service, is enabled and that
> such data is retained for one year after its collection, exclusively to demonstrate the
> conformity of the machinery or related product with this Annex further to a reasoned
> request from a competent national authority;

- Records: command records with `decision_sha256`, and the decision files they name.
- Retention: one year, counted from the command record's `at`.
- Reading: the decision file is the "data on the safety related decision-making process".
  What goes in it is the integrator's choice (section 6.4).

A citation note. Section 1.2.1 has three lettered lists. "1.2.1(b)" alone could mean point
(b) of the second paragraph ("a fault in the hardware or the logic of the control system
shall not lead to hazardous situations"). The profile always cites paragraph and point.

Both B and C say the records exist "exclusively to demonstrate the conformity ... further
to a reasoned request from a competent national authority". The profile carries those words
in its `purpose` field. They matter for the second future profile in section 10.5.

### 10.3 Retention and deletion

The periods above are minimums: the least time records must be kept. Draft 0:

- never deletes journal records. Deleting one would change the root;
- allows decision files to be deleted once every profile in use has released them;
- lists, in the verifier's profile report (`--profile FILE --as-of DATE`), what is held,
  what each provision still requires on that date, and which decision files may be
  released. Nothing deletes anything.

Journals that grow for five years need rotation into sealed segments. That is not in this
build (section 14).

Years are counted on the date part of `at`. One year after 2026-10-01 is 2026-10-01 of the
next year, and a file is still required on that day. 29 February plus a year is 28
February.

### 10.4 What the verifier reports for a profile

For each provision: which mapped records are present, the earliest date any of them may be
released, and any record required on `--as-of` that is missing. A missing decision file
inside its one-year period is the finding `RETENTION_SHORTFALL`. Outside it, it is
`decision_absent` and not a finding.

The wording is fixed: "the journal holds the records this profile maps to provision B". The
verifier MUST NOT print "compliant", "conforms" or "meets the regulation".

### 10.5 Candidate profiles, listed and not built

1. **California Vehicle Code section 38750, subdivision (c), paragraph (1), subparagraph
   (G): the separate pre-collision recorder.** Among the things a manufacturer's application
   must certify:

   > The autonomous vehicle has a separate mechanism, in addition to, and separate from, any
   > other mechanism required by law, to capture and store the autonomous technology sensor
   > data for at least 30 seconds before a collision occurs between the autonomous vehicle
   > and another vehicle, object, or natural person while the vehicle is operating in
   > autonomous mode. The autonomous technology sensor data shall be captured and stored in
   > a read-only format by the mechanism so that the data is retained until extracted from
   > the mechanism by an external device capable of downloading and storing the data. The
   > data shall be preserved for three years after the date of the collision.

   Text read 2026-10-08 on `california.public.law/codes/vehicle_code_section_38750`, a
   republication of the code. The Legislature's own site (`leginfo.legislature.ca.gov`)
   refused automated retrieval, so the wording has not been compared with it by this
   project.

   This needs a record kind the core does not have: a fixed window of sensor data around a
   trigger. It would be a core change first and a profile second. Who defines the trigger
   is an open problem: if the operator does, an omission can happen before the recorder
   is ever involved.
2. **Insurance and billing use.** No single rule to quote. Two cautions to resolve before
   any design: the EU text above limits its records to demonstrating conformity on an
   authority's request, so reuse for pricing or billing is a separate legal question; and
   a model in which the audited party is the only one paying for its own audit trail has a
   conflict of interest built in.
3. **The 2022 ethical black box draft standard.** Alan F. T. Winfield, Anouk van Maris,
   Pericle Salvini and Marina Jirotka, "An Ethical Black Box for Social Robots: a draft Open
   Standard", arXiv:2205.06564, submitted 13 May 2022. Title, authors and date confirmed
   against the arXiv record on 2026-10-08. The paper itself has not been read for this
   draft. A profile would map what it says a robot should log onto `decision` contents.

## 11. What this is not

- **Not certified.** No notified body, test house or authority has examined it. Using it
  does not make a machine conform to Regulation (EU) 2023/1230 or to anything else. The
  duties in that regulation fall on the manufacturer. A profile shows which records exist.
  Whether they are sufficient is for the manufacturer and the authority.
- **Not a safety system.** It does not make a machine safe and is not a safety component.
  It records what a safety layer did. It has not been developed to any functional-safety
  standard, and it adds a failure mode of its own: when it cannot write, the machine goes to
  its safe state.
- **It cannot see anything that bypasses the command path.** A hardware emergency stop, a
  second controller wired straight to the actuator, a manual override, a fault inside the
  actuator: none of these produce a record. "Every command has a record" means every command
  that went through the recorder. Whether that is every command the machine received
  depends on the wiring, which this software cannot check.
- **Not proof that the record is true or whole.** Hashing shows the journal was not changed
  afterwards. It says nothing about whether the safety inputs were accurate, whether the
  decision data left something out, or whether a journal was simply never produced. This is
  the limit set out in LogChain's `docs/LIMITS.md`, and nothing here gets round it.
- **Not signed.** A root commits to content. It does not say who wrote the journal. A
  timestamp token, when one is fetched, says a root existed by a certain time and nothing
  more.
- **Not a verdict.** It records declared and detected changes. It never says a change was
  improper or who was at fault.

## 12. Decisions taken (8 October 2026)

1. This is Sentinel Ledger version 1.
2. Recorder in Rust on the `logchain` crate; verifier in Python, standard library only.
3. Demo machine: a simulated one-axis conveyor. A clamp on `speed_mm_s` (0 to 1500), a
   block when `light_curtain_clear` is 0, safe state `speed_mm_s` 0.
4. Journal rotation is not in the first build and is stated as a limit.
5. A declared intervention has an `authorisation` field, reserved. No signature is checked.
6. Name: Sentinel Ledger.

Changes made to the approved draft while building, each because the build showed the draft
was incomplete:

- two record kinds were added, `recorder_start` and `recorder_stop`. Without them every
  restart of the recorder would have been reported as a heartbeat gap;
- the genesis record carries `settings`, so the verifier can know the heartbeat interval;
- the two edge cases in section 5.2 (absent input, absent field) were not in the draft;
- a fifth planted bug (heartbeats not written) was added to the four the draft named;
- the `retention` command became part of the verifier's profile report.

Second round, the same day, after the first build was reviewed:

7. Anchoring: a witness process that stores the roots it receives, and RFC 3161
   timestamps as an option, with FreeTSA contacted only when a flag is given. Section 7.5
   says what this first form does and does not achieve.
8. An actuator-side gate, separate from the recorder, that refuses any command not
   carried by a record extending the chain. The recorder now forwards every record with
   its number and hash. Section 4.2.

Two corrections to decision 8. It was first put as: completeness is enforced at the
actuator and no longer trusted to the recorder. The gate enforces that every command
carries a chained record. It cannot enforce that the record was written. And the bound of
one unrecorded command, stated in an earlier draft as a property of the gate, is a
property of this recorder. Section 4.2 states both in the form the build supports.

## 13. Not verified

- Whether Regulation (EU) 2023/1230 has been amended since the corrigendum of 4 July 2023
  was not checked.
- California Vehicle Code 38750(c)(1)(G) was read on a republication, not on the
  Legislature's site (section 10.5).
- The Winfield et al. paper was confirmed to exist as cited. Its contents were not read.
- No harmonised standard for these Annex III provisions was looked for. If one exists it may
  say what "tracing log" must contain, and the profile would follow it.
- That a successful flush means the record survives power loss. The recorder asks the
  operating system to flush the journal after every record and treats a failure as a
  failed write. On some storage a flush that reports success has not reached the medium.
  No power-loss test has been run.
- The recorder has only been run on Windows.

## 14. Limits of this build

- **No live clock-driven heartbeat.** Heartbeats are written when the demo driver advances
  a fixed clock. With the system clock the recorder has no timer, so a quiet period would
  show as a gap. A real deployment needs one.
- **No transport.** Commands arrive as lines on standard input and the actuator is a file.
- **No journal rotation.** The journal grows without bound, and LogChain's append rereads
  the whole journal to recompute the root, so each record costs more than the last.
- **Anchoring is a first form.** One witness, unsigned, on localhost in the demo. No
  consistency proofs, no cosigning, no second witness. FreeTSA has not been called by any
  test or by this build: the timestamp path was exercised with a throwaway authority made
  by openssl. A real token from FreeTSA has not been fetched or verified here.
- **The gate is not in line.** It reads the recorder's messages from a file after they are
  written. It is a Python program standing in for logic that belongs in the actuator's
  controller.
- **The gate cannot see whether a record reached the disk.** With this recorder one
  unrecorded command can pass before the gap shows. A recorder that ignored failed writes
  could pass more, and is caught only when the gate's head is compared with the journal
  (section 4.2).
- **A write that half succeeds.** If the journal line is written and the state file update
  then fails, the recorder treats the write as failed and goes to the safe state. The
  record is in the journal and the command was not forwarded, which is the allowed
  direction of section 4. LogChain's state file is then one entry behind and must be
  rebuilt before the recorder is restarted. Nothing rebuilds it yet.
- **A refused command leaves no trace** (section 5.1).
- **Measurement is periodic.** A file changed and changed back between two measurements is
  not seen.
- **The reference safety layer lives inside the recorder.** In the demo the recorder
  evaluates the declared ruleset itself, so `reported` and the recorded outcome always
  agree unless a bug is planted. A real safety layer is a separate component, and
  `REPORTED_MISMATCH` only earns its place then.
