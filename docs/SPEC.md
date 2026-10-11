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
| gate | the check on the actuator's side that passes a command on only inside a valid record (section 4.2) |
| gate receipt | the gate's signed statement of what it did with a record or a message (section 4.5). Not the receipt of section 7.3, which is a proof that a record is in the journal |

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
- the record is signed by the recorder (section 7.6). The gate holds the recorder's
  public key and nothing that could sign a record;
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

What the gate did with each record goes back to the recorder as a signed receipt and into
the journal, when the gate has a key of its own. That is section 4.5.

**What this enforces.** No command reaches the actuator unless it arrives inside a record
that the recorder signed and that extends the chain the gate has seen. A command with no
record, a replayed command, a record out of order, a record from a different journal, a
record whose text was changed, and a record built by someone else to follow the chain are
all refused. A recorder that drops, skips or loses a record cannot continue: its next
record does not follow the gate's head, so the gate refuses it and everything after it.

**What this cannot enforce.** A signature shows the record was made by someone holding the
private key. Anyone who can read the recorder's key file can make records the gate
accepts. And the gate sees a record. It cannot see whether that record reached the disk. A recorder that forwards before it writes, and then fails to write, gets
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

### 4.3 The deadman: silence means the safe state

Record first, then forward, has a consequence. While the recorder cannot record, it
forwards nothing, and the actuator hears nothing. What the actuator does then must not be
"whatever it was last told".

So the gate has a deadman. `gate_deadman_seconds` is a setting in the machine's
configuration, a positive whole number. Once the gate has accepted a record, if no valid
record follows within that time it sends the safe-state action to the actuator, once, and
the actuator stays there until the next accepted command.

- **What counts.** Only a record the gate accepts: signed by the recorder and next in the
  chain. Heartbeat records count. A recorder that is alive and has nothing to say writes
  a heartbeat every `heartbeat_seconds`, the gate sees it, and the last command stays in
  force. A refused message does not count, nor does a safe-state message, so another
  node cannot hold the deadman off.
- **The value.** It has to be longer than `heartbeat_seconds` or a quiet recorder would
  trip it. The demo uses 4 seconds with a heartbeat of 2: the same length of silence the
  verifier calls a gap (section 8).
- **Where it runs.** On the actuator's side, on that side's clock. It needs nothing from
  the recorder, which is the point: it is what happens when the recorder says nothing.
- **Before the first record** the gate has passed nothing on, and the deadman does not
  run.
- **What it is not.** It does not judge a command's age. That is section 4.4.
- **What it does not watch.** The controller. Heartbeat records hold the deadman off, so
  if the controller dies or hangs while the recorder is alive, the actuator keeps its
  last command with no time limit. A timeout on a command that is not renewed is not
  built.
- **No latch.** After a trip, the next accepted command moves the actuator again. The
  same holds after a command refused for its age (section 4.4), a blocked command and a
  refused message. A stop that holds until someone deliberately resets it is not built.

The setting is in the genesis record's `settings` when the machine has one, and the
configuration file is hashed into the state in force, so every record names it.

The file demo's gate reads a file after the recorder has finished. It has no clock to run
a deadman against and does not run one. The simulated robot of section 15 does. The
planted bug for this is a gate with the deadman removed: the robot runs on for the whole
of the recorder's silence.

### 4.4 A command's age

The deadman covers silence. It does not cover what comes after: a command whose record
was held up, by a slow disk for example, and reaches the gate seconds late. It is a valid
record and it follows the chain. Carried out, it moves the machine on an instruction
that was right some seconds ago.

So every command record carries `received_ms`: the time the recorder received the
command, in milliseconds since 1970 on the recorder's clock, taken before the recorder
waits for anything. And the gate has a limit, `gate_max_command_age_ms`, a positive whole
number in the machine's configuration.

When a command record arrives, the gate takes its own wall clock and subtracts
`received_ms`:

- more than the limit: the command is not carried out. The safe-state action goes to the
  actuator;
- more than the limit in the other direction, a command dated ahead of the gate's clock:
  the same. The two clocks disagree by more than the limit and the gate does not guess;
- no `received_ms` in a command record: the same.

**The record is still taken into the chain.** It is a genuine, signed record and the
recorder's later records name it as their predecessor. If the gate dropped it, it would
refuse everything after it. Only the action is refused. The gate reports it as a refusal
and the simulated robot exits 2. Its receipt for that record says `refused`, reason `age`
(section 4.5), so the refusal is in the journal beside the record it is about.

Only command records have an age. A heartbeat or any other record is never stale.

**The limit of this check.** It compares two clocks. On one machine the recorder and the
gate read the same clock and the check is sound. On separate machines it is only as good
as the two clocks agree: a gate whose clock runs behind lets old commands through, and
one that runs ahead refuses fresh ones. Synchronized clocks are needed, and nothing in
this build provides or tests that. Two more: the age starts when the recorder's own code
first sees the command, so time the command spent before that (in a queue, on the
network) is not counted; and a wall clock can be stepped. A real controller would also
want the command's time of origin from the controller itself.

The planted bug for this is a gate with the age check removed: in scenario 11 the robot,
stopped by the deadman, starts moving again on a command six seconds old.

### 4.5 Receipts: what the gate did with each record

Sections 4.2 to 4.4 give the gate several ways not to carry a command out. Until this
section none of them reached the journal. A command the gate refused for its age was, in
the journal, a command recorded and forwarded, and the verifier had no finding for it.
The refusal was in the robot's own log and nowhere else.

So the gate answers. When it is given a signing key of its own, it signs a receipt:

- for every command record it takes into the chain: `applied` (the record's `applied`
  went to the actuator), `blocked` (the record says blocked, and the safe-state action
  went), or `refused` with the reason `age` (section 4.4);
- for every message it refuses: `refused`, with the reason `signature` (not signed by the
  recorder), `chain` (not the record after the gate's head, or a first record that is
  not a genesis record) or `form` (not a well-formed record message: no record in it, a
  hash that is not the record's, text that is not JSON, a command with no usable action);
- for every deadman trip (section 4.3): `deadman`.

Those four reasons are the four checks the gate makes. The gate checks no speed or range
limit of its own: limits are rules in the ruleset, applied before the record is written
and recomputed by the verifier (section 5).

An accepted record that is not a command (a heartbeat, for example) gets no receipt. A
`safe_state` message gets none either: it is not a record.

```
gate receipt:
  "schema":    "sentinel-ledger/gate-receipt/0"
  "seq":       the gate's own count of its receipts, from 0, with no gaps. Kept in the
               gate's state file, so it carries on when the gate restarts
  "decision":  "applied" | "blocked" | "refused" | "deadman"
  "reason":    "age" | "signature" | "chain" | "form" for a refusal, otherwise null
  "detail":    for a refusal, the gate's own sentence saying why, for example "the command
               is 6003 ms old; the limit is 1000 ms". For a deadman trip, how long the
               silence was. Otherwise null
  "n", "hash": the number and leaf hash of the record the receipt is about. For applied,
               blocked and refused for age: the command record. For a deadman trip: the
               last record the gate had accepted. For the other refusals both are null:
               those messages were never taken into the chain
  "sent":      the action the gate sent to the actuator
  "at_ms":     the gate's wall clock, whole milliseconds since 1970, or null where the
               gate has no clock
  "sig":       Ed25519 signature, with the gate's key, over the canonical form
               (section 7.1) of every other field, as 128 hexadecimal characters
```

**The gate's key** is not the recorder's. It is a second Ed25519 key. The private half is
a file on the gate's side that the recorder is never given. The public half is
`gate_public_key` in the machine's configuration, 64 hexadecimal characters. It is copied
into the first record's `settings`, and the configuration file is hashed into the state
in force, so every record names it. A receipt signed with the recorder's key would be a
statement the recorder could make without the gate. The gate still holds only the public
half of the recorder's key and cannot make a record. A configuration with no
`gate_public_key` means no receipts: the gate signs none, the recorder takes none, and the
verifier expects none. Changing the key is not supported, as for the recorder's
(section 7.6).

**Order on the gate's side.** The gate acts first, then signs, then saves its state with
the next receipt number in it, then sends the receipt. Signing a receipt does not delay
the stop that receipt is about, and a number is not used twice.

**The recorder** writes each receipt into the journal as a record of kind `gate_receipt`
(section 7.2), holding the receipt whole, signature included. Before it writes, it checks
two things: that the receipt is signed with the configured gate key, and that its `seq`
is higher than that of the last receipt in the journal. A receipt that fails either is not
written. So a receipt made by another node, or a genuine one sent twice, does not reach
the journal. The recorder does not judge what a receipt says. Like every record, the
`gate_receipt` record is numbered, chained, signed by the recorder and sent to the gate,
which takes it into the chain and issues no receipt for it.

One case needs a rule of its own. Once the gate's chain is broken it refuses every record,
and each refusal makes a receipt, whose record the gate would refuse in turn. So a record
of kind `gate_receipt` that is signed by the recorder and refused for its place in the
chain gets no receipt. Another node cannot use that to hide anything of its own: it
cannot sign a record.

**Before a stop** the recorder waits for the receipts of commands it has already
forwarded, for a bounded time (two seconds in the ROS node), because nothing is written
after the stop record.

**The verifier** (section 8) checks each receipt's signature against the gate key the
first record names, and reports:

- every refusal, with its reason, and every deadman trip. These are findings: something
  was sent to the machine that the gate did not carry out, or the recorder was silent;
- every command record that no receipt answers for, where the settings name a gate key;
- every gap in the gate's numbering: a receipt the gate issued that the journal does not
  hold;
- every receipt that is not the gate's, or does not belong to the record it names.

**What this adds.** A refusal is in the journal, signed by the component that made it,
beside the record it is about. The command record itself is unchanged: it still says what
was requested and what the safety layer applied. The receipt says what the gate then did.
To remove a refusal from the journal, or to turn it into `applied`, takes the gate's key
as well as the recorder's. With the recorder's key alone the rewritten receipt fails the
gate's signature, and a deleted one leaves a command without a receipt and a gap in the
numbering. Both are tests.

**What it does not add.**

- **It is the gate's statement.** It says what the gate sent. It does not show that the
  actuator obeyed. Anyone who can read the gate's key file can make receipts.
- **Two keys on one machine are still one custodian.** In the demo both key files belong
  to the same user. The separation is between components. It becomes a separation of
  custody only when the gate's key is somewhere the journal's keeper cannot read.
- **A receipt is sent once.** If the recorder is stopped, in the safe state or gone when
  a receipt arrives, the receipt is not written, and the gate does not send it again. The
  verifier then reports the command as having no receipt, or the gap in the numbering.
  That says the journal does not account for something. It does not say what the gate
  decided.
- **The numbering only shows a gap once something follows it.** A dropped receipt that
  was about a command always shows, as a command with no receipt. A dropped receipt for
  a refusal of something that was never a record shows only as a gap, and only when a
  later receipt is in the journal. If it was the last receipt the gate ever issued,
  nothing shows it.
- **A journal read while it is still being written** can have a command whose receipt has
  not arrived yet. The verifier reports it like any other.
- **A `safe_state` message leaves no receipt.** Any party that can reach the gate can
  send one and stop the machine without a trace in the journal.
- **Nothing limits the rate.** Every message the gate refuses costs it a signature and
  costs the recorder a record. A node that floods the gate's input fills the journal.
- **Cost.** A command is now two records and two flushes to disk: the command, and the
  receipt for it. The gate's signature is made in plain Python and is not written to
  hide the key from someone who can time it. Measured on one machine, it takes about
  4 ms when the machine is idle and about 11 ms with every processor busy, and checking
  a record's signature takes about the same. Both run in the simulated robot's one
  thread, and the deadman check waits while they do. The figures and what follows from
  them are in the README under "Time spent in the gate".
- **The file demo does not use it.** The gate program can sign receipts and append them
  to a file (`--gate-key`, `--receipts`), and the command-line recorder takes one with the
  operation `gate_receipt`. The five file scenarios do neither: their configuration names
  no gate key, and nothing carries a receipt back while the recorder runs.

The planted bugs for this are in the gate. One drops every receipt for a refusal before
it is sent: the robot behaves exactly as it should, and the verifier reports the command
with no receipt and the gap in the numbering. The other signs no receipts at all, which
is the gate as it was: the verifier reports every command.

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

The genesis record also carries `settings`: `heartbeat_seconds`, `measure_every`,
`safe_state_action` and `recorder_public_key`, copied from the configuration file. An intervention that changes the
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
            | "recorder_fault" | "storage_stall" | "anchor_failed" | "gate_receipt"
  "n":      position in the journal, from 0
  "prev":   hex leaf hash of record n-1, or "" for n = 0
  "at":     recorder clock, UTC, whole seconds, exactly YYYY-MM-DDTHH:MM:SSZ
  "sig":    Ed25519 signature over every other field, 128 hex characters (section 7.6)

genesis:
  "machine", "state" (section 6.1), "settings": "heartbeat_seconds", "measure_every",
  "recorder_public_key", "safe_state_action", and, when the configuration has them,
  "gate_deadman_seconds", "gate_max_command_age_ms", "gate_public_key"

command:
  "requested", "applied" (null when blocked), "outcome", "rules_acted",
  "reported" (an object with the same three fields: "applied", "outcome",
  "rules_acted"), "safety_inputs", "in_force", "received_ms" (when the recorder
  received the command, whole milliseconds since 1970 on its clock; section 4.4),
  and optionally "decision_sha256", "decision_bytes"

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

storage_stall:
  "step" (the longest write in the interval: "journal_write", "decision_file",
  "install" or "anchor_write"), "of_record" (the number of the record that write
  belonged to), "stalled_ms" (the time the recorder spent waiting for storage since the
  record before, in whole milliseconds, measured on the monotonic clock).

anchor_failed:
  "entry_count" (the number of records the lost anchor statement covered), "detail".
  Written when an anchor statement could not be written (section 7.5).

gate_receipt:
  "receipt": one receipt from the gate, whole, with the gate's signature (section 4.5).
  The record around it is signed by the recorder like any other.
```

**Storage stalls.** A record's `at` is taken when the record is built, before it is
written. If the write then takes eight seconds, the next record's `at` is eight seconds
later, and a reader sees a gap. The recorder knows why, and says so.

The rule is the verifier's own. The verifier calls it a gap when two consecutive records'
`at` values, which are whole seconds, differ by more than `2 * heartbeat_seconds`
(section 8). The recorder applies exactly that comparison, on the same clock and at the
same resolution, to the last record's time and the present, at two moments: as soon as a
record has been written and forwarded, and before it builds any record. If it is a gap by
that test, and the time the recorder spent waiting for storage since the last record
accounts for it by the verifier's own rule (the gap, less the storage time, is no more
than `2 * heartbeat_seconds`), the next record is a `storage_stall` record.

Because the recorder uses the verifier's test and not a stopwatch of its own, the two
cannot disagree about whether there is a gap. A write of 1.9 seconds that happens to
straddle three whole seconds is a gap to the verifier, and the recorder states it. A
write of 2.5 seconds that lands two whole seconds later is not a gap to the verifier, and
the recorder writes nothing, because there is nothing to explain. Both are tests.

- The time stated is measured on the monotonic clock, which a correction to the wall
  clock does not move. The decision to state it uses the wall clock in whole seconds,
  because that is what the records carry.
- A silence that storage does not account for gets no stall record. The recorder does not
  dress a hang up as a stall.
- Writing a stall record can itself be slow and leave another gap. At most three are
  written in one go.
- A stall in writing the `recorder_stop` record is not stated, because nothing is written
  after a stop.
- It is the recorder's statement. It is signed, so it cannot be added by someone without
  the key. The verifier cannot confirm that storage was the cause, only that the recorder
  said so and that the stated time accounts for the gap (section 8).
- The gate treats it as any other record.

The data directory holds `logchain.journal` and `logchain.state` (LogChain's names),
`rulesets/<sha256>.json` (every ruleset that was ever in force, by the hash of its bytes),
`decisions/<sha256>.json` and `anchors/` (section 7.5).

`at` is the recorder's own clock. It is covered by the hash, so it cannot be edited later
without detection. It is still only what the recorder's clock said. It is not a trusted
timestamp.

### 7.3 Receipts

This section is about receipts for a record's place in the journal. The gate's receipts,
which say what the gate did with a record, are section 4.5 and are a different thing.

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

A statement is written under a temporary name, flushed, and renamed into place, so a
reader never finds half a statement under a statement's name.

**Off the lock.** The command-line recorder writes each statement itself before it
carries on. The ROS node does not: it hands the statement to a thread that writes it, and
the recorder goes on to the next record at once (section 15.4). A statement is evidence
about records already on disk, so no record waits for it. Two consequences, both tested:

- a statement can land a little after the records it covers, and if the disk fails it may
  not land at all. That is not a fault and does not stop the machine. The recorder writes
  a signed `anchor_failed` record naming the statement that was lost, and the verifier
  reports it (`ANCHOR_FAILED`). A line on a status topic would be gone with the process;
  the journal is where the recorder says what happened to it. The command-line recorder
  does the same. The one exception is the last statement, written after the stop record:
  nothing is written after a stop, so its loss is not stated;
- nothing about verification changes. An anchor is only ever compared with a root
  recomputed from the journal. One that is late or missing removes a check, or is itself a
  finding (`NO_ANCHOR_FOR_JOURNAL`). It cannot make a check pass.

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

### 7.6 Signatures

Every record is signed with Ed25519 (RFC 8032).

- **What is signed.** The canonical form (section 7.1) of the record with every field
  except `sig`. The signature, as 128 lowercase hexadecimal characters, is then put into
  the record as `sig`. The leaf hash is taken over the record with `sig` in it, so the
  next record's `prev`, and the root, cover the signature as well.
- **The private key** is a file holding the 32-byte seed of RFC 8032 as 64 hexadecimal
  characters. It is kept outside the journal's directory. On Unix the recorder refuses to
  start if anyone but the file's owner can read it. `sentinel-recorder keygen --out FILE`
  makes one and prints the public key.
- **The public key** is `recorder_public_key` in the configuration file. The configuration
  file's hash is part of the state in force, so every record names, through `in_force`,
  the configuration that held the key it was signed for. The key is also copied into the
  first record's `settings`.
- **The recorder** refuses to start unless the key file is the private half of the
  configured public key.
- **The gate** is given the public key when it is started, from its own copy of the
  configuration. It refuses any record whose signature does not verify.
- **The gate's own key** is a second key of the same kind, used only to sign the gate's
  receipts (section 4.5). Its private half is a file on the gate's side, held to the same
  rule about who can read it. Its public half is `gate_public_key` in the configuration.
  The recorder checks a receipt against it before writing the receipt down, and the
  verifier checks every receipt in the journal against it.
- **The verifier** checks every record's signature against the key the first record
  names. Given `--public-key`, it also requires that key to be the one supplied, which is
  how a journal re-signed throughout with someone else's key is caught.

What a signature does and does not add:

- A node or a person without the key cannot make a record the gate accepts, and cannot
  rewrite a journal without the verifier seeing it, when the verifier is given the
  machine's public key.
- **Without `--public-key` the signature checks say nothing about whose key it is.** The
  verifier then takes the key from the first record. A journal re-signed throughout with
  another key, with that key written into the first record, verifies with no findings.
  The public key has to reach the verifier from somewhere the journal's keeper cannot
  write.
- **Anyone who can read the private key file can forge.** That includes the operator, and
  anything running as the recorder's user. Signatures do not make the journal evidence
  against the operator. Anchoring (section 7.5) and the gate's head are what do that.
- **Key rotation is not supported.** A configuration that names a different key is refused.
  A lost or exposed key means a new journal.
- **The key is a file.** Keeping it in hardware (a TPM, a secure element, an HSM) so that
  it cannot be copied is out of scope.
- The recorder signs with the `ed25519-dalek` library, and checks the gate's receipts
  with it. The gate and the verifier each carry their own verification code in plain
  Python, checked against two of the RFC's test vectors (section 7.1, tests 1 and 2) and
  no others. It takes about 4 ms a signature on an idle machine, so a long journal
  verifies slowly. The gate's signing code is plain Python too, checked against the same
  two vectors, and is not constant time.

## 8. The verifier

```
python verifier/verify_journal.py JOURNAL --rulesets DIR [--root HEX]
                                  [--witness-store FILE] [--anchors DIR] [--gate-state FILE]
                                  [--public-key HEX] [--gate-public-key HEX] [--decisions DIR]
                                  [--profile FILE --as-of YYYY-MM-DD] [--json]
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
| `HEARTBEAT_GAP` | more than `2 * heartbeat_seconds` between consecutive records, unless the first is a `recorder_stop` and the second a `recorder_start`, or the second is a `storage_stall` record that accounts for it (next row) |
| `STORAGE_STALL` | a `storage_stall` record: the recorder states how long it waited for storage. Reported for every such record. The gap ending at that record is not also reported as `HEARTBEAT_GAP` if the stated time accounts for it: the gap less `stalled_ms` is no more than `2 * heartbeat_seconds` |
| `ANCHOR_FAILED` | an `anchor_failed` record: the recorder states that an anchor statement could not be written. The records it would have covered have one piece of outside evidence fewer |
| `SIGNATURE_MISSING` | a record has no `sig` |
| `SIGNATURE_INVALID` | a record's `sig` is not a valid signature of its other fields under the key the first record names |
| `KEY_MISMATCH` | `--public-key` was given and the first record names a different key, or `--gate-public-key` was given and the first record names a different gate key or none |
| `GATE_REFUSED` | a `gate_receipt` record whose receipt says `refused`: the gate did not carry something out. Reported with the reason (`age`, `signature`, `chain`, `form`), the gate's own sentence, and, for `age`, the number of the command record refused |
| `GATE_DEADMAN` | a `gate_receipt` record whose receipt says `deadman`: the gate heard no valid record for its configured time and sent the safe state |
| `COMMAND_WITHOUT_RECEIPT` | the settings name a gate key, and no receipt in the journal answers for this command record. Reported at the end, with the command's number |
| `RECEIPT_MISSING` | the gate's receipt numbers skip: it issued receipts the journal does not hold. The first receipt in a journal must be number 0 |
| `RECEIPT_INVALID` | a `gate_receipt` record that holds no well-formed receipt, or one not signed with the gate key the first record names, or one numbered at or below an earlier one, or the settings name no gate key |
| `RECEIPT_MISMATCH` | a receipt signed by the gate that does not belong to the record it names: the record is not an earlier command, the hash is not that record's, the command already has a receipt, the receipt says `applied` and `sent` is not the record's `applied`, or it says `blocked` and the record was not |
| `DECISION_MISMATCH` | a decision file is present and does not hash to `decision_sha256`, or is not `decision_bytes` long |

`STORAGE_STALL` is a finding and the exit code is 2. The recorder could not record for
that time, and the report says so. The threshold for a gap is the same with or without a
stall record; a stated stall too short to account for the silence leaves the
`HEARTBEAT_GAP` in place beside it. A `storage_stall` record without usable numbers is
`RECORD_MALFORMED` and explains nothing.

`GATE_REFUSED` and `GATE_DEADMAN` are findings and the exit code is 2, whether or not the
refusal was the right thing for the gate to do. A journal with one of them is a journal
in which the machine was sent something it did not carry out, or was left without a
valid record for too long, and a reader should see that without having to look for it.
A refusal for age marks its command as answered for, so that command is not also reported
as `COMMAND_WITHOUT_RECEIPT`.

A receipt of section 7.3 (`--receipt`) is checked for `RECEIPT_LEAF_MISMATCH` (the record
is not the leaf the proof is about) and `RECEIPT_ROOT_MISMATCH` (the proof does not lead
to the supplied root).

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
- That every record was signed by a holder of the private key matching the public key
  the first record names. Only with `--public-key` is that the machine's key. Without
  it, it is whatever key the journal names (section 7.6).
- Where the settings name a gate key: that for every command record a holder of the
  gate's private key signed a statement of what the gate did with it, and which of
  those statements were refusals. With `--gate-public-key`, that the key is the machine's.
- Each command names the state the journal's own interventions put in force.
- Under a declared ruleset, the recorded outcome is what that ruleset gives for the
  recorded request and the recorded safety inputs.

### 8.2 What it does not establish

- That the safety inputs were true.
- That the real safety layer ran the declared ruleset. `REPORTED_MISMATCH` catches a
  disagreement. Agreement does not prove the layer is correct.
- That the actuator obeyed. A gate receipt says what the gate sent to it, in the gate's
  own word. Where there are no receipts, not even that the command reached the gate.
- What the gate decided about a command that has no receipt.
- That nothing happened outside the recorder.

### 8.3 Showing the checks can fail

Before any result is trusted, the build plants bugs in the recorder (wrong clamp bound,
skipped rule, stale `in_force`, record written after forwarding, the same with failed
writes ignored, heartbeats not written) and confirms a check exits non-zero for each. Each
bug is a Cargo feature that is off by default. The table of planted bugs and which check
caught each is in the README. The gate's planted bugs (no signature check, no deadman, no
age check, receipts for refusals dropped, no receipts) are made by handing the robot a
copy of the gate with one line changed.

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
- **Signed, which proves less than it sounds.** Each record carries a signature made with
  the recorder's private key. That shows a holder of the key made it. The operator holds
  the key. A timestamp token, when one is fetched, says a root existed by a certain time
  and nothing more.
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

Third round, the same day, after the ROS 2 version showed that a forged, correctly
chained record was accepted:

9. Records are signed with Ed25519. The gate holds the public key only and refuses a
   record whose signature does not verify. The verifier checks signatures. Section 7.6.
10. Not built, by decision: key rotation, hardware key storage, SROS 2.

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
- The file demo runs on Windows 11 and on Ubuntu 26.04 under WSL 2. The ROS 2 part has
  run only on Ubuntu 26.04 under WSL 2, with ROS 2 Lyrical and rclrs 0.8. No real robot,
  no second machine, no other ROS distribution.

## 14. Limits of this build

- **The command-line recorder has no clock-driven heartbeat and no transport.** Its
  heartbeats are written when the demo driver advances a fixed clock, and its commands
  arrive on standard input. The ROS 2 node (section 15) has both: a timer and topics.
- **No journal rotation.** The journal grows without bound, and LogChain's append rereads
  the whole journal to recompute the root, so each record costs more than the last.
- **The private key is a file.** Anyone who can read it can forge records. No rotation,
  no hardware storage. On Windows the recorder does not check who can read the file.
- **Anchoring is a first form.** One witness, which does not sign what it stores, on
  localhost in the demo. No
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
- **A slow disk stops the recorder for as long as it is slow.** Measured: up to 7.8
  seconds for one flush on WSL 2 (section 15.8). The deadman stops the actuator and the
  journal states the stall, but for that time nothing is recorded and nothing is forwarded.
- **The check on a command's age compares the recorder's clock with the gate's.** Across
  separate machines it needs synchronized clocks, which are not built (section 4.4).
- **The deadman exists only where the gate has a clock.** The simulated robot has one.
  The file demo's gate does not.
- **The deadman watches the recorder, not the controller, and no stop latches.** A
  controller that stops commanding while the recorder heartbeats leaves the last command
  in force with no time limit, and after any stop the next accepted command moves the
  actuator again (section 4.3).
- **Gate receipts are the gate's own statement, sent once.** One that does not reach the
  journal is reported as missing, not recovered. Both keys are files on one machine in
  the demo. The file scenarios do not use receipts at all (section 4.5).
- **Measurement is periodic.** A file changed and changed back between two measurements is
  not seen.
- **The reference safety layer lives inside the recorder.** In the demo the recorder
  evaluates the declared ruleset itself, so `reported` and the recorded outcome always
  agree unless a bug is planted. A real safety layer is a separate component, and
  `REPORTED_MISMATCH` only earns its place then.

## 15. The recorder as a ROS 2 node

Built and run on ROS 2 Lyrical, Ubuntu 26.04, with the Rust client library rclrs 0.8.
Everything above this section applies unchanged. This section says what is added and
where the ROS version falls short.

### 15.1 Two processes

```
controller --Twist--> cmd_vel_in --> [ recorder node ] --records--> cmd_vel_out --> [ gate, inside the robot ] --> motion
sensor --JSON--> safety_inputs ----^
```

- **The recorder node** (`ros2/sentinel_recorder_node`, Rust) is the recorder of sections
  4 to 7 with topics for its input and output.
- **The simulated robot** (`ros2/sim_robot.py`) is a separate process with the gate of
  section 4.2 inside it. It is a point that moves by its current velocity twenty times a
  second. It has no display.

`ros2/launch/sentinel.launch.py` starts both.

| topic | type | direction | what |
|---|---|---|---|
| `cmd_vel_in` | `geometry_msgs/Twist` | into the recorder | the requested command |
| `safety_inputs` | `std_msgs/String` | into the recorder | a JSON object of integers, for example `{"light_curtain_clear":1}` |
| `recorder_control` | `std_msgs/String` | into the recorder | JSON: a declared intervention, a measurement, or a stop |
| `cmd_vel_out` | `std_msgs/String` | recorder to robot | the message of section 4.2: the record's text, its number, its hash |
| `recorder_status` | `std_msgs/String` | out of the recorder | one JSON reply for each input handled |
| `gate_events` | `std_msgs/String` | out of the robot | one JSON line for each message the gate judged |
| `gate_receipts` | `std_msgs/String` | robot to recorder | the gate's signed receipts (section 4.5), one message each |

`cmd_vel_out` is reliable and transient local with a history of 1000, so a robot that
starts after the recorder still receives the chain from its first record.
`gate_receipts` has the same settings. A recorder that starts after the robot is sent
the robot's earlier receipts again and writes none of them twice: it takes only a receipt
numbered above the last one in the journal.

The launch file gives the robot the gate's key file, `robot_private/gate.key`, when the
configuration names a `gate_public_key`. The recorder node is never given that file.

The recorder node creates no publisher of `Twist`. The robot subscribes to no `Twist`. The
only thing that sets the robot's velocity is an action the gate hands it.

### 15.2 From a Twist to a command

A Twist is six floating-point numbers. Section 5.1 allows integers only. The node converts
once, on arrival, and the record holds the result:

| Twist field | command field | unit |
|---|---|---|
| `linear.x`, `linear.y`, `linear.z` | `linear_x_mm_s`, `linear_y_mm_s`, `linear_z_mm_s` | whole millimetres per second |
| `angular.x`, `angular.y`, `angular.z` | `angular_x_mrad_s`, `angular_y_mrad_s`, `angular_z_mrad_s` | whole milliradians per second |

- The value is multiplied by 1000 and rounded to the nearest integer, halves away from zero.
- All six fields are always present in the command, including those that are zero.
- A Twist with NaN or infinity in any field is refused.
- A Twist with any field whose magnitude, after conversion, is above the limit is refused.
  The limits are `twist_limits` in the configuration file: `linear_mm_s` and
  `angular_mrad_s`. The configuration file is hashed into the state in force, so every
  record names the limits that applied.
- A refused Twist leaves no record and nothing is sent to the robot, as in section 5.1.

The limit is a sanity bound on the input. It is separate from the safety rules, which clamp
or block a command that was accepted.

A clamped command's record holds both values, as section 5 requires: `requested` is the
converted request (1800 for 1.8 m/s) and `applied` is what the rules left of it (1500),
with the rule's id in `rules_acted`. A test reads the record back to check. What the
record does not hold is the original floating-point number: only its rounded integer.

### 15.3 Safety inputs

The node keeps the last `safety_inputs` message it received and uses it for every command.
Before the first one arrives there are no inputs, and a `block_when` rule with a missing
input fires (section 5.2), so the robot does not move until a safety signal has been seen.
A message that is not a JSON object of integers clears the inputs.

### 15.4 Heartbeat, and publishing off the recorder's lock

A thread of its own checks five times a second whether `heartbeat_seconds` have passed
since the last record and writes a heartbeat if so. It does not depend on the ROS
executor.

Publishing is done by another thread that takes messages from a queue, in order. The
recorder, while it holds its lock, only puts a line on the queue. A record is therefore
written to the journal first and published a moment later, which is the order section 4
requires, and a slow publish cannot hold up the next record. The cost: a publish that
fails is no longer reported back to the recorder as a fault.

Getting here took four attempts, each caught by running the scenarios repeatedly and each
leaving the journal without a heartbeat for five to twelve seconds, against a tolerance of
four in the demo:

1. a check between calls to `spin` with a timeout: the call did not return until a message
   arrived;
2. a ROS timer: the same, about once in fifty runs;
3. a separate thread that published while holding the recorder's lock;
4. a separate thread and a publishing queue, with the main loop still taking the
   recorder's lock on every pass to read a stop flag. When `spin` returned at once the
   loop took the lock over and over and the heartbeat thread waited behind it.

Two things were checked along the way, by measurement: the wall clock in WSL did not
step, and flushing a file to disk took 10 ms at worst. The second was wrong as a general
statement. It was true of the runs measured that day. Section 15.8 is what a longer look
found, and it accounts for a stall the four fixes above did not.

**Anchor statements** are also written by a thread of their own (section 7.5). Under the
recorder's lock, one anchor flush of 7.8 seconds kept every other record waiting. A
statement that cannot be written does not put the recorder in the safe state. The
failure goes back to the recorder, which states it in an `anchor_failed` record within
a fifth of a second, and it is also reported on `recorder_status`. Scenario 12.

**For diagnosis**, off unless asked for: with `SL_TRACE_FILE` set, the node appends one
line for each write (how long it took), each heartbeat, and each wait for the lock, with
the monotonic clock beside the wall clock. `ros2/clock_watchdog.py` is a separate program
that logs three clocks every 100 ms and shares nothing with the recorder. Laid side by
side, the two say whether a silence was the recorder or the whole machine.

### 15.5 What the gate refuses on `cmd_vel_out`

Any node can publish on any topic. ROS 2 has no access control unless SROS 2 is set up.
The scenarios play a second node publishing straight onto the robot's input:

| what the other node publishes | gate | refused because | test |
|---|---|---|---|
| a command with no record | refused | no record | scenario 6 |
| text that is not JSON | refused | no record | scenario 6 |
| a real record the recorder sent earlier, sent again | refused | signed, but it does not extend the chain | scenario 6 |
| a real record with its text changed and its hash left alone | refused | the hash | scenario 6 |
| a well-formed record two ahead of the gate's head | refused | not signed by the recorder | scenario 6 |
| a correctly hashed record that follows the gate's head, carrying a signature lifted from a real record | refused | not signed by the recorder | scenario 7 |
| the same, properly signed with a key of the forger's own | refused | not signed by the recorder | scenario 8 |
| the same, with no signature | refused | not signed by the recorder | scenario 9 |

In scenarios 7 to 9 the robot never moves at the forger's speed and the recorder's own
next command is accepted. In all of scenarios 6 to 9 the journal's chain, signatures and
rules check out, and the verifier exits 2 with `GATE_REFUSED`: the journal holds the
gate's receipt for each refusal, with the reason in the third column as `form` (no
record, the hash), `chain` or `signature`. Before receipts the verifier exited 0 on these
journals and nothing in them said another node had tried.

Before records were signed, the forged record of scenario 7 was accepted and moved the
robot at 1500 mm/s. A test keeps that visible: it hands the robot a copy of the gate with
the signature check removed, and scenario 7 turns red in exactly that way.

What is left: a node that can read the recorder's private key file can still forge
(section 7.6). And every refusal sends the safe state, so a node that publishes junk on
`cmd_vel_out` cannot move the robot, but it can stop it, as often as it likes. Each time
costs the gate a signature and the journal a record, and nothing limits the rate.

### 15.6 Gaps, and the bound

A gap is a record number the gate did not see. What can pass in each case:

| how the gap arises | unrecorded commands that reach the robot | then |
|---|---|---|
| the node records a command and never publishes it (planted bug) | none | the gate refuses every later record; the robot gets only the safe state; the journal is whole and says so: `GATE_REFUSED` for each refusal, `COMMAND_WITHOUT_RECEIPT` for each command not carried out, and `GATE_DEADMAN`, because with every record refused the gate hears no valid one |
| a message is lost in transit | none | the same |
| the node publishes before it writes, and the write fails (planted bug) | one, with this recorder | `GATE_HEAD_NOT_IN_JOURNAL`; on restart the gate refuses the recorder |
| a recorder that ignores failed writes (section 4.2) | any number, until the gate's head is compared with the journal | the same finding |
| another node forges the next record without the recorder's key (15.5) | none | the gate refuses it; the recorder carries on |
| someone who can read the recorder's key file forges records | any number, until compared | `GATE_HEAD_NOT_IN_JOURNAL` |

This is the bound of section 4.2, unchanged by ROS: the gate cannot see whether a record
reached the disk.

A recorder that says nothing at all is a different case from a gap in the numbers. The
gate sees no record to refuse. That is the deadman's case (section 4.3): scenario 10
freezes the recorder's process for ten seconds with the robot at 0.5 m/s, and the robot
is stopped after four. The gate's receipt for the trip waits on the topic until the
recorder is running again and is then written down, so the journal shows the gap
(`HEARTBEAT_GAP`) and what the robot did about it (`GATE_DEADMAN`).

### 15.7 What the ROS version does not cover

- **A robot with a plain `Twist` input.** If the robot, or its driver, also listens on a
  `Twist` topic, any node can move it and nothing here can refuse that. The demo robot has
  no such input. A real one would need SROS 2 access control, which is not set up or
  tested here.
- **Whoever can read the private key file.** They can forge records the robot accepts.
  Key rotation and hardware key storage are out of scope (section 7.6).
- **Stale safety inputs.** The last safety message stays in force however old it is. A
  sensor that stops publishing "clear" is not noticed.
- **Who publishes `safety_inputs` and `recorder_control`.** Any node can. A false "clear",
  or a declared intervention from an unknown node, is recorded as it arrived.
- **A robot that joins more than 1000 records late** does not receive the start of the
  chain and refuses everything.
- **Decision data, anchoring to a witness and timestamps** are not wired into the ROS
  scenarios. The node writes anchor statements as before; nothing delivers them.
- **Precision.** Speeds are whole millimetres and milliradians per second. Anything finer
  in the incoming Twist is rounded away before it is recorded.
- **A custom message type** for `cmd_vel_out` in place of JSON in a string: not built.
- **An in-line gate in a real controller, real time behaviour, more than one machine, a
  real robot, a simulator with physics:** none tested.
- **After a fault, the time the recorder was down shows as `HEARTBEAT_GAP`.** Scenario 5
  expects exit 2 from the verifier after the restart for that reason. It is what happened.
- **The simulated robot's deadman shares a thread with everything else the robot does.**
  A slow write of the gate's own state file delays the check. The robot now acts on a
  decision before writing anything down, so a stop is not delayed by its own disk, but a
  real controller needs the deadman on a timer of its own.
- **The command's age is measured between two clocks on one machine here.** The recorder
  node and the robot run on the same computer in every test (section 4.4).
- **The age starts at the node's callback.** A Twist has no time stamp of its own. Time a
  message spent queued before the node's code ran is not counted.
- **Who publishes `gate_receipts`.** Any node can. One that cannot sign with the gate's
  key gets nothing written. One that replays the gate's own receipts gets nothing
  written twice.
- **A receipt that arrives when the recorder cannot write** (stopped, in the safe state,
  not running) is lost. The gate sends each once. After scenario 5's fault, a deadman
  trip on a slow machine would leave a gap in the gate's numbering for that reason.
- **Both key files are on one machine and belong to one user** in every test.

### 15.8 When the disk is slow

Section 4 makes every command wait for the disk. This section is what that costs on a
disk that is sometimes slow, what was measured, and what the build now does about it.

**What was measured.** WSL 2, Ubuntu 26.04, ext4 on a virtual disk file on an NVMe SSD,
9 October 2026. Three instruments: the node's own trace, an independent clock log
(`ros2/clock_watchdog.py`), and a program that only writes and flushes a small file.

| | measured |
|---|---|
| a journal flush, usual | about 10 ms (median) |
| a journal flush, worst seen | 4.0 s |
| an anchor file flush, worst seen | 7.8 s |
| longest time with no record written | 8.2 s, against a threshold of 4 s |
| the independent clock log over the same runs | no step over 0.105 s on the wall, monotonic or boot-time clock |
| the flush-only program, recorder not running, idle machine | bursts of about 15 s in which every flush took 0.5 to 2.0 s |
| runs of the nine scenarios that failed on that disk for this reason | 3 of 12 |

The machine did not pause: a paused machine would have paused the clock log too. The
heartbeat thread woke on time on every pass. The time went inside the calls that flush a
file to disk, made while the recorder held its lock. Why that disk has slow bursts is not
known. A guess that they follow a large build was tested and not supported.

**What a reader of the journal saw.** A `HEARTBEAT_GAP`. That was true: for those seconds
the recorder could not record. It did not say why, and it read the same as a recorder
that had hung.

**What the robot did.** Nothing different. It had no deadman. In the measured case its
last command happened to be a stop. Had it been a speed, the robot would have held that
speed for the whole of the silence.

**What happens now.**

1. The gate's deadman stops the robot when no valid record has arrived for
   `gate_deadman_seconds` (section 4.3). Scenario 10.
2. The command that was held up is not carried out when it finally arrives. The gate
   refuses a command older than `gate_max_command_age_ms` (section 4.4), 1000 in the
   demo, and the robot stays in the safe state. Scenario 11.
3. The gate signs a receipt for the deadman trip and one for the refusal, and the
   recorder writes both into the journal (section 4.5). The verifier reports
   `GATE_DEADMAN` and `GATE_REFUSED` with the reason `age`. Scenario 11.
4. When the slow write completes, the recorder writes a `storage_stall` record with the
   measured duration (section 7.2), and the verifier reports `STORAGE_STALL` in place of
   an unexplained gap (section 8). It is still a finding. Scenario 11, on a test build
   whose flush can be made slow on demand, since a real disk cannot be told to stall.
5. Anchor statements are flushed off the lock (sections 7.5 and 15.4), which removes the
   longest wait measured. One that cannot be written is stated in the journal. Scenario 12.

None of this makes the recorder faster. On a disk that takes eight seconds, a command
waits eight seconds, and is then refused for its age. What changes is that the robot is
stopped, stays stopped until a fresh command, and the journal says what happened.

**Scenario 11, step by step.** The robot is moving at 0.5 m/s. The next command's record
takes six seconds to land. At four seconds the deadman stops the robot. At six the record
is forwarded: the gate takes it into the chain, sees a command six seconds old against a
limit of one, and keeps the safe state. The recorder's next record states the stall. A
fresh command after that moves the robot as usual. Before the age check existed the
robot started moving again at six seconds on the old command; the planted bug keeps that
visible.

The journal of one such run, record by record:

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

and what the verifier prints for it:

```
gate receipts:    4 in the journal: 1 refusal(s), 1 deadman trip(s); 0 command(s) with no receipt
storage stalls:   1 stated by the recorder (each is a finding below)
  STORAGE_STALL n=5 step="journal_write" of_record=4 stalled_ms=6000 previous="2026-10-10T14:27:45Z" at="2026-10-10T14:27:51Z"
  GATE_DEADMAN n=6 gate_seq=1 last_record_accepted=3 detail="no valid record for 4.041 s; the limit is 4 s"
  GATE_REFUSED n=7 gate_seq=2 reason="age" of_record=4 detail="the command is 6003 ms old; the limit is 1000 ms"
3 FINDING(S)
```

Record 4 still reads as it did before receipts: requested 200, applied 200. Record 7 is
what says the robot never did it. The two receipts written at records 6 and 7 were
issued four and six seconds into the stall and waited until the recorder could write.

**Tests, and where the journal is kept for them.** The scenarios are judged pass or fail
and several depend on timing. On the disk above a round of them often has a run that
ends differently (6 rounds of 10 in the soak below), for a reason that is true and is not
about the code. So the pass/fail runs put the scenario
folders, journal included, in a RAM-backed folder (`/dev/shm`). This is for tests only: a
journal in RAM does not survive power-off, and a flush there proves nothing about a disk.

`ros2/soak_real_disk.py` is the other half. It runs the same scenarios on a real disk for
a number of rounds and reports flush times, stall records, deadman trips and verifier
findings as measurements. It has no pass or fail and exits 0 whenever it could run.

One soak, on the disk above, on the code as it is now, receipts included: ten rounds of
scenarios 1 to 10 and 12, 110 scenario runs in 782 seconds, 10 October 2026.
`gate_max_command_age_ms` was 1,000.

| | measured |
|---|---|
| journal flushes | 993: median 4.6 ms, longest 3.33 s, 37 over 0.5 s, 24 over 1 s, 0 over 4 s |
| anchor flushes, off the lock | 392: median 3.3 ms, longest 3.75 s, 12 over 0.5 s |
| records in the 110 journals | 1,243, of which 350 command records and 441 gate receipts |
| `storage_stall` records written | 0: no flush left a gap past the threshold |
| what the gate did with the 350 command records | applied 325, 19 were blocked commands, refused 6 for their age |
| deadman trips | 11: one in each round from scenario 10, and one in a run of scenario 1, where the next command was then refused for its age |
| receipts in the journals for those | all 6 refusals for age, all 11 deadman trips |
| what the verifier reported, run over the 110 journals | `GATE_REFUSED` with reason `age` 6 times, `GATE_DEADMAN` 11 times; no `COMMAND_WITHOUT_RECEIPT`, no `RECEIPT_MISSING`, no `RECEIPT_INVALID`, no `RECEIPT_MISMATCH` |
| other verifier findings | only those the scenarios cause on purpose: `HEARTBEAT_GAP` in 5 and 10, `GATE_REFUSED` for the 80 messages another node sent in 6 to 9, `ANCHOR_FAILED` in 12 |
| scenario runs not as the pass/fail run expects | 6 of 110, each because a command was refused for its age |
| the clock log | 7,820 lines, largest step 0.115 s |

Ten rounds on one disk on one day. No flush went past the heartbeat threshold in this run,
so it did not put the stall record to work on a real disk; scenario 11 does that with the
test build. What it shows is the limit on a command's age at work, and the receipts: a
flush of one to three seconds is too short to be a stall and long enough to make a
command late, the gate refused those commands and kept the safe state, and each refusal
is in the journal and in the verifier's report. The soak before receipts (545 journal
flushes, 8 refusals for age, one deadman trip nobody planned) left none of those nine
events in any journal. The number of journal flushes nearly doubled, because each
command is now two records. This is not a measure of how often that disk stalls.
