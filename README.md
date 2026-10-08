# Sentinel Ledger

Sentinel Ledger is a recorder that sits in a machine's command path: a command reaches the
actuator only inside a record of it, so the record of what was commanded is complete by
construction and does not rest on trusting the operator to log. The journal is
tamper-evident, and its roots are anchored outside the operator's control, with a witness
that stores them or an RFC 3161 timestamp.

Both sentences have limits, and they are stated below before anything else is claimed.
This is a first build on a simulated machine. It is not certified, it is not a safety
system, and it cannot see anything that does not pass through it.

I designed Sentinel Ledger and directed its build. The code was written with an AI coding
assistant; I reviewed the specification, the results and this README.

## What it does

For every command, in this order: take the command the controller requested, get the
command the safety layer applied and the rules that acted, write one record, flush it to
disk, and only then send the record to a gate on the actuator's side. The gate passes the
command on only if the record extends the chain of records it has already seen.

Each record holds:

- the requested command and the applied command, and which safety rule changed or blocked it;
- a hash naming the software versions, ruleset and configuration in force at that moment;
- optionally, the data an autonomous decision was based on, stored beside the journal.

Changes to safety software, rules or configuration are records too. A change made through
the recorder is one kind. A change the recorder finds by hashing the installed files is
another. The recorder does not say which changes were proper.

A verifier, written in a different language from the recorder and sharing no code with it,
checks the chain, checks every anchored root, replays the journal to work out what was in
force for each command, and recomputes which rule acted.

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
- **A rewrite verifies if nothing outside is consulted.** Someone who rewrites a record,
  every hash, the root and the local anchor statements gets a journal with no findings,
  unless the verifier is given a root, a witness's store or the gate's state that the
  rewriter could not reach. See the table below.
- **Hashing says nothing about truth or omission.** A journal that was never written, a
  safety input that was wrong, decision data that left something out: none of these is
  detectable from the journal.
- **Not built:** signatures, more than one witness, consistency proofs between roots,
  journal rotation, a clock-driven heartbeat, a real transport, a ROS 2 node. FreeTSA has
  not been called; the timestamp path was tested with a throwaway authority made by
  openssl.
- Run on Windows 11 only so far.

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

## Run it

Needs Rust (cargo), Python 3 with pytest, and openssl on the PATH for the timestamp tests.
The first build downloads crates and LogChain from GitHub. After that nothing uses the
network: the witness listens on localhost.

```
git clone https://github.com/JakPot42/sentinel-ledger
cd sentinel-ledger
cd recorder && cargo build && cargo test && cd ..
python demo/run_scenarios.py      # exit 0 only if all five scenarios are as expected
python -m pytest tests            # 53 tests; builds six deliberately broken recorders
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
| `gate/actuator_gate.py` | the actuator-side gate | Python, standard library |
| `witness/witness.py` | a witness: stores the roots it is sent and never changes one | Python, standard library |
| `anchor/anchor_roots.py` | delivers root statements to a witness, or timestamps them (needs openssl) | Python, standard library |
| `verifier/verify_journal.py` | the verifier | Python, standard library |
| `profiles/` | the EU profile | |
| `sources/eu/` | the regulation and its corrigendum as retrieved from the Publications Office of the European Union | |
| `demo/` | the simulated conveyor and the five scenarios | |
| `tests/` | scenarios, planted bugs, tampering, the gate, anchoring, the profile | |

The gate, the witness and the verifier import nothing from each other or from the
recorder, and tests check their import lists.

## Licence

MIT, see `LICENSE`. The two files in `sources/eu/` are European Union documents
(© European Union), included unchanged so the quotations can be checked; only the version
published in the Official Journal is authentic.
