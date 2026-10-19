# Exporting a journal to syslog and CEF (draft 1)

A journal is meant to be read by the verifier. Many sites also want the same records in the
log system they already watch: a SIEM, a syslog server, a log archive. This document defines
two line formats for that, and what an offline checker can still establish once a journal
has left its own directory.

Two programs, as elsewhere in this repository:

- `export/export_journal.py` reads a journal and writes one of the two formats;
- `export/check_export.py` reads an exported file and checks the hash chain and the
  signatures. It is written from this document, imports nothing from this repository, and
  uses only the Python standard library, so it can be copied to the machine where the
  exported file ended up and run there.

## 1. What travels

Every record travels whole: the exact text the leaf hash and the signature cover (SPEC 7.2),
byte for byte, inside the line. Everything else on the line (time, severity, event name, the
record's number and hashes) is derived from that text, and the checker derives it again and
compares. So a line whose routing fields were changed after export (a severity lowered so an
alert does not fire, an event name swapped) is a finding, even when the record inside it is
untouched.

The exporter never reads the clock. The same journal always gives the same bytes.

The exporter does not judge the journal. It computes each leaf hash from the record text
itself, warns when that differs from the hash stored in the journal, and exports the text it
found. Judging is the checker's job, and the verifier's.

## 2. The end-of-export line

After the last record the exporter writes one more line: the number of records, the Merkle
root over all of them (LogChain format version 2, RFC 6962) and the leaf hash of record 0,
which names the journal. The checker recomputes all three.

That line is in the same file as the records. Whoever can edit one can edit the other: drop
the last record and rewrite the end line, and the file is consistent again. The end line
catches records lost on the way (a forwarder that drops messages, a file cut short). It does
not catch someone who rewrites the file on purpose. For that the checker needs a root from
somewhere the file's keeper cannot reach: an anchor statement held by a witness, an RFC 3161
token, or the gate's head (SPEC 7.5, 4.2). Given `--root`, the checker requires the
recomputed root to equal it. Without `--root` it says that it ran without one.

## 3. RFC 5424 syslog

One message per line, LF-terminated (the framing of a file or of RFC 6587 non-transparent
transport). For record `n`:

```
<PRI>1 TIMESTAMP HOSTNAME sentinel-ledger - KIND [sl@PEN n="N" kind="KIND" leaf="LEAF" prev="PREV"] BOM RECORD
```

| field | value |
|---|---|
| PRI | facility * 8 + severity. Facility 13 ("log audit" in RFC 5424) unless `--facility` says otherwise. Severity from the table in section 5 |
| VERSION | 1 |
| TIMESTAMP | the record's `at`, unchanged (RFC 5424 accepts `Z`) |
| HOSTNAME | `--hostname`, or the NILVALUE `-` |
| APP-NAME | `sentinel-ledger` |
| PROCID | `-` |
| MSGID | the record's `kind` (at most 21 characters; RFC 5424 allows 32) |
| STRUCTURED-DATA | one element, ID `sl@PEN`: the record's `n`, `kind`, the leaf hash of the record text, and `prev` |
| MSG | a UTF-8 byte order mark, then the record text |

`PEN` is an IANA Private Enterprise Number. The default, 32473, is the number RFC 5612
reserves for documentation. It is there as an example and is not meant for real logs.
**Before real use, set your own organisation's number with `--enterprise-number`.** IANA
assigns these numbers on request. The checker accepts any number.

The record text is canonical JSON with only ASCII characters and no line breaks (SPEC 7.1),
so it never needs escaping in MSG. Parameter values are escaped as RFC 5424 requires (`"`,
`\` and `]` get a backslash). The checker accepts MSG with or without the byte order mark,
because some relays strip it.

The end line:

```
<PRI>1 TIMESTAMP HOSTNAME sentinel-ledger - export_end [slEnd@PEN records="COUNT" root="ROOT" journal="LEAF0"] BOM end of export
```

TIMESTAMP is the last record's `at`, severity 5.

**Size.** RFC 5424 receivers must accept 480 octets and should accept 2048. A command line is
about 1,000 octets. The exporter never shortens a line, since a shortened record cannot be
checked, and it warns about any line over 2048 octets. A relay that truncates longer lines
will produce lines the checker reports as malformed.

## 4. CEF

One event per line:

```
CEF:0|Sentinel Ledger|journal export|1|KIND|NAME|SEVERITY|externalId=N rt=MS cs1Label=slRecord cs1=RECORD cs2Label=slLeaf cs2=LEAF cs3Label=slPrev cs3=PREV
```

| field | value |
|---|---|
| Device Vendor, Device Product | `Sentinel Ledger`, `journal export` |
| Device Version | `1`, the version of this export format |
| Device Event Class ID | the record's `kind` |
| Name, Severity | from the table in section 5 (CEF severity runs 0 to 10) |
| `externalId` | the record's `n` |
| `rt` | the record's `at` as milliseconds since 1970 |
| `cs1` | the record text |
| `cs2`, `cs3` | the leaf hash of the record text, and `prev` (empty for record 0) |

Header fields escape `\` and `|`. Extension values escape `\` and `=`, and a line break would
be `\n` (canonical JSON has none). A checker unescapes before hashing.

The end line:

```
CEF:0|Sentinel Ledger|journal export|1|export_end|end of export|3|cn1Label=slRecords cn1=COUNT cs4Label=slRoot cs4=ROOT cs5Label=slJournal cs5=LEAF0
```

A forwarder may put its own syslog header in front of `CEF:0|`. The checker ignores anything
before the first `CEF:0|` on a line.

**Size.** Some SIEMs store at most 4000 characters in a custom string. Records are well under
that today. The exporter warns about any record over 4000 characters and never shortens one.

## 5. Severity and name

The severity is a label for routing and alerting. It says nothing about whether anything was
safe, right or wrong.

| record | syslog severity | CEF severity | CEF name |
|---|---|---|---|
| `genesis` | 5 | 3 | journal started |
| `recorder_start` | 5 | 3 | recorder started |
| `recorder_stop` | 5 | 3 | recorder stopped |
| `heartbeat` | 6 | 1 | heartbeat |
| `command`, outcome `unchanged` | 6 | 2 | command passed unchanged |
| `command`, outcome `changed` | 5 | 4 | command changed by a rule |
| `command`, outcome `blocked` | 4 | 6 | command blocked |
| `command`, any other outcome | 4 | 6 | command with an unreadable outcome |
| `intervention_declared` | 5 | 5 | declared intervention |
| `intervention_detected` | 4 | 7 | change found by measurement |
| `recorder_fault` | 3 | 8 | recorder fault |
| `storage_stall` | 4 | 6 | storage stall |
| `anchor_failed` | 4 | 6 | anchor statement lost |
| `gate_receipt`, decision `applied` | 6 | 2 | gate receipt: applied |
| `gate_receipt`, decision `blocked` | 5 | 4 | gate receipt: blocked |
| `gate_receipt`, decision `refused` | 4 | 7 | gate receipt: refused |
| `gate_receipt`, decision `deadman` | 4 | 7 | gate receipt: deadman |
| `gate_receipt`, anything else | 4 | 7 | gate receipt: unreadable |
| `actuator_feedback` | 6 | 2 | actuator feedback |
| any other kind | 4 | 7 | unknown record |
| end of export | 5 | 3 | end of export |

As SPEC 6.2 requires of every report from this project, a detected change is named for what
was observed, not for whether it was legitimate.

## 6. What the checker establishes

`check_export.py FILE [--root HEX] [--public-key HEX] [--gate-public-key HEX] [--feedback-public-key HEX] [--json]`

In this order, and it reports every finding rather than stopping at the first:

1. every line parses as the format, and the format is the same throughout;
2. every line's derived fields agree with the record inside it (`ENVELOPE_MISMATCH`);
3. every record is a record: canonical JSON, the schema, a known kind, `n`, `prev`, `at`
   (`RECORD_MALFORMED`);
4. the order: record 0 is a genesis record (`NO_GENESIS`), every record's `n` is its
   position in the file (`POSITION_MISMATCH`), every `prev` is the leaf hash of the record
   before it (`PREV_MISMATCH`). A record dropped, added, repeated or moved shows here;
5. the signatures: every record is signed with the key the genesis record names, or with
   `--public-key`, which the genesis record must then name (`KEY_MISMATCH`,
   `SIGNATURE_MISSING`, `SIGNATURE_INVALID`); every receipt inside a `gate_receipt` record
   is signed with the gate key the genesis record names, or with `--gate-public-key`
   (`RECEIPT_SIGNATURE_INVALID`); every report inside an `actuator_feedback` record is
   signed with the feedback key the genesis record names, or with `--feedback-public-key`,
   which the genesis record must then name (`KEY_MISMATCH`, `FEEDBACK_SIGNATURE_INVALID`).
   With no recorder key at all it says so (`KEY_UNKNOWN`);
6. the end: exactly one end line, and it is the last line (`END_MISSING`, `END_REPEATED`,
   `END_NOT_LAST`);
   its count, root and journal name match the records (`END_MISMATCH`); and, with `--root`,
   the recomputed root equals the one given (`ROOT_MISMATCH`).

Exit codes: 0 nothing found, 2 a finding, 1 the file cannot be read at all.

## 7. What it does not establish

- Anything the verifier checks beyond the chain and the signatures: the state in force,
  which rule acted, gaps in the heartbeat, whether a receipt or a feedback report belongs
  to its command, whether a receipt or a report is missing from the numbering, whether a
  reading was taken in time, anchors, decision files, a profile. For those, run the
  verifier on the journal.
- Whether the actuator did what it was told. A feedback report that checks is genuine:
  the feedback key signed it. What it says is the controller's word, and neither the
  checker nor the verifier compares it with what was sent (SPEC 4.6).
- That the file holds a whole journal, when the end line was rewritten and no `--root` was
  given (section 2).
- That an operator who holds the recorder's private key did not re-sign a rewritten journal
  before exporting it. That is the same limit as the verifier's, and the same answer: a root
  held by someone else.
- Partial exports. The checker needs record 0 for the key and for the order. A SIEM that
  keeps only recent events cannot be checked with it.
