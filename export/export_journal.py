#!/usr/bin/env python3
"""Export a Sentinel Ledger journal as RFC 5424 syslog lines or CEF events.

    export_journal.py JOURNAL --format syslog|cef [--out FILE] [--hostname NAME]
                      [--facility N] [--enterprise-number N]

The default enterprise number, 32473, is the one RFC 5612 reserves for documentation. Set
your own with --enterprise-number before real use.

Every record travels whole, as the exact text its leaf hash and signature cover, so the
exported file can still be checked with export/check_export.py. The format is in
docs/EXPORT.md. The exporter never reads the clock: the same journal gives the same bytes.

Exit codes: 0 written, 1 usage or input error.
"""
import argparse
import calendar
import datetime
import hashlib
import json
import re
import sys

APP_NAME = "sentinel-ledger"
FORMAT_VERSION = "1"
DOC_PEN = 32473            # RFC 5612: the enterprise number reserved for documentation
SYSLOG_LIMIT = 2048        # RFC 5424: receivers SHOULD accept messages of this size
CEF_STRING_LIMIT = 4000    # what some SIEMs keep of a custom string
AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HOSTNAME = re.compile(r"^[\x21-\x7e]{1,255}$")
MSGID = re.compile(r"^[\x21-\x7e]{1,32}$")

# docs/EXPORT.md section 5: (syslog severity, CEF severity, CEF name)
PLAIN = {
    "genesis": (5, 3, "journal started"),
    "recorder_start": (5, 3, "recorder started"),
    "recorder_stop": (5, 3, "recorder stopped"),
    "heartbeat": (6, 1, "heartbeat"),
    "intervention_declared": (5, 5, "declared intervention"),
    "intervention_detected": (4, 7, "change found by measurement"),
    "recorder_fault": (3, 8, "recorder fault"),
    "storage_stall": (4, 6, "storage stall"),
    "anchor_failed": (4, 6, "anchor statement lost"),
    "actuator_feedback": (6, 2, "actuator feedback"),
}
COMMAND = {
    "unchanged": (6, 2, "command passed unchanged"),
    "changed": (5, 4, "command changed by a rule"),
    "blocked": (4, 6, "command blocked"),
}
RECEIPT = {
    "applied": (6, 2, "gate receipt: applied"),
    "blocked": (5, 4, "gate receipt: blocked"),
    "refused": (4, 7, "gate receipt: refused"),
    "deadman": (4, 7, "gate receipt: deadman"),
}
END = (5, 3, "end of export")


class Unusable(Exception):
    """The journal cannot be exported. Exit 1."""


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves):
    """RFC 6962: split at the largest power of two strictly below n."""
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def classify(record):
    """(syslog severity, CEF severity, CEF name) for one parsed record."""
    kind = record.get("kind")
    if kind == "command":
        return COMMAND.get(record.get("outcome"), (4, 6, "command with an unreadable outcome"))
    if kind == "gate_receipt":
        receipt = record.get("receipt")
        decision = receipt.get("decision") if isinstance(receipt, dict) else None
        return RECEIPT.get(decision, (4, 7, "gate receipt: unreadable"))
    return PLAIN.get(kind, (4, 7, "unknown record"))


def read_records(path):
    """The record texts of a LogChain journal, in order, with each one parsed."""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [line for line in fh if line.strip()]
    except OSError as exc:
        raise Unusable(str(exc))
    for lineno, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
            raw = entry["raw"]
            record = json.loads(raw)
        except (ValueError, KeyError, TypeError) as exc:
            raise Unusable("journal line %d holds no readable record (%s); run the verifier on it" % (lineno, exc))
        if not isinstance(raw, str) or not isinstance(record, dict):
            raise Unusable("journal line %d holds no readable record; run the verifier on it" % lineno)
        if "\n" in raw or "\r" in raw:
            raise Unusable("record on journal line %d contains a line break, which no record in canonical form does"
                           % lineno)
        if (not isinstance(record.get("at"), str) or not AT.match(record["at"])
                or not isinstance(record.get("kind"), str) or not MSGID.match(record["kind"])):
            raise Unusable("record on journal line %d has no usable `at` or `kind`; run the verifier on it" % lineno)
        stored = entry.get("hash")
        leaf = leaf_hash(raw.encode("utf-8")).hex()
        if stored != leaf:
            print("warning: journal line %d: the stored hash is not the leaf hash of the record text; "
                  "exporting the text as found" % lineno, file=sys.stderr)
        out.append((raw, record, leaf))
    if not out:
        raise Unusable("the journal holds no records")
    return out


def sd_value(value):
    """RFC 5424 section 6.3.3: escape '"', '\\' and ']' in a parameter value."""
    return re.sub(r'(["\\\]])', r"\\\1", str(value))


def cef_header(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def cef_value(value):
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def epoch_ms(at):
    return calendar.timegm(datetime.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").timetuple()) * 1000


def syslog_lines(records, hostname, facility, pen):
    lines = []
    for raw, record, leaf in records:
        severity = classify(record)[0]
        sd = '[sl@%d n="%s" kind="%s" leaf="%s" prev="%s"]' % (
            pen, sd_value(record.get("n")), sd_value(record["kind"]), leaf, sd_value(record.get("prev")))
        lines.append("<%d>1 %s %s %s - %s %s \ufeff%s" % (
            facility * 8 + severity, record["at"], hostname, APP_NAME, record["kind"], sd, raw))
    count, root, journal = end_values(records)
    sd = '[slEnd@%d records="%d" root="%s" journal="%s"]' % (pen, count, root, journal)
    lines.append("<%d>1 %s %s %s - export_end %s \ufeffend of export" % (
        facility * 8 + END[0], records[-1][1]["at"], hostname, APP_NAME, sd))
    return lines


def cef_lines(records):
    prefix = "CEF:0|Sentinel Ledger|journal export|%s|" % FORMAT_VERSION
    lines = []
    for raw, record, leaf in records:
        _, severity, name = classify(record)
        extension = "externalId=%s rt=%d cs1Label=slRecord cs1=%s cs2Label=slLeaf cs2=%s cs3Label=slPrev cs3=%s" % (
            cef_value(record.get("n")), epoch_ms(record["at"]), cef_value(raw), leaf, cef_value(record.get("prev")))
        lines.append(prefix + "%s|%s|%d|%s" % (cef_header(record["kind"]), cef_header(name), severity, extension))
    count, root, journal = end_values(records)
    lines.append(prefix + "export_end|%s|%d|cn1Label=slRecords cn1=%d cs4Label=slRoot cs4=%s cs5Label=slJournal cs5=%s"
                 % (END[2], END[1], count, root, journal))
    return lines


def end_values(records):
    leaves = [bytes.fromhex(leaf) for _, _, leaf in records]
    return len(records), merkle_root(leaves).hex(), records[0][2]


def export(journal, fmt, hostname="-", facility=13, pen=DOC_PEN):
    """The exported text, one line per record and one end line, each ending in LF."""
    if fmt not in ("syslog", "cef"):
        raise Unusable("--format must be syslog or cef")
    if not HOSTNAME.match(hostname):
        raise Unusable("--hostname must be 1 to 255 printable ASCII characters with no space")
    if not 0 <= facility <= 23:
        raise Unusable("--facility must be 0 to 23")
    if pen < 0:
        raise Unusable("--enterprise-number must not be negative")
    records = read_records(journal)
    if fmt == "syslog":
        lines = syslog_lines(records, hostname, facility, pen)
        for i, line in enumerate(lines):
            if len(line.encode("utf-8")) > SYSLOG_LIMIT:
                print("warning: line %d is %d octets, over the %d that RFC 5424 receivers should accept; "
                      "a relay that truncates it will make it uncheckable" % (i + 1, len(line.encode("utf-8")),
                                                                           SYSLOG_LIMIT), file=sys.stderr)
    else:
        lines = cef_lines(records)
        for i, (raw, _, _) in enumerate(records):
            if len(cef_value(raw)) > CEF_STRING_LIMIT:
                print("warning: record %d is over %d characters, which some SIEMs cut short in a custom string"
                      % (i, CEF_STRING_LIMIT), file=sys.stderr)
    return "".join(line + "\n" for line in lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Export a Sentinel Ledger journal as syslog or CEF.")
    ap.add_argument("journal", help="path to the journal (logchain.journal)")
    ap.add_argument("--format", required=True, choices=("syslog", "cef"))
    ap.add_argument("--out", help="write here instead of standard output")
    ap.add_argument("--hostname", default="-", help="syslog HOSTNAME field (default: the NILVALUE '-')")
    ap.add_argument("--facility", type=int, default=13, help="syslog facility, 0 to 23 (default 13, log audit)")
    ap.add_argument("--enterprise-number", type=int, default=DOC_PEN,
                    help="IANA Private Enterprise Number for the structured-data IDs. The default, "
                         "32473, is reserved for documentation by RFC 5612 and is only an example: "
                         "set your own organisation's number before real use")
    args = ap.parse_args(argv)
    try:
        text = export(args.journal, args.format, args.hostname, args.facility, args.enterprise_number)
    except Unusable as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
    else:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
