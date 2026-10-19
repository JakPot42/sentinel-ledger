#!/usr/bin/env python3
"""Offline checker for a Sentinel Ledger journal exported as RFC 5424 syslog or CEF.

    check_export.py FILE [--format syslog|cef] [--root HEX] [--public-key HEX]
                    [--gate-public-key HEX] [--feedback-public-key HEX] [--json]

Written from docs/EXPORT.md. It imports nothing from this repository, shells out to
nothing, never reads the clock, and uses only the Python standard library, so it can be
copied to the machine where an exported file ended up and run there.

It checks what survives export: each line against the record inside it, the order of the
records and their hash chain, every record's Ed25519 signature, every gate receipt's
signature, every actuator feedback report's signature, and the end-of-export line.
Everything else (rules, state, gaps, anchors, whether a receipt or a report belongs to its
command) is the verifier's job, on the journal itself.

Exit codes: 0 clean, 2 at least one finding, 1 the file cannot be read at all.
"""
import argparse
import calendar
import datetime
import hashlib
import json
import re
import sys

SCHEMA = "sentinel-ledger/record/0"
KINDS = ("genesis", "recorder_start", "recorder_stop", "command", "intervention_declared",
         "intervention_detected", "heartbeat", "recorder_fault", "storage_stall", "anchor_failed",
         "gate_receipt", "actuator_feedback")
AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
APP_NAME = "sentinel-ledger"
CEF_PREFIX = ["0", "Sentinel Ledger", "journal export", "1"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")

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
    """The file cannot be read at all. Exit 1, which is different from a finding."""


class LineError(Exception):
    """One line is not a line of the format."""


# --- hashing (LogChain FORMAT.md, version 2) -------------------------------------------

def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves):
    """RFC 6962: split at the largest power of two strictly below n."""
    if not leaves:
        return None
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# --- Ed25519 verification, RFC 8032 (the verifier's arithmetic, copied, not imported) ---

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P


def _point_add(a, b):
    f = (a[1] - a[0]) * (b[1] - b[0]) % _P
    g = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    d = 2 * a[2] * b[2] % _P
    e, ff, gg, h = g - f, d - c, d + c, g + f
    return (e * ff % _P, gg * h % _P, ff * gg % _P, e * h % _P)


def _point_mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_from_bytes(data):
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - x2) % _P != 0 or (x == 0 and sign):
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_BASE = _point_from_bytes((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(public, message, signature):
    """True only if `signature` (64 bytes) is a valid Ed25519 signature of `message` under
    the public key `public` (32 bytes)."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _point_from_bytes(public), _point_from_bytes(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    left, right = _point_mul(s, _BASE), _point_add(r, _point_mul(k, a))
    return ((left[0] * right[2] - right[0] * left[2]) % _P == 0
            and (left[1] * right[2] - right[1] * left[2]) % _P == 0)


def signature_ok(obj, public_hex):
    """`obj["sig"]` must sign the canonical form of every other field of `obj`."""
    sig = obj.get("sig")
    if not isinstance(sig, str) or len(sig) != 128 or not isinstance(public_hex, str):
        return False
    body = {k: v for k, v in obj.items() if k != "sig"}
    try:
        return ed25519_verify(bytes.fromhex(public_hex), canonical(body).encode("utf-8"), bytes.fromhex(sig))
    except ValueError:
        return False


# --- what a line should say about its record (docs/EXPORT.md section 5) ----------------

def classify(record):
    kind = record.get("kind")
    if kind == "command":
        return COMMAND.get(record.get("outcome"), (4, 6, "command with an unreadable outcome"))
    if kind == "gate_receipt":
        receipt = record.get("receipt")
        decision = receipt.get("decision") if isinstance(receipt, dict) else None
        return RECEIPT.get(decision, (4, 7, "gate receipt: unreadable"))
    return PLAIN.get(kind, (4, 7, "unknown record"))


def epoch_ms(at):
    return calendar.timegm(datetime.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").timetuple()) * 1000


# --- RFC 5424 ---------------------------------------------------------------------------

SYSLOG_HEAD = re.compile(r"<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) ")
SD_NAME = re.compile(r'[^= \]"]{1,32}')


def parse_structured_data(s, i):
    """RFC 5424 section 6.3: the SD-ELEMENTs starting at s[i], and the index after them."""
    elements = []
    while i < len(s) and s[i] == "[":
        m = SD_NAME.match(s, i + 1)
        if not m:
            raise LineError("structured data: an element with no ID")
        sd_id, i, params = m.group(0), m.end(), {}
        while s.startswith(" ", i):
            m = SD_NAME.match(s, i + 1)
            if not m or not s.startswith('="', m.end()):
                raise LineError("structured data: a parameter that is not name=\"value\"")
            name, i, value = m.group(0), m.end() + 2, []
            while True:
                if i >= len(s):
                    raise LineError("structured data: a value with no closing quote")
                c = s[i]
                if c == "\\" and i + 1 < len(s) and s[i + 1] in '"\\]':
                    value.append(s[i + 1])
                    i += 2
                elif c == '"':
                    i += 1
                    break
                elif c == "]":
                    raise LineError("structured data: an unescaped ] inside a value")
                else:
                    value.append(c)
                    i += 1
            if name in params:
                raise LineError("structured data: parameter %s given twice" % name)
            params[name] = "".join(value)
        if not s.startswith("]", i):
            raise LineError("structured data: an element that is not closed")
        elements.append((sd_id, params))
        i += 1
    if not elements:
        raise LineError("no structured data element")
    return elements, i


def parse_syslog(line):
    m = SYSLOG_HEAD.match(line)
    if not m:
        raise LineError("not an RFC 5424 header")
    pri, version, timestamp, hostname, app, procid, msgid = m.groups()
    if int(pri) > 191 or version != "1":
        raise LineError("PRI or VERSION out of range")
    elements, i = parse_structured_data(line, m.end())
    if i == len(line) or line[i] != " ":
        raise LineError("no MSG after the structured data")
    msg = line[i + 1:]
    if msg.startswith("﻿"):
        msg = msg[1:]
    if len(elements) != 1:
        raise LineError("%d structured data elements; this format has one" % len(elements))
    sd_id, params = elements[0]
    base = {"severity": int(pri) % 8, "facility": int(pri) // 8, "timestamp": timestamp, "app": app,
            "procid": procid, "msgid": msgid, "params": params}
    if re.fullmatch(r"sl@\d+", sd_id):
        return dict(base, type="record", raw=msg)
    if re.fullmatch(r"slEnd@\d+", sd_id):
        return dict(base, type="end", msg=msg)
    raise LineError("structured data ID %r is not one of this format's" % sd_id)


def syslog_record_envelope(line, raw, record, leaf):
    """(field, what the line says, what the record says) for every field that disagrees."""
    s, p = line, line["params"]
    expected = [
        ("severity", s["severity"], classify(record)[0]),
        ("app_name", s["app"], APP_NAME),
        ("procid", s["procid"], "-"),
        ("msgid", s["msgid"], record.get("kind")),
        ("timestamp", s["timestamp"], record.get("at")),
        ("sd_params", sorted(p), ["kind", "leaf", "n", "prev"]),
        ("sd_n", p.get("n"), str(record.get("n"))),
        ("sd_kind", p.get("kind"), record.get("kind")),
        ("sd_leaf", p.get("leaf"), leaf),
        ("sd_prev", p.get("prev"), record.get("prev")),
    ]
    return [(f, has, says) for f, has, says in expected if has != says]


def syslog_end_envelope(line):
    p = line["params"]
    expected = [
        ("severity", line["severity"], END[0]),
        ("app_name", line["app"], APP_NAME),
        ("procid", line["procid"], "-"),
        ("msgid", line["msgid"], "export_end"),
        ("sd_params", sorted(p), ["journal", "records", "root"]),
        ("msg", line["msg"], "end of export"),
    ]
    bad = [(f, has, says) for f, has, says in expected if has != says]
    values = {"records": p.get("records"), "root": p.get("root"), "journal": p.get("journal"),
              "timestamp": line["timestamp"]}
    return bad, values


# --- CEF -------------------------------------------------------------------------------

EXT_PAIR = re.compile(r"([A-Za-z0-9_.]+)=((?:\\.|[^\\])*?)(?=\s+[A-Za-z0-9_.]+=|\s*$)", re.S)


def cef_unescape(value, extension):
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            if extension and nxt in "\\=":
                out.append(nxt)
            elif extension and nxt in "nr":
                out.append("\n" if nxt == "n" else "\r")
            elif not extension and nxt in "\\|":
                out.append(nxt)
            else:
                raise LineError("an escape CEF does not define: \\%s" % nxt)
            i += 2
        elif c == "\\":
            raise LineError("a lone backslash at the end of a value")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_cef(line):
    start = line.find("CEF:0|")
    if start < 0:
        raise LineError("no CEF:0| on the line")
    s, fields, cur, i = line[start + 4:], [], [], 0
    while len(fields) < 7:
        if i >= len(s):
            raise LineError("a CEF header with fewer than seven fields")
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            cur.append(c + s[i + 1])
            i += 2
        elif c == "|":
            fields.append(cef_unescape("".join(cur), extension=False))
            cur = []
            i += 1
        else:
            cur.append(c)
            i += 1
    extension, pos, ext = s[i:], 0, {}
    while pos < len(extension):
        m = EXT_PAIR.match(extension, pos)
        if not m:
            raise LineError("the CEF extension does not parse at character %d" % pos)
        key = m.group(1)
        if key in ext:
            raise LineError("extension key %s given twice" % key)
        ext[key] = cef_unescape(m.group(2), extension=True)
        pos = m.end()
        while pos < len(extension) and extension[pos].isspace():
            pos += 1
    header = {"version": fields[0], "vendor": fields[1], "product": fields[2], "device_version": fields[3],
              "event_class": fields[4], "name": fields[5], "severity": fields[6], "ext": ext}
    if fields[:4] != CEF_PREFIX:
        raise LineError("CEF version, vendor, product or device version is not this format's")
    if fields[4] == "export_end":
        return dict(header, type="end")
    if "cs1" not in ext:
        raise LineError("no record (cs1) in the extension")
    return dict(header, type="record", raw=ext["cs1"])


def cef_record_envelope(line, raw, record, leaf):
    _, severity, name = classify(record)
    e = line["ext"]
    try:
        rt = str(epoch_ms(record.get("at")))
    except (TypeError, ValueError):
        rt = None
    expected = [
        ("event_class", line["event_class"], record.get("kind")),
        ("name", line["name"], name),
        ("severity", line["severity"], str(severity)),
        ("extension_keys", sorted(e), sorted(["externalId", "rt", "cs1Label", "cs1", "cs2Label", "cs2",
                                              "cs3Label", "cs3"])),
        ("labels", [e.get("cs1Label"), e.get("cs2Label"), e.get("cs3Label")], ["slRecord", "slLeaf", "slPrev"]),
        ("externalId", e.get("externalId"), str(record.get("n"))),
        ("rt", e.get("rt"), rt),
        ("cs2_leaf", e.get("cs2"), leaf),
        ("cs3_prev", e.get("cs3"), record.get("prev")),
    ]
    return [(f, has, says) for f, has, says in expected if has != says]


def cef_end_envelope(line):
    e = line["ext"]
    expected = [
        ("name", line["name"], END[2]),
        ("severity", line["severity"], str(END[1])),
        ("extension_keys", sorted(e), sorted(["cn1Label", "cn1", "cs4Label", "cs4", "cs5Label", "cs5"])),
        ("labels", [e.get("cn1Label"), e.get("cs4Label"), e.get("cs5Label")], ["slRecords", "slRoot", "slJournal"]),
    ]
    bad = [(f, has, says) for f, has, says in expected if has != says]
    return bad, {"records": e.get("cn1"), "root": e.get("cs4"), "journal": e.get("cs5"), "timestamp": None}


FORMATS = {
    "syslog": (parse_syslog, syslog_record_envelope, syslog_end_envelope),
    "cef": (parse_cef, cef_record_envelope, cef_end_envelope),
}


# --- reading the file ------------------------------------------------------------------

def read_lines(path):
    """(line number, text) for every non-empty line; a line that is not UTF-8 comes back as
    None so it can be reported, not skipped."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise Unusable(str(exc))
    out = []
    for lineno, chunk in enumerate(data.split(b"\n"), 1):
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        if not chunk.strip():
            continue
        try:
            out.append((lineno, chunk.decode("utf-8")))
        except UnicodeDecodeError:
            out.append((lineno, None))
    if not out:
        raise Unusable("the file is empty")
    return out


def detect(lines):
    """The format of the first readable line. A CEF line may carry a forwarder's syslog
    header in front, so a line is syslog only if it parses as this format's syslog."""
    for _, text in lines:
        if text is None:
            continue
        try:
            parse_syslog(text)
            return "syslog"
        except (LineError, ValueError):
            pass
        if "CEF:0|" in text:
            return "cef"
        break
    raise Unusable("the first line is neither this format's RFC 5424 syslog nor CEF; give --format")


def parse_record(raw):
    """A record, or ValueError saying why the text is not one."""
    def no_floats(text):
        raise ValueError("floating-point number " + text)
    obj = json.loads(raw, parse_float=no_floats, parse_constant=no_floats)
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    if canonical(obj) != raw:
        raise ValueError("not in canonical form")
    if obj.get("schema") != SCHEMA:
        raise ValueError("schema is not " + SCHEMA)
    if obj.get("kind") not in KINDS:
        raise ValueError("unknown kind %r" % (obj.get("kind"),))
    if type(obj.get("n")) is not int or not isinstance(obj.get("prev"), str):
        raise ValueError("missing n or prev")
    if not isinstance(obj.get("at"), str) or not AT.match(obj["at"]):
        raise ValueError("at is not a time of the form 2026-10-01T08:00:00Z")
    return obj


# --- the checks (docs/EXPORT.md section 6) ---------------------------------------------

def check(path, fmt=None, root=None, public_key=None, gate_public_key=None, feedback_public_key=None):
    lines = read_lines(path)
    fmt = fmt or detect(lines)
    parse, record_envelope, end_envelope = FORMATS[fmt]
    findings = []

    def add(kind, **more):
        findings.append(dict({"finding": kind}, **more))

    parsed = []
    for lineno, text in lines:
        if text is None:
            add("LINE_MALFORMED", line=lineno, reason="not UTF-8")
            continue
        try:
            parsed.append((lineno, parse(text)))
        except (LineError, ValueError) as exc:
            add("LINE_MALFORMED", line=lineno, reason=str(exc))

    # Records, in file order. A line that did not parse holds no record: what follows it
    # is then out of place, and says so below.
    leaves, prev_hash, key, gate_key, feedback_key = [], "", public_key, gate_public_key, feedback_public_key
    counts = {"lines": len(lines), "records": 0, "signatures_checked": 0, "receipts_checked": 0,
              "feedback_checked": 0}
    ends, last_at, last_record_line = [], None, None
    for lineno, line in parsed:
        if line["type"] == "end":
            ends.append((lineno, line))
            continue
        last_record_line = lineno
        position, raw = counts["records"], line["raw"]
        counts["records"] += 1
        this_hash = leaf_hash(raw.encode("utf-8")).hex()
        leaves.append(bytes.fromhex(this_hash))
        try:
            record = parse_record(raw)
        except ValueError as exc:
            add("RECORD_MALFORMED", line=lineno, position=position, reason=str(exc))
            prev_hash = this_hash
            continue
        last_at = record["at"]
        for field, has, says in record_envelope(line, raw, record, this_hash):
            add("ENVELOPE_MISMATCH", line=lineno, n=record["n"], field=field, line_says=has, record_says=says)
        if position == 0 and record["kind"] != "genesis":
            add("NO_GENESIS", line=lineno)
        if record["n"] != position:
            add("POSITION_MISMATCH", line=lineno, position=position, stored_n=record["n"])
        if record["prev"] != prev_hash:
            add("PREV_MISMATCH", line=lineno, position=position)
        prev_hash = this_hash

        if position == 0 and record["kind"] == "genesis":
            # The keys come from the first record unless they were given. When given, the
            # first record must name the same ones.
            settings = record.get("settings") if isinstance(record.get("settings"), dict) else {}
            named, named_gate = settings.get("recorder_public_key"), settings.get("gate_public_key")
            named_feedback = settings.get("feedback_public_key")
            key, gate_key = public_key or named, gate_public_key or named_gate
            feedback_key = feedback_public_key or named_feedback
            if public_key is not None and named != public_key:
                add("KEY_MISMATCH", line=lineno, journal_key=named, expected_key=public_key)
            if gate_public_key is not None and named_gate != gate_public_key:
                add("KEY_MISMATCH", line=lineno, journal_gate_key=named_gate, expected_gate_key=gate_public_key)
            if feedback_public_key is not None and named_feedback != feedback_public_key:
                add("KEY_MISMATCH", line=lineno, journal_feedback_key=named_feedback,
                    expected_feedback_key=feedback_public_key)

        if key is not None:
            counts["signatures_checked"] += 1
            if "sig" not in record:
                add("SIGNATURE_MISSING", line=lineno, n=record["n"])
            elif not signature_ok(record, key):
                add("SIGNATURE_INVALID", line=lineno, n=record["n"])
        if record["kind"] == "gate_receipt":
            counts["receipts_checked"] += 1
            receipt = record.get("receipt")
            if not isinstance(receipt, dict) or "sig" not in receipt:
                add("RECEIPT_SIGNATURE_INVALID", line=lineno, n=record["n"], reason="the record holds no signed receipt")
            elif gate_key is None:
                add("RECEIPT_SIGNATURE_INVALID", line=lineno, n=record["n"], reason="no gate key is named or given")
            elif not signature_ok(receipt, gate_key):
                add("RECEIPT_SIGNATURE_INVALID", line=lineno, n=record["n"],
                    reason="the receipt is not signed with the gate's key")
        if record["kind"] == "actuator_feedback":
            counts["feedback_checked"] += 1
            report = record.get("feedback")
            if not isinstance(report, dict) or "sig" not in report:
                add("FEEDBACK_SIGNATURE_INVALID", line=lineno, n=record["n"],
                    reason="the record holds no signed feedback")
            elif feedback_key is None:
                add("FEEDBACK_SIGNATURE_INVALID", line=lineno, n=record["n"],
                    reason="no feedback key is named or given")
            elif not signature_ok(report, feedback_key):
                add("FEEDBACK_SIGNATURE_INVALID", line=lineno, n=record["n"],
                    reason="the feedback is not signed with the feedback key")

    top = merkle_root(leaves)
    recomputed = top.hex() if top is not None else None
    journal = leaves[0].hex() if leaves else None
    if counts["records"] and key is None:
        add("KEY_UNKNOWN", reason="no genesis record names a recorder key and none was given; signatures unchecked")
    if not ends:
        add("END_MISSING")
    for lineno, line in ends[1:]:
        add("END_REPEATED", line=lineno)
    if ends and last_record_line is not None and last_record_line > ends[0][0]:
        add("END_NOT_LAST", line=ends[0][0], last_record_line=last_record_line)
    if ends:
        lineno, line = ends[0]
        bad, values = end_envelope(line)
        for field, has, says in bad:
            add("ENVELOPE_MISMATCH", line=lineno, n=None, field=field, line_says=has, record_says=says)
        for field, says in (("records", str(counts["records"])), ("root", recomputed), ("journal", journal),
                            ("timestamp", last_at)):
            if values[field] is not None or field != "timestamp":
                if values[field] != says:
                    add("END_MISMATCH", line=lineno, field=field, end_says=values[field], recomputed=says)
    if root is not None and recomputed != root:
        add("ROOT_MISMATCH", supplied=root, recomputed=recomputed)
    return {"format": fmt, "counts": counts, "root_recomputed": recomputed, "root_checked": root,
            "findings": findings}


def show(result):
    c = result["counts"]
    out = ["format:           %s" % result["format"],
           "lines:            %d, holding %d record(s)" % (c["lines"], c["records"]),
           "signatures:       %d record(s) checked, %d gate receipt(s) checked, %d feedback report(s) checked"
           % (c["signatures_checked"], c["receipts_checked"], c["feedback_checked"]),
           "root recomputed:  %s" % result["root_recomputed"]]
    if result["root_checked"] is None:
        out.append("root checked:     none given. The end line is in the same file as the records; this run "
                   "shows the file is consistent with itself, not that nothing was removed from its end")
    else:
        out.append("root checked:     %s (supplied with --root)" % result["root_checked"])
    for f in result["findings"]:
        detail = " ".join("%s=%s" % (k, json.dumps(v, sort_keys=True)) for k, v in f.items() if k != "finding")
        out.append(("  %s %s" % (f["finding"], detail)).rstrip())
    out.append("NO FINDINGS" if not result["findings"] else "%d FINDING(S)" % len(result["findings"]))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline checker for an exported Sentinel Ledger journal.")
    ap.add_argument("file", help="the exported file")
    ap.add_argument("--format", choices=("syslog", "cef"), help="default: decided from the first line")
    ap.add_argument("--root", help="Merkle root, hex, from a copy the file's keeper cannot edit")
    ap.add_argument("--public-key", help="the recorder's public key, from the machine's configuration")
    ap.add_argument("--gate-public-key", help="the gate's public key, from the machine's configuration")
    ap.add_argument("--feedback-public-key", help="the feedback key, from the machine's configuration")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)
    for name in ("root", "public_key", "gate_public_key", "feedback_public_key"):
        value = getattr(args, name)
        if value is not None and not HEX64.match(value.lower()):
            print("error: --%s must be 64 hexadecimal characters" % name.replace("_", "-"), file=sys.stderr)
            return 1
    try:
        result = check(args.file, args.format, args.root and args.root.lower(),
                       args.public_key and args.public_key.lower(),
                       args.gate_public_key and args.gate_public_key.lower(),
                       args.feedback_public_key and args.feedback_public_key.lower())
    except Unusable as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else show(result))
    return 2 if result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
