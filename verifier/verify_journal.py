#!/usr/bin/env python3
"""Independent verifier for a Sentinel Ledger journal.

Written from docs/SPEC.md and LogChain's docs/FORMAT.md. It imports nothing from the
recorder or from LogChain, shells out to nothing, and uses only the Python standard
library, so it can be read, audited and run on its own.

    verify_journal.py JOURNAL --rulesets DIR [--root HEX] [--witness-store FILE]
                      [--anchors DIR] [--gate-state FILE] [--decisions DIR]
                      [--profile FILE --as-of YYYY-MM-DD] [--json]
    verify_journal.py --receipt FILE --root HEX

Three levels, and it stops at the first one that fails:
  1. the chain: every leaf hash, then the Merkle root (LogChain format version 2), then
     every anchored root it was given and the head the actuator-side gate holds;
  2. the records: position, order, the state in force, and which rule acted;
  3. a profile, when one is given: which records it maps to a rule, and retention.

Exit codes: 0 clean, 2 at least one finding, 1 usage or I/O error.

It never reads the clock. Anything that depends on a date takes --as-of.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

SCHEMA = "sentinel-ledger/record/0"
RECEIPT_SCHEMA = "sentinel-ledger/receipt/0"
PROFILE_SCHEMA = "sentinel-ledger/profile/0"
KINDS = ("genesis", "recorder_start", "recorder_stop", "command", "intervention_declared",
         "intervention_detected", "heartbeat", "recorder_fault")
AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OPS = {"lt": lambda a, b: a < b, "le": lambda a, b: a <= b, "eq": lambda a, b: a == b,
       "ge": lambda a, b: a >= b, "gt": lambda a, b: a > b}


class Unusable(Exception):
    """The inputs cannot be read at all. Exit 1, which is different from a finding."""


# --- hashing and canonical form (SPEC 7.1, FORMAT.md 3 to 5) ---------------------------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


# --- level 1: the chain ----------------------------------------------------------------

def read_journal(path):
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError as exc:
                    raise Unusable("journal line %d is not JSON: %s" % (lineno, exc))
                ok = (isinstance(e, dict) and type(e.get("seq")) is int and e["seq"] >= 0
                      and isinstance(e.get("ingested_at"), str) and isinstance(e.get("raw"), str)
                      and isinstance(e.get("hash"), str) and len(e["hash"]) == 64)
                if not ok:
                    raise Unusable("journal line %d is not a LogChain entry" % lineno)
                entries.append(e)
    except OSError as exc:
        raise Unusable(str(exc))
    return entries


def check_chain(entries, root, compare_root=True):
    findings = []
    if entries and all(e["hash"] == sha256_hex(e["raw"].encode("utf-8")) for e in entries):
        return [{"finding": "LegacyV1Journal", "entry_count": len(entries)}], None
    leaves = []
    for position, e in enumerate(entries):
        if e["seq"] != position:
            findings.append({"finding": "SeqMismatch", "position": position, "stored_seq": e["seq"]})
        recomputed = leaf_hash(e["raw"].encode("utf-8"))
        if recomputed.hex() != e["hash"]:
            findings.append({"finding": "EntryHashMismatch", "seq": e["seq"],
                             "stored": e["hash"], "recomputed": recomputed.hex()})
        try:
            leaves.append(bytes.fromhex(e["hash"]))
        except ValueError:
            raise Unusable("journal entry %d: hash is not hex" % position)
    top = merkle_root(leaves)
    recomputed_root = top.hex() if top is not None else None
    if (compare_root and recomputed_root != root
            and not any(f["finding"] == "EntryHashMismatch" for f in findings)):
        findings.append({"finding": "RootMismatch", "supplied": root, "recomputed": recomputed_root})
    return findings, recomputed_root


# --- level 1, continued: anchored roots and the gate's head (SPEC 7.5, 4.2) -----------

def read_witness_store(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError) as exc:
        raise Unusable("witness store: %s" % exc)


def read_statements(directory):
    found = []
    try:
        for name in sorted(os.listdir(directory)):
            if re.fullmatch(r"\d{8}\.json", name):
                with open(os.path.join(directory, name), "r", encoding="utf-8") as fh:
                    found.append(json.load(fh))
    except (OSError, ValueError) as exc:
        raise Unusable("anchor statements: %s" % exc)
    return found


def check_anchors(entries, anchors, source):
    """Every anchor for this journal must be the root of the journal's first
    `entry_count` records. Roots are recomputed from the record text."""
    leaves = [leaf_hash(e["raw"].encode("utf-8")) for e in entries]
    journal_id = leaves[0].hex() if leaves else None
    mine = sorted((a for a in anchors if isinstance(a, dict) and a.get("journal_id") == journal_id
                   and type(a.get("entry_count")) is int), key=lambda a: a["entry_count"])
    info = {"source": source, "anchors_checked": len(mine), "records_after_last_anchor": None}
    if not mine:
        return [{"finding": "NO_ANCHOR_FOR_JOURNAL", "source": source, "journal_id": journal_id}], info
    findings = []
    for a in mine:
        count = a["entry_count"]
        if count > len(leaves) or count < 1:
            findings.append({"finding": "ANCHOR_BEYOND_JOURNAL", "source": source, "entry_count": count,
                             "journal_records": len(leaves)})
            continue
        recomputed = merkle_root(leaves[:count]).hex()
        if recomputed != a.get("root"):
            findings.append({"finding": "ANCHOR_MISMATCH", "source": source, "entry_count": count,
                             "anchored": a.get("root"), "recomputed": recomputed})
            continue
        try:
            at = json.loads(entries[count - 1]["raw"]).get("at")
        except (ValueError, AttributeError):
            at = None
        if a.get("last_at") != at:
            findings.append({"finding": "ANCHOR_MISMATCH", "source": source, "entry_count": count,
                             "reason": "last_at is not the time of the last record covered"})
    info["records_after_last_anchor"] = len(leaves) - mine[-1]["entry_count"]
    return findings, info


def check_gate(entries, path):
    """The record the actuator-side gate last accepted must be in the journal."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            gate = json.load(fh)
        n, held = gate["n"], gate["hash"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Unusable("gate state: %s" % exc)
    info = {"gate_head": n, "records_after_gate_head": len(entries) - 1 - n if type(n) is int else None}
    if type(n) is not int or n < 0:
        return [], info
    if n >= len(entries) or leaf_hash(entries[n]["raw"].encode("utf-8")).hex() != held:
        return [{"finding": "GATE_HEAD_NOT_IN_JOURNAL", "gate_n": n, "gate_hash": held,
                 "journal_records": len(entries)}], info
    return [], info


# --- level 2: the records --------------------------------------------------------------

def _no_floats(text):
    raise ValueError("floating-point number " + text)


def _has_bool(obj):
    if isinstance(obj, bool):
        return True
    if isinstance(obj, dict):
        return any(_has_bool(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_bool(v) for v in obj)
    return False


def parse_record(raw):
    """A record, or ValueError saying why the text is not one."""
    obj = json.loads(raw, parse_float=_no_floats, parse_constant=_no_floats)
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    if _has_bool(obj):
        raise ValueError("boolean value")
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


def seconds(at):
    return int(datetime.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=datetime.timezone.utc).timestamp())


def load_rulesets(directory):
    """Every file in the directory, keyed by the SHA-256 of its bytes."""
    found = {}
    try:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    data = fh.read()
                found[sha256_hex(data)] = data
    except OSError as exc:
        raise Unusable(str(exc))
    return found


def parse_ruleset(data):
    """A ruleset, or ValueError. SPEC 5.2."""
    rs = json.loads(data.decode("utf-8"))
    if not isinstance(rs, dict) or rs.get("kind") not in ("declared", "opaque"):
        raise ValueError("unknown ruleset kind")
    if not isinstance(rs.get("ruleset_id"), str) or not isinstance(rs.get("rules"), list):
        raise ValueError("ruleset lacks ruleset_id or rules")
    for r in rs["rules"]:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str):
            raise ValueError("a rule lacks an id")
        if r.get("type") == "clamp":
            good = (isinstance(r.get("field"), str) and type(r.get("min")) is int
                    and type(r.get("max")) is int and r["min"] <= r["max"])
        elif r.get("type") == "block_when":
            good = isinstance(r.get("input"), str) and r.get("op") in OPS and type(r.get("value")) is int
        else:
            good = False
        if not good:
            raise ValueError("rule %s is not a rule this specification defines" % r["id"])
    return rs


def evaluate(ruleset, requested, inputs):
    """What a declared ruleset gives for one command. SPEC 5.2."""
    applied = dict(requested)
    acted = []
    for rule in ruleset["rules"]:
        if rule["type"] == "clamp":
            value = applied.get(rule["field"])
            if type(value) is int:
                bounded = min(max(value, rule["min"]), rule["max"])
                if bounded != value:
                    applied[rule["field"]] = bounded
                    acted.append(rule["id"])
        else:
            value = inputs.get(rule["input"])
            if type(value) is not int or OPS[rule["op"]](value, rule["value"]):
                acted.append(rule["id"])
                return {"applied": None, "outcome": "blocked", "rules_acted": acted}
    return {"applied": applied, "outcome": "changed" if acted else "unchanged", "rules_acted": acted}


def get_target(state, target):
    if target == "ruleset":
        return state["ruleset_sha256"]
    if target == "config":
        return state["config_sha256"]
    if isinstance(target, str) and target.startswith("software:"):
        return state["software"].get(target[len("software:"):])
    raise ValueError("unknown target %r" % (target,))


def set_target(state, target, value):
    if target == "ruleset":
        state["ruleset_sha256"] = value
    elif target == "config":
        state["config_sha256"] = value
    else:
        state["software"][target[len("software:"):]] = value


def good_state(state):
    return (isinstance(state, dict) and set(state) == {"config_sha256", "ruleset_sha256", "software"}
            and isinstance(state["config_sha256"], str) and isinstance(state["ruleset_sha256"], str)
            and isinstance(state["software"], dict))


def good_settings(settings):
    return (isinstance(settings, dict) and type(settings.get("heartbeat_seconds")) is int
            and settings["heartbeat_seconds"] > 0)


def good_command(rec):
    verdict_keys = ("applied", "outcome", "rules_acted")
    if not all(k in rec for k in verdict_keys + ("requested", "safety_inputs", "in_force", "reported")):
        return "a required field is missing"
    if not isinstance(rec["requested"], dict) or not isinstance(rec["safety_inputs"], dict):
        return "requested and safety_inputs must be objects"
    for where in (rec, rec["reported"]):
        if not isinstance(where, dict) or not all(k in where for k in verdict_keys):
            return "reported lacks a field"
        if where["outcome"] not in ("unchanged", "changed", "blocked"):
            return "unknown outcome"
        if (where["applied"] is None) != (where["outcome"] == "blocked"):
            return "applied must be null exactly when the outcome is blocked"
        if where["applied"] is not None and not isinstance(where["applied"], dict):
            return "applied must be an object or null"
        if not isinstance(where["rules_acted"], list):
            return "rules_acted must be a list"
    if ("decision_sha256" in rec) != ("decision_bytes" in rec):
        return "decision_sha256 and decision_bytes go together"
    return None


def check_records(entries, rulesets, decisions_dir):
    findings = []
    counts = {"records": len(entries), "commands": 0, "unchanged": 0, "changed": 0, "blocked": 0,
              "not_recomputed": 0, "interventions_declared": 0, "interventions_detected": 0,
              "heartbeats": 0, "recorder_faults": 0, "restarts_without_stop": 0,
              "decisions_named": 0, "decisions_checked": 0, "decision_absent": 0}
    downtime = []
    records = []
    parsed_rulesets = {}
    state = settings = None
    prev_hash, prev_at, prev_kind = "", None, None

    def add(kind, n, **more):
        findings.append(dict({"finding": kind, "n": n}, **more))

    for position, entry in enumerate(entries):
        this_hash = leaf_hash(entry["raw"].encode("utf-8")).hex()
        try:
            rec = parse_record(entry["raw"])
        except ValueError as exc:
            add("RECORD_MALFORMED", position, reason=str(exc))
            prev_hash, prev_kind = this_hash, None
            records.append(None)
            continue
        records.append(rec)
        kind = rec["kind"]
        if rec["n"] != position:
            add("POSITION_MISMATCH", position, stored_n=rec["n"])
        if rec["prev"] != prev_hash:
            add("PREV_MISMATCH", position)
        if prev_at is not None and rec["at"] < prev_at:
            add("CLOCK_BACKWARDS", position, at=rec["at"], previous=prev_at)
        if position == 0 and kind != "genesis":
            add("NO_GENESIS", position)
        if position > 0 and kind == "genesis":
            add("RECORD_MALFORMED", position, reason="a genesis record that is not the first record")
        if prev_at is not None and settings is not None and rec["at"] >= prev_at:
            gap = seconds(rec["at"]) - seconds(prev_at)
            if gap > 2 * settings["heartbeat_seconds"]:
                if prev_kind == "recorder_stop" and kind == "recorder_start":
                    downtime.append({"from": prev_at, "to": rec["at"], "seconds": gap})
                else:
                    add("HEARTBEAT_GAP", position, seconds=gap, previous=prev_at, at=rec["at"])

        if kind == "genesis" and position == 0:
            if good_state(rec.get("state")) and good_settings(rec.get("settings")):
                state, settings = json.loads(canonical(rec["state"])), rec["settings"]
            else:
                add("RECORD_MALFORMED", position, reason="genesis lacks a usable state or settings")
        elif kind == "recorder_start":
            if prev_kind not in ("genesis", "recorder_stop"):
                counts["restarts_without_stop"] += 1
        elif kind == "heartbeat":
            counts["heartbeats"] += 1
        elif kind == "recorder_fault":
            counts["recorder_faults"] += 1
        elif kind in ("intervention_declared", "intervention_detected"):
            counts["interventions_declared" if kind.endswith("declared") else "interventions_detected"] += 1
            if kind == "intervention_declared":
                changes = [{"target": rec.get("target"), "expected": rec.get("old"), "measured": rec.get("new")}]
            else:
                changes = rec.get("changes")
            if not isinstance(changes, list) or not changes or not all(isinstance(c, dict) for c in changes):
                add("RECORD_MALFORMED", position, reason="no list of changes")
            elif state is not None:
                for change in changes:
                    try:
                        current = get_target(state, change.get("target"))
                    except ValueError as exc:
                        add("RECORD_MALFORMED", position, reason=str(exc))
                        continue
                    if change.get("expected") != current:
                        add("IN_FORCE_MISMATCH", position, target=change["target"],
                            reason="the record's previous value is not the replayed value")
                    set_target(state, change["target"], change.get("measured"))
                    if change["target"] == "config":
                        if good_settings(rec.get("settings")):
                            settings = rec["settings"]
                        else:
                            add("RECORD_MALFORMED", position, reason="a configuration change without settings")
        elif kind == "command":
            counts["commands"] += 1
            problem = good_command(rec)
            if problem:
                add("RECORD_MALFORMED", position, reason=problem)
            elif state is not None:
                counts[rec["outcome"]] += 1
                recorded = {k: rec[k] for k in ("applied", "outcome", "rules_acted")}
                if rec["in_force"] != sha256_hex(canonical(state).encode("utf-8")):
                    add("IN_FORCE_MISMATCH", position,
                        reason="in_force is not the hash of the state the journal put in force")
                sha = state["ruleset_sha256"]
                if sha not in parsed_rulesets:
                    try:
                        parsed_rulesets[sha] = parse_ruleset(rulesets[sha]) if sha in rulesets else None
                    except (ValueError, UnicodeDecodeError) as exc:
                        parsed_rulesets[sha] = str(exc)
                ruleset = parsed_rulesets[sha]
                if ruleset is None:
                    add("RULESET_UNAVAILABLE", position, ruleset_sha256=sha, reason="no file with this hash")
                elif isinstance(ruleset, str):
                    add("RULESET_UNAVAILABLE", position, ruleset_sha256=sha, reason=ruleset)
                elif ruleset["kind"] == "opaque":
                    counts["not_recomputed"] += 1
                    if rec["reported"] != recorded:
                        add("REPORTED_MISMATCH", position, reason="the record differs from the safety layer's report")
                else:
                    recomputed = evaluate(ruleset, rec["requested"], rec["safety_inputs"])
                    if recorded != recomputed:
                        add("RULE_MISMATCH", position, recorded=recorded, recomputed=recomputed)
                    if rec["reported"] != recomputed:
                        add("REPORTED_MISMATCH", position, reported=rec["reported"], recomputed=recomputed)
                if "decision_sha256" in rec:
                    counts["decisions_named"] += 1
                    data = read_decision(decisions_dir, rec["decision_sha256"])
                    if data is None:
                        counts["decision_absent"] += 1
                    else:
                        counts["decisions_checked"] += 1
                        if sha256_hex(data) != rec["decision_sha256"] or len(data) != rec["decision_bytes"]:
                            add("DECISION_MISMATCH", position, decision_sha256=rec["decision_sha256"])
        prev_hash, prev_at, prev_kind = this_hash, rec["at"], kind

    return findings, counts, downtime, records


def read_decision(decisions_dir, sha):
    if decisions_dir is None or not isinstance(sha, str) or not HEX64.match(sha):
        return None
    try:
        with open(os.path.join(decisions_dir, sha + ".json"), "rb") as fh:
            return fh.read()
    except OSError:
        return None


# --- level 3: a profile (SPEC 10) ------------------------------------------------------

def add_years(at, years):
    """The date `years` after the date part of `at`. 29 February becomes 28 February."""
    d = datetime.date.fromisoformat(at[:10])
    try:
        return d.replace(year=d.year + years)
    except ValueError:
        return d.replace(year=d.year + years, day=28)


def touches_software(rec):
    if rec["kind"] == "genesis":
        return True
    if rec["kind"] == "intervention_declared":
        return str(rec.get("target", "")).startswith("software:")
    if rec["kind"] == "intervention_detected":
        return any(str(c.get("target", "")).startswith("software:") for c in rec.get("changes", []))
    return False


def check_profile(profile, records, decisions_dir, as_of):
    findings, report = [], []
    records = [r for r in records if r is not None]
    for p in profile["provisions"]:
        mapped = [r for r in records if r["kind"] in p["record_kinds"]]
        line = {"provision": p["id"], "citation": p["citation"], "records_held": len(mapped)}
        retention = p.get("retention")
        if retention is None:
            line["retention"] = "the provision states no period"
        elif retention["applies_to"] == "software_version_records":
            dated = [r for r in mapped if touches_software(r)]
            line["records_counted_for_retention"] = len(dated)
            if dated:
                line["keep_until_at_least"] = max(add_years(r["at"], retention["years"]) for r in dated).isoformat()
            line["retention"] = "journal records are never deleted by this build"
        elif retention["applies_to"] == "decision_files":
            named = [r for r in records if r["kind"] == "command" and "decision_sha256" in r]
            held = required = 0
            releasable = []
            for r in named:
                until = add_years(r["at"], retention["years"])
                present = read_decision(decisions_dir, r["decision_sha256"]) is not None
                held += present
                if as_of <= until:
                    required += 1
                    if not present:
                        findings.append({"finding": "RETENTION_SHORTFALL", "n": r["n"], "provision": p["id"],
                                         "decision_sha256": r["decision_sha256"],
                                         "required_until": until.isoformat()})
                elif present:
                    releasable.append(r["decision_sha256"])
            line.update({"records_held": len(named), "decision_files_named": len(named),
                         "decision_files_held": held, "still_required_on_as_of": required,
                         "may_be_released": releasable})
        else:
            raise Unusable("profile: unknown retention rule %r" % (retention.get("applies_to"),))
        if p.get("not_mapped"):
            line["not_mapped"] = p["not_mapped"]
        report.append(line)
    return findings, report


def load_profile(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            profile = json.load(fh)
    except (OSError, ValueError) as exc:
        raise Unusable("profile: %s" % exc)
    if profile.get("profile_schema") != PROFILE_SCHEMA or not isinstance(profile.get("provisions"), list):
        raise Unusable("profile: not a %s file" % PROFILE_SCHEMA)
    return profile


# --- receipts (SPEC 7.3) ---------------------------------------------------------------

def check_receipt(path, root):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            receipt = json.load(fh)
        proof, raw = receipt["proof"], receipt["record"]
        if receipt.get("receipt_schema") != RECEIPT_SCHEMA or proof.get("format_version") != 2:
            raise Unusable("receipt: not a %s file over a version 2 journal" % RECEIPT_SCHEMA)
        current = leaf_hash(raw.encode("utf-8"))
        findings = []
        if current.hex() != proof["leaf_hash"]:
            findings.append({"finding": "RECEIPT_LEAF_MISMATCH"})
        for step in proof["path"]:
            sibling = bytes.fromhex(step["hash"])
            if step["side"] == "left":
                current = node_hash(sibling, current)
            elif step["side"] == "right":
                current = node_hash(current, sibling)
            else:
                raise Unusable("receipt: side must be left or right")
        if current.hex() != root:
            findings.append({"finding": "RECEIPT_ROOT_MISMATCH", "supplied": root, "recomputed": current.hex()})
        try:
            rec = parse_record(raw)
            if rec["n"] != proof["seq"]:
                findings.append({"finding": "POSITION_MISMATCH", "n": proof["seq"], "stored_n": rec["n"]})
        except ValueError as exc:
            findings.append({"finding": "RECORD_MALFORMED", "n": proof.get("seq"), "reason": str(exc)})
        return findings, proof.get("seq")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Unusable("receipt: %s" % exc)


# --- command line ----------------------------------------------------------------------

def show(result):
    out = []
    out.append("root checked:     %s (%s)" % (result["root_checked"], result["root_source"]))
    out.append("level reached:    %d" % result["level_reached"])
    for a in result.get("anchors", []):
        out.append("anchors:          %d from %s match the journal; %s record(s) after the last one"
                   % (a["anchors_checked"], a["source"], a["records_after_last_anchor"]))
    if result.get("gate"):
        out.append("actuator gate:    its head is record %s; %s record(s) in the journal after it"
                   % (result["gate"]["gate_head"], result["gate"]["records_after_gate_head"]))
    if result.get("counts"):
        c = result["counts"]
        out.append("records:          %d" % c["records"])
        out.append("commands:         %d  (unchanged %d, changed %d, blocked %d, not recomputed %d)"
                   % (c["commands"], c["unchanged"], c["changed"], c["blocked"], c["not_recomputed"]))
        out.append("interventions:    %d declared, %d detected by measurement"
                   % (c["interventions_declared"], c["interventions_detected"]))
        out.append("heartbeats:       %d" % c["heartbeats"])
        out.append("decision files:   %d named, %d present and matching their hash, %d absent"
                   % (c["decisions_named"], c["decisions_checked"], c["decision_absent"]))
        if c["recorder_faults"] or c["restarts_without_stop"]:
            out.append("recorder:         %d fault record(s), %d start(s) with no stop before"
                       % (c["recorder_faults"], c["restarts_without_stop"]))
        for d in result.get("downtime", []):
            out.append("stopped:          %s to %s (%d s), between a stop and a start"
                       % (d["from"], d["to"], d["seconds"]))
    if result.get("profile"):
        out.append("")
        out.append("profile %s, as of %s" % (result["profile"]["profile_id"], result["profile"]["as_of"]))
        for line in result["profile"]["provisions"]:
            out.append("  provision %s (%s)" % (line["provision"], line["citation"]))
            out.append("    the journal holds %d record(s) this profile maps to this provision"
                       % line["records_held"])
            for key in ("records_counted_for_retention", "keep_until_at_least", "decision_files_held",
                        "still_required_on_as_of", "retention"):
                if key in line:
                    out.append("    %s: %s" % (key.replace("_", " "), line[key]))
            if line.get("may_be_released"):
                out.append("    may be released: %d decision file(s) past their period" % len(line["may_be_released"]))
            for gap in line.get("not_mapped", []):
                out.append("    not mapped: %s" % gap)
    for f in result["findings"]:
        detail = " ".join("%s=%s" % (k, json.dumps(v, sort_keys=True)) for k, v in f.items() if k != "finding")
        out.append(("  %s %s" % (f["finding"], detail)).rstrip())
    out.append("NO FINDINGS" if not result["findings"] else "%d FINDING(S)" % len(result["findings"]))
    return "\n".join(out)


def run(args):
    if args.root is not None:
        root, source = args.root.lower(), "supplied with --root"
    elif args.state:
        try:
            with open(args.state, "r", encoding="utf-8") as fh:
                state = json.load(fh)
        except (OSError, ValueError) as exc:
            raise Unusable("state file: %s" % exc)
        if state.get("format_version", 1) != 2:
            raise Unusable("the state file is LogChain format version %s; this verifier reads version 2"
                           % state.get("format_version", 1))
        root, source = state.get("merkle_root"), "read from the state file kept beside the journal"
        print("warning: the root was read from the state file. Whoever can edit the journal can "
              "edit that file too. This run shows only that the two files agree.", file=sys.stderr)
    elif args.witness_store and not args.receipt:
        root, source = None, "none supplied; the journal is checked against the witness's anchors"
    else:
        raise Unusable("supply --root, --witness-store, or --state to read the root from the state file")

    if args.receipt:
        findings, seq = check_receipt(args.receipt, root)
        return {"mode": "receipt", "n": seq, "root_checked": root, "root_source": source,
                "level_reached": 1, "findings": findings}

    if not args.journal or not args.rulesets:
        raise Unusable("a journal and --rulesets are required")
    profile = as_of = None
    if args.profile:
        if not args.as_of or not args.decisions:
            raise Unusable("--profile needs --as-of YYYY-MM-DD and --decisions DIR")
        profile = load_profile(args.profile)
        try:
            as_of = datetime.date.fromisoformat(args.as_of)
        except ValueError:
            raise Unusable("--as-of must be a date, YYYY-MM-DD")

    entries = read_journal(args.journal)
    result = {"mode": "journal", "root_checked": root, "root_source": source, "level_reached": 1}
    findings, recomputed = check_chain(entries, root, compare_root=root is not None or not args.witness_store)
    result["root_recomputed"] = recomputed
    if result["root_checked"] is None:
        result["root_checked"] = recomputed
    if not findings:
        result["anchors"] = []
        sources = []
        if args.witness_store:
            sources.append((read_witness_store(args.witness_store), "the witness"))
        if args.anchors:
            sources.append((read_statements(args.anchors), "the statements beside the journal"))
        for anchors, name in sources:
            more, info = check_anchors(entries, anchors, name)
            findings += more
            result["anchors"].append(info)
        if args.gate_state:
            more, result["gate"] = check_gate(entries, args.gate_state)
            findings += more
    if not findings:
        result["level_reached"] = 2
        findings, result["counts"], result["downtime"], records = check_records(
            entries, load_rulesets(args.rulesets), args.decisions)
        if not findings and profile is not None:
            result["level_reached"] = 3
            findings, provisions = check_profile(profile, records, args.decisions, as_of)
            result["profile"] = {"profile_id": profile.get("profile_id"), "as_of": as_of.isoformat(),
                                 "provisions": provisions}
    result["findings"] = findings
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent verifier for a Sentinel Ledger journal.")
    ap.add_argument("journal", nargs="?", help="path to the journal (logchain.journal)")
    ap.add_argument("--root", help="Merkle root, hex, from a copy the journal's keeper cannot edit")
    ap.add_argument("--state", help="read the root from logchain.state instead (prints a warning)")
    ap.add_argument("--witness-store", help="a witness's store of anchored roots; every one must match")
    ap.add_argument("--anchors", help="directory of anchor statements (for example timestamped ones); every one must match")
    ap.add_argument("--gate-state", help="the actuator-side gate's state file; its head must be in the journal")
    ap.add_argument("--rulesets", help="directory holding the ruleset files the journal names")
    ap.add_argument("--decisions", help="directory holding decision files, named by their SHA-256")
    ap.add_argument("--profile", help="a profile file to report against (level 3)")
    ap.add_argument("--as-of", help="the date retention is judged on, YYYY-MM-DD")
    ap.add_argument("--receipt", help="check one receipt against the root instead of a journal")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)
    try:
        result = run(args)
    except Unusable as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else show(result))
    return 2 if result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
