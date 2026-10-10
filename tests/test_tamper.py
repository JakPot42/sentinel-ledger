"""Edits made to a journal after the fact, and what the verifier says about each."""
import json
import os

import pytest

import pure_ed25519 as ed
import run_scenarios
import verify_journal as vj

ALONE = {"witness": False, "gate": False}


def attach(tmp_path, number, recorder):
    return run_scenarios.Workspace(str(tmp_path), "scenario_%d" % number, recorder, fresh=False)


def state_root(w):
    with open(os.path.join(w.data, "logchain.state"), encoding="utf-8") as fh:
        return json.load(fh)["merkle_root"]


@pytest.fixture()
def run2(recorder, tmp_path):
    """Scenario 2's journal, with the root the recorder printed kept as the published root."""
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    return w, state_root(w)


def entries_of(w):
    with open(w.journal, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write(w, entries):
    with open(w.journal, "w", encoding="utf-8", newline="\n") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def forge(w, change, with_the_key=True):
    """Rewrite the journal the way someone who understands the format would: apply
    `change` to the parsed records, then repair every leaf hash, every `prev`, the root,
    the state file and the anchor statements kept beside the journal. Returns the
    forger's own root.

    `with_the_key`: the forger is the operator, who can read the recorder's private key
    and signs every rewritten record again. Without it the old signatures are left on
    records whose contents have changed."""
    entries = entries_of(w)
    records = [json.loads(e["raw"]) for e in entries]
    records = change(records) or records
    with open(w.key_file, encoding="utf-8") as fh:
        seed = bytes.fromhex(fh.read().strip())
    prev = ""
    forged = []
    for n, rec in enumerate(records):
        rec["n"], rec["prev"] = n, prev
        if with_the_key:
            rec = records[n] = ed.sign_record(seed, rec)
        raw = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        prev = vj.leaf_hash(raw.encode("utf-8")).hex()
        forged.append({"seq": n, "ingested_at": entries[min(n, len(entries) - 1)]["ingested_at"],
                       "hash": prev, "raw": raw})
    write(w, forged)
    leaves = [bytes.fromhex(e["hash"]) for e in forged]
    anchors = os.path.join(w.data, "anchors")
    for name in os.listdir(anchors):
        if name.endswith(".json") and name[:8].isdigit():
            count = int(name[:8])
            if count <= len(forged):
                statement = {"schema": "sentinel-ledger/anchor/0", "journal_id": forged[0]["hash"],
                             "entry_count": count, "root": vj.merkle_root(leaves[:count]).hex(),
                             "last_at": records[count - 1]["at"]}
                with open(os.path.join(anchors, name), "w", encoding="utf-8") as fh:
                    fh.write(vj.canonical(statement))
    return vj.merkle_root(leaves).hex()


def findings(report):
    return sorted({f["finding"] for f in report["findings"]})


def test_untouched_journal_is_clean(run2):
    w, published = run2
    assert w.verify(root=published)[0] == 0
    # The witness's anchors are enough on their own: no root has to be supplied.
    code, report = w.verify(gate=False)
    assert code == 0 and report["anchors"][0]["anchors_checked"] == 2


def test_editing_a_record_without_fixing_its_hash(run2):
    w, published = run2
    entries = entries_of(w)
    entries[3]["raw"] = entries[3]["raw"].replace('"applied":{"speed_mm_s":1500}', '"applied":{"speed_mm_s":1800}')
    write(w, entries)
    code, report = w.verify(root=published)
    assert (code, findings(report), report["level_reached"]) == (2, ["EntryHashMismatch"], 1)


def test_dropping_the_last_record(run2):
    w, published = run2
    write(w, entries_of(w)[:-1])
    code, report = w.verify(root=published)
    assert (code, findings(report)) == (2, ["RootMismatch"])
    # With no root supplied, the witness's last anchor covers a record that is gone.
    code, report = w.verify(gate=False)
    assert (code, findings(report)) == (2, ["ANCHOR_BEYOND_JOURNAL"])


def raise_the_clamped_speed(records):
    """Make the journal say the clamped command went out at 1800 after all."""
    for where in (records[3], records[3]["reported"]):
        where["applied"] = {"speed_mm_s": 1800}


def never_asked_for_1800(records):
    """Rewrite the request as well, so the rules agree with the forged outcome."""
    records[3].update({"requested": {"speed_mm_s": 1400}, "applied": {"speed_mm_s": 1400},
                       "outcome": "unchanged", "rules_acted": []})
    records[3]["reported"] = {"applied": {"speed_mm_s": 1400}, "outcome": "unchanged", "rules_acted": []}


def test_a_rewrite_by_someone_without_the_key_fails_the_signature_check(run2):
    """An outsider who can write to the journal but cannot read the recorder's key. Every
    hash and the root are repaired. The verifier is given nothing from outside the
    journal's directory, and still finds it: each record whose contents changed carries a
    signature that no longer fits. That is record 3, and every record after it, because
    each names the hash of the one before."""
    w, _ = run2
    forged_root = forge(w, never_asked_for_1800, with_the_key=False)
    code, report = w.verify(root=forged_root, **ALONE)
    assert code == 2 and findings(report) == ["SIGNATURE_INVALID"]
    assert [f["n"] for f in report["findings"]] == [3, 4, 5, 6]


def test_a_record_with_its_signature_removed(run2):
    w, _ = run2

    def strip(records):
        del records[2]["sig"]

    code, report = w.verify(root=forge(w, strip, with_the_key=False), **ALONE)
    assert code == 2 and "SIGNATURE_MISSING" in findings(report)


def test_a_journal_signed_with_a_different_key_than_the_machines(run2):
    """The whole journal re-signed with the forger's own key, with that key written into
    the first record. Inside the journal everything agrees. Given the public key from the
    machine's configuration, the verifier sees it is not this machine's journal."""
    w, _ = run2
    other = bytes(range(32))
    entries = entries_of(w)
    prev, forged = "", []
    for n, e in enumerate(entries):
        rec = json.loads(e["raw"])
        rec["n"], rec["prev"] = n, prev
        if n == 0:
            rec["settings"]["recorder_public_key"] = ed.public_key(other).hex()
        raw = json.dumps(ed.sign_record(other, rec), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        prev = vj.leaf_hash(raw.encode("utf-8")).hex()
        forged.append(dict(e, hash=prev, raw=raw))
    write(w, forged)
    root = vj.merkle_root([bytes.fromhex(e["hash"]) for e in forged]).hex()
    code, report = w.verify(root=root, **ALONE)
    assert code == 2 and findings(report) == ["KEY_MISMATCH"]


def test_a_clamped_command_records_both_what_was_asked_and_what_was_applied(run2):
    w, _ = run2
    clamped = json.loads(entries_of(w)[3]["raw"])
    assert clamped["requested"] == {"speed_mm_s": 1800}
    assert clamped["applied"] == {"speed_mm_s": 1500}
    assert (clamped["outcome"], clamped["rules_acted"]) == ("changed", ["R2-speed-limit"])
    assert clamped["reported"]["applied"] == {"speed_mm_s": 1500}


def test_a_full_rewrite_fails_against_the_published_root(run2):
    w, published = run2
    forge(w, raise_the_clamped_speed)
    code, report = w.verify(root=published, **ALONE)
    assert (code, findings(report)) == (2, ["RootMismatch"])


def test_a_full_rewrite_with_its_own_root_still_fails_the_rule_check(run2):
    """Even when the forger's root is accepted, the recorded outcome is not what the
    ruleset in force gives for the recorded request."""
    w, _ = run2
    forged_root = forge(w, raise_the_clamped_speed)
    code, report = w.verify(root=forged_root, **ALONE)
    assert code == 2 and report["level_reached"] == 2
    assert findings(report) == ["REPORTED_MISMATCH", "RULE_MISMATCH"]


def test_a_self_consistent_rewrite_passes_when_nothing_outside_the_journal_is_consulted(run2):
    """The limit, shown and not hidden. A forger who can read the recorder's private key,
    which the operator can, and who rewrites the request, the outcome, every signature,
    every hash, the root, the state file and the anchor statements kept beside the
    journal, produces a journal with no findings, as long as the verifier is given only
    things the forger can reach. Signatures stop an outsider. They do not stop the
    operator."""
    w, _ = run2
    forged_root = forge(w, never_asked_for_1800)
    code, report = w.verify("--anchors", os.path.join(w.data, "anchors"), root=forged_root, **ALONE)
    assert code == 0 and report["anchors"][0]["anchors_checked"] == 2


def test_the_same_rewrite_fails_against_the_witness(run2):
    """The forger cannot reach the witness's store. Both roots the witness was sent
    cover the rewritten record, and neither matches the rewritten journal."""
    w, _ = run2
    forged_root = forge(w, never_asked_for_1800)
    code, report = w.verify(root=forged_root, gate=False)
    assert (code, findings(report), report["level_reached"]) == (2, ["ANCHOR_MISMATCH"], 1)
    assert sorted(f["entry_count"] for f in report["findings"]) == [4, 7]
    assert all(f["source"] == "the witness" for f in report["findings"])
    # And with no root supplied at all.
    assert w.verify(gate=False)[0] == 2


def test_the_same_rewrite_fails_against_the_gates_head(run2):
    """The gate on the actuator's side holds the hash of the last record it accepted.
    Each record names the one before it, so that one hash covers the whole history."""
    w, _ = run2
    forged_root = forge(w, never_asked_for_1800)
    code, report = w.verify(root=forged_root, witness=False)
    assert (code, findings(report)) == (2, ["GATE_HEAD_NOT_IN_JOURNAL"])


def test_a_journal_swapped_for_a_different_one_has_no_anchor(run2):
    w, _ = run2

    def new_machine(records):
        records[0]["machine"] = "some-other-conveyor"

    forged_root = forge(w, new_machine)
    code, report = w.verify(root=forged_root, gate=False)
    assert (code, findings(report)) == (2, ["NO_ANCHOR_FOR_JOURNAL"])


def test_a_float_in_a_record(run2):
    w, _ = run2
    entries = entries_of(w)
    raw = entries[2]["raw"].replace('"requested":{"speed_mm_s":800}', '"requested":{"speed_mm_s":800.0}')
    assert raw != entries[2]["raw"]
    entries[2]["raw"], entries[2]["hash"] = raw, vj.leaf_hash(raw.encode("utf-8")).hex()
    write(w, entries)
    root = vj.merkle_root([bytes.fromhex(e["hash"]) for e in entries]).hex()
    code, report = w.verify(root=root, **ALONE)
    assert code == 2 and "RECORD_MALFORMED" in findings(report)


def test_records_out_of_order_in_time(run2):
    w, _ = run2

    def swap_times(records):
        records[3]["at"], records[4]["at"] = records[4]["at"], records[3]["at"]

    code, report = w.verify(root=forge(w, swap_times), **ALONE)
    assert (code, findings(report)) == (2, ["CLOCK_BACKWARDS"])


def test_a_journal_that_does_not_start_with_genesis(run2):
    w, _ = run2
    code, report = w.verify(root=forge(w, lambda records: records[1:]), **ALONE)
    assert code == 2 and "NO_GENESIS" in findings(report)


def test_a_missing_ruleset_file_is_a_finding_not_a_pass(run2):
    w, published = run2
    folder = os.path.join(w.data, "rulesets")
    for name in os.listdir(folder):
        os.remove(os.path.join(folder, name))
    code, report = w.verify(root=published)
    assert (code, findings(report)) == (2, ["RULESET_UNAVAILABLE"])


def test_an_edited_decision_file(recorder, tmp_path):
    run_scenarios.run_scenario(4, recorder, str(tmp_path))
    w = attach(tmp_path, 4, recorder)
    folder = os.path.join(w.data, "decisions")
    victim = os.path.join(folder, sorted(os.listdir(folder))[0])
    with open(victim, "r+", encoding="utf-8") as fh:
        text = fh.read().replace("970", "999")
        fh.seek(0)
        fh.write(text)
    code, report = w.verify(root=state_root(w))
    assert (code, findings(report)) == (2, ["DECISION_MISMATCH"])


def test_an_opaque_ruleset_is_reported_as_not_recomputed(recorder, tmp_path):
    """A safety layer the rule table cannot express: the verifier counts its commands as
    not recomputed and never as checked."""
    w = run_scenarios.Workspace(str(tmp_path), "opaque", recorder)
    with open(os.path.join(w.installed, "ruleset.json"), "w", encoding="utf-8") as fh:
        json.dump({"ruleset_id": "vendor-safety-plc", "kind": "opaque", "rules": []}, fh)
    says = {"applied": {"speed_mm_s": 300}, "outcome": "changed", "rules_acted": ["vendor-rule-17"]}
    ops = [run_scenarios.command(900, safety_layer_says=says), run_scenarios.command(900)]
    code, replies = w.record(ops, "2026-10-01T08:00:00Z")
    # The second command had no verdict from the safety layer: not forwarded, safe state.
    assert code == 3 and [r["ok"] for r in replies] == [True, False]
    assert w.sent() == [("applied", 300), ("recorder_fault", 0)]
    v_code, report = w.verify(root=state_root(w), witness=False)
    assert v_code == 0
    assert (report["counts"]["commands"], report["counts"]["not_recomputed"]) == (1, 1)
    assert report["counts"]["recorder_faults"] == 1


def test_a_float_command_is_refused_and_not_forwarded(recorder, tmp_path):
    w = run_scenarios.Workspace(str(tmp_path), "float", recorder)
    ops = [{"op": "command", "requested": {"speed_mm_s": 500.5}, "safety_inputs": run_scenarios.CLEAR},
           run_scenarios.command(500)]
    code, replies = w.record(ops, "2026-10-01T08:00:00Z")
    assert code == 0 and [r["ok"] for r in replies[:2]] == [False, True]
    assert w.sent() == [("applied", 500)]
