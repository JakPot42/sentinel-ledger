"""Anchoring: the witness's rule, and RFC 3161 timestamps.

Nothing here leaves the machine. The witness listens on localhost. The timestamp tests
use a throwaway timestamping authority made with openssl in a temporary folder, so the
whole path (request, token, verification) runs with real RFC 3161 tokens and no network.
"""
import json
import os
import shutil
import socket
import subprocess
import sys

import pytest

import run_scenarios
import verify_journal as vj
from test_tamper import attach, forge, never_asked_for_1800

OPENSSL = shutil.which("openssl")
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="openssl is not on the PATH")


def anchor_tool(*args):
    return subprocess.run([sys.executable, run_scenarios.ANCHOR, *args], capture_output=True, text=True)


# --- the witness ------------------------------------------------------------------------

def ask(port, statement):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall((json.dumps(statement) + "\n").encode("utf-8"))
        return json.loads(conn.makefile("r", encoding="utf-8").readline())


def statement(count, root_char, journal="a"):
    return {"schema": "sentinel-ledger/anchor/0", "journal_id": journal * 64, "entry_count": count,
            "root": root_char * 64, "last_at": "2026-10-01T08:00:00Z"}


def test_the_witness_keeps_the_first_root_and_refuses_a_different_one(recorder, tmp_path):
    w = run_scenarios.Workspace(str(tmp_path), "witness", recorder)
    w.start_witness()
    try:
        assert ask(w.witness_port, statement(4, "1"))["stored"] is True
        again = ask(w.witness_port, statement(4, "1"))
        assert again["stored"] is True and again["already_held"] is True
        refused = ask(w.witness_port, statement(4, "2"))
        assert refused["stored"] is False and "different root" in refused["refused"]
        assert ask(w.witness_port, statement(4, "2", journal="b"))["stored"] is True
        assert ask(w.witness_port, {"entry_count": 4})["stored"] is False
        assert ask(w.witness_port, "not a statement")["stored"] is False
    finally:
        w.stop_witness()
    with open(w.witness_store, encoding="utf-8") as fh:
        held = [json.loads(line) for line in fh]
    assert [(h["journal_id"][0], h["root"][0]) for h in held] == [("a", "1"), ("b", "2")]


def test_a_forger_cannot_get_the_witness_to_take_the_rewritten_roots(recorder, tmp_path):
    """After the rewrite the forger resubmits. The witness already holds roots for this
    journal at those entry counts, so it refuses, and the anchoring tool exits 2."""
    w = run_scenarios.Workspace(str(tmp_path), "scenario_2", recorder)
    w.start_witness()
    try:
        w.record([run_scenarios.command(s) for s in (800, 1800, -50, 1500)], "2026-10-01T08:00:00Z")
        before = w.anchors_held_by_witness()
        forge(w, never_asked_for_1800)
        for name in os.listdir(os.path.join(w.data, "anchors")):
            if name.endswith(".witness.json"):
                os.remove(os.path.join(w.data, "anchors", name))
        assert w.submit_anchors() == 2
        assert w.anchors_held_by_witness() == before == 2
    finally:
        w.stop_witness()
    assert w.verify(gate=False)[0] == 2


def test_the_anchoring_tool_does_not_touch_the_network_without_the_flag(recorder, tmp_path):
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    done = anchor_tool("fetch", "--dir", w.data)
    assert done.returncode == 1 and "--freetsa" in done.stderr
    assert not [n for n in os.listdir(os.path.join(w.data, "anchors")) if n.endswith(".tsr")]


# --- RFC 3161 ---------------------------------------------------------------------------

TSA_CONFIG = """
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir = .
serial = ./serial
crypto_device = builtin
signer_cert = ./tsa.crt
certs = ./ca.crt
signer_key = ./tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def run_openssl(folder, *args):
    done = subprocess.run([OPENSSL, *args], cwd=folder, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done


@pytest.fixture(scope="module")
def local_tsa(tmp_path_factory):
    """A certificate authority and a timestamping certificate that exist only for this
    test run. Returns a function that answers a request file with a token file."""
    folder = str(tmp_path_factory.mktemp("tsa"))
    with open(os.path.join(folder, "tsa.cnf"), "w") as fh:
        fh.write(TSA_CONFIG)
    with open(os.path.join(folder, "ext.cnf"), "w") as fh:
        fh.write("extendedKeyUsage = critical,timeStamping\n")
    with open(os.path.join(folder, "serial"), "w") as fh:
        fh.write("01\n")
    run_openssl(folder, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
                "-subj", "/CN=Sentinel Ledger test CA", "-days", "2")
    run_openssl(folder, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr",
                "-subj", "/CN=Sentinel Ledger test TSA")
    run_openssl(folder, "x509", "-req", "-in", "tsa.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                "-out", "tsa.crt", "-days", "2", "-extfile", "ext.cnf")

    def answer(query, token):
        run_openssl(folder, "ts", "-reply", "-config", "tsa.cnf", "-queryfile", query, "-out", token)

    answer.ca = os.path.join(folder, "ca.crt")
    answer.cert = os.path.join(folder, "tsa.crt")
    return answer


def stamp_all(w, local_tsa):
    assert anchor_tool("request", "--dir", w.data).returncode == 0
    folder = os.path.join(w.data, "anchors")
    for name in sorted(os.listdir(folder)):
        if name.endswith(".tsq"):
            local_tsa(os.path.join(folder, name), os.path.join(folder, name[:-4] + ".tsr"))


def verify_tokens(w, local_tsa, *extra):
    return anchor_tool("verify", "--dir", w.data, "--ca", local_tsa.ca, "--untrusted", local_tsa.cert, *extra)


@needs_openssl
def test_timestamps_round_trip(recorder, tmp_path, local_tsa):
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    before = verify_tokens(w, local_tsa)
    assert before.returncode == 2 and before.stdout.count("NOT_TIMESTAMPED") == 2
    stamp_all(w, local_tsa)
    done = verify_tokens(w, local_tsa)
    assert done.returncode == 0, done.stdout
    assert done.stdout.count("timestamped ") == 2
    # The statements the tokens cover are the journal's own roots.
    code, report = w.verify("--anchors", os.path.join(w.data, "anchors"), witness=False, gate=False,
                            root=report_root(w))
    assert code == 0 and report["anchors"][0]["anchors_checked"] == 2


def report_root(w):
    with open(os.path.join(w.data, "logchain.state"), encoding="utf-8") as fh:
        return json.load(fh)["merkle_root"]


@needs_openssl
def test_a_rewritten_journal_no_longer_matches_its_timestamps(recorder, tmp_path, local_tsa):
    """Two ways the forger can go, and both fail.
    Keep the original statements: their roots are not the rewritten journal's.
    Rewrite the statements to match: the tokens were issued for different bytes."""
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    stamp_all(w, local_tsa)
    anchors = os.path.join(w.data, "anchors")
    kept = os.path.join(str(tmp_path), "original_statements")
    shutil.copytree(anchors, kept)

    forged_root = forge(w, never_asked_for_1800)  # rewrites the statements too
    tokens = verify_tokens(w, local_tsa)
    assert tokens.returncode == 2 and tokens.stdout.count("TOKEN_INVALID") == 2
    assert w.verify("--anchors", anchors, root=forged_root, witness=False, gate=False)[0] == 0

    code, report = w.verify("--anchors", kept, root=forged_root, witness=False, gate=False)
    assert code == 2 and {f["finding"] for f in report["findings"]} == {"ANCHOR_MISMATCH"}


@needs_openssl
def test_a_token_from_another_authority_is_not_accepted(recorder, tmp_path, local_tsa, tmp_path_factory):
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    stamp_all(w, local_tsa)
    other = str(tmp_path_factory.mktemp("other_ca"))
    run_openssl(other, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
                "-subj", "/CN=Some other CA", "-days", "2")
    done = anchor_tool("verify", "--dir", w.data, "--ca", os.path.join(other, "ca.crt"))
    assert done.returncode == 2 and done.stdout.count("TOKEN_INVALID") == 2


@needs_openssl
def test_a_token_issued_long_after_the_records_is_a_finding(recorder, tmp_path, local_tsa):
    """The demo journal's clock is fixed at 1 October 2026 and the token is issued now.
    Stamping a root long after the records it covers is what a rewrite looks like."""
    run_scenarios.run_scenario(2, recorder, str(tmp_path))
    w = attach(tmp_path, 2, recorder)
    stamp_all(w, local_tsa)
    late = verify_tokens(w, local_tsa, "--max-lag-seconds", "60")
    assert late.returncode == 2 and late.stdout.count("STAMPED_LATE") == 2
    assert verify_tokens(w, local_tsa, "--max-lag-seconds", str(20 * 365 * 86400)).returncode == 0


def test_openssl_is_available_for_the_timestamp_tests():
    """If this fails, the four timestamp tests above were skipped, not passed."""
    assert OPENSSL is not None
