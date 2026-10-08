"""The EU profile: every quotation is in the vendored source, word for word, and the
verifier never claims conformity."""
import hashlib
import html
import json
import os
import re
import subprocess
import sys

import run_scenarios

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = ("compliant", "compliance achieved", "conforms", "complies", "meets the regulation", "certified")


def profile():
    with open(run_scenarios.PROFILE, encoding="utf-8") as fh:
        return json.load(fh)


def plain_text(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as fh:
        raw = fh.read()
    raw = re.sub(r"(?i)</(p|div|tr|td|table|h\d)>", "\n", raw)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", raw)).split())


def test_source_files_are_the_ones_the_profile_names():
    source = profile()["source"]
    for item in (source, source["corrigendum"]):
        with open(os.path.join(REPO, item["file"]), "rb") as fh:
            assert hashlib.sha256(fh.read()).hexdigest() == item["sha256"]


def test_every_quotation_is_verbatim_in_the_source():
    p = profile()
    text = plain_text(p["source"]["file"])
    quotes = []
    for provision in p["provisions"]:
        quotes += provision["text"] + provision.get("not_mapped_text", [])
        quotes += [provision[k] for k in ("purpose", "applies_when") if k in provision]
    assert len(quotes) >= 7
    for quote in quotes:
        assert quote in text, quote[:80]


def test_the_corrigendum_moves_the_application_date():
    p = profile()
    original = plain_text(p["source"]["file"])
    corrigendum = plain_text(p["source"]["corrigendum"]["file"])
    assert "It shall apply from 14 January 2027." in original
    item_10 = corrigendum.split("Article 54, second paragraph:")[1].split("11.")[0]
    assert "14 January 2027" in item_10 and "20 January 2027" in item_10
    assert "ANNEX III" not in corrigendum.upper()
    assert p["source"]["applies_from"] == "2027-01-20"


def test_the_report_never_claims_conformity(recorder, tmp_path):
    run_scenarios.run_scenario(4, recorder, str(tmp_path))
    data = os.path.join(str(tmp_path), "scenario_4", "data")
    with open(os.path.join(data, "logchain.state"), encoding="utf-8") as fh:
        root = json.load(fh)["merkle_root"]
    for as_of in ("2026-12-01", "2028-01-01"):
        done = subprocess.run(
            [sys.executable, run_scenarios.VERIFIER, os.path.join(data, "logchain.journal"), "--root", root,
             "--rulesets", os.path.join(data, "rulesets"), "--decisions", os.path.join(data, "decisions"),
             "--profile", run_scenarios.PROFILE, "--as-of", as_of], capture_output=True, text=True)
        out = done.stdout.lower()
        assert "this profile maps to this provision" in out
        assert not [word for word in FORBIDDEN if word in out]


def test_profile_needs_a_date_and_never_uses_the_clock(recorder, tmp_path):
    run_scenarios.run_scenario(1, recorder, str(tmp_path))
    data = os.path.join(str(tmp_path), "scenario_1", "data")
    done = subprocess.run(
        [sys.executable, run_scenarios.VERIFIER, os.path.join(data, "logchain.journal"), "--state",
         os.path.join(data, "logchain.state"), "--rulesets", os.path.join(data, "rulesets"),
         "--decisions", os.path.join(data, "decisions"), "--profile", run_scenarios.PROFILE],
        capture_output=True, text=True)
    assert done.returncode == 1 and "--as-of" in done.stderr
    with open(run_scenarios.VERIFIER, encoding="utf-8") as fh:
        source = fh.read()
    assert ".now(" not in source and ".today(" not in source and "import time" not in source


def test_the_verifier_shares_no_code_with_the_recorder():
    with open(run_scenarios.VERIFIER, encoding="utf-8") as fh:
        imports = re.findall(r"^(?:import|from)\s+([\w.]+)", fh.read(), flags=re.M)
    assert sorted(set(imports)) == ["argparse", "datetime", "hashlib", "json", "os", "re", "sys"]
