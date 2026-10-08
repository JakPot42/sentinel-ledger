"""The five demo scenarios, judged by exit codes and counts."""
import pytest

import run_scenarios


@pytest.mark.parametrize("number", sorted(run_scenarios.SCENARIOS))
def test_scenario_is_as_expected(number, recorder, tmp_path):
    observed = run_scenarios.run_scenario(number, recorder, str(tmp_path))
    assert observed == run_scenarios.EXPECTED[number]


def test_the_driver_exits_zero_only_when_everything_matches(recorder, tmp_path, monkeypatch):
    args = ["--recorder", recorder, "--out", str(tmp_path), "--only", "2"]
    assert run_scenarios.main(args) == 0
    monkeypatch.setitem(run_scenarios.EXPECTED[2], "changed", 3)
    assert run_scenarios.main(args) == 2
