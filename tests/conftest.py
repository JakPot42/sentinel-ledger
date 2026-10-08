"""Shared setup: build the recorder once, and make the demo driver and the verifier importable."""
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDER_DIR = os.path.join(REPO, "recorder")
EXE = "sentinel-recorder.exe" if os.name == "nt" else "sentinel-recorder"
sys.path.insert(0, os.path.join(REPO, "demo"))
sys.path.insert(0, os.path.join(REPO, "verifier"))


def cargo_build(*extra):
    done = subprocess.run(["cargo", "build", "--quiet", *extra], cwd=RECORDER_DIR, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


@pytest.fixture(scope="session")
def recorder():
    """The recorder as shipped: no planted bug."""
    cargo_build()
    return os.path.join(RECORDER_DIR, "target", "debug", EXE)


@pytest.fixture(scope="session")
def planted():
    """Build the recorder with one planted bug. Uses its own target directory, so the
    clean binary in target/debug is never replaced by a broken one."""
    target = os.path.join(RECORDER_DIR, "target", "planted")
    built = {}

    def build(feature):
        if feature not in built:
            cargo_build("--target-dir", target, "--features", feature)
            copy = os.path.join(target, feature + "-" + EXE)
            shutil.copy2(os.path.join(target, "debug", EXE), copy)
            built[feature] = copy
        return built[feature]

    return build
