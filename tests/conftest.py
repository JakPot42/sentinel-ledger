"""Shared setup: build the recorder once, and make the demo driver and the verifier importable."""
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORDER_DIR = os.path.join(REPO, "recorder")
NODE_DIR = os.path.join(REPO, "ros2", "sentinel_recorder_node")
EXE = "sentinel-recorder.exe" if os.name == "nt" else "sentinel-recorder"
sys.path.insert(0, os.path.join(REPO, "demo"))
sys.path.insert(0, os.path.join(REPO, "verifier"))
sys.path.insert(0, os.path.join(REPO, "gate"))
sys.path.insert(0, os.path.join(REPO, "ros2"))


def target_dir(crate_dir, suffix=""):
    """Where cargo puts its output. CARGO_TARGET_DIR is honoured so that a checkout shared
    between Windows and Linux (WSL) does not mix two platforms' builds in one folder."""
    base = os.environ.get("CARGO_TARGET_DIR")
    if base:
        return os.path.join(base, os.path.basename(crate_dir) + suffix)
    return os.path.join(crate_dir, "target" + suffix)


def cargo_build(crate_dir, target, *extra):
    done = subprocess.run(["cargo", "build", "--quiet", "--target-dir", target, *extra], cwd=crate_dir,
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def builder(crate_dir, binary):
    """Returns build(feature=None): the path of the binary, built clean or with one planted
    bug. Planted builds go to their own target directory and are copied aside, so the clean
    binary is never replaced by a broken one."""
    built = {}

    def build(feature=None):
        if feature not in built:
            if feature is None:
                target = target_dir(crate_dir)
                cargo_build(crate_dir, target)
                built[feature] = os.path.join(target, "debug", binary)
            else:
                target = target_dir(crate_dir, "-planted")
                cargo_build(crate_dir, target, "--features", feature)
                copy = os.path.join(target, feature + "-" + binary)
                shutil.copy2(os.path.join(target, "debug", binary), copy)
                built[feature] = copy
        return built[feature]

    return build


@pytest.fixture(scope="session")
def _recorder_builds():
    return builder(RECORDER_DIR, EXE)


@pytest.fixture(scope="session")
def recorder(_recorder_builds):
    """The recorder as shipped: no planted bug."""
    return _recorder_builds()


@pytest.fixture(scope="session")
def planted(_recorder_builds):
    """planted(feature): the recorder built with one planted bug."""
    return _recorder_builds


@pytest.fixture(scope="session")
def ros_node():
    """ros_node(feature=None): the ROS 2 recorder node, clean or with one planted bug."""
    return builder(NODE_DIR, "sentinel_recorder_node")
