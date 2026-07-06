"""Reproduce the eight-scenario evaluation: run every reference capture through the detector and
check the (rate, ratio, pattern) verdict it produces against that scenario's known label, plus
the combined ``alarm`` -- the Decision neuron's flat 2-of-3 majority vote, expected to fire when
at least two of the three features agree.

This is the one-command version of the evaluation described in the README:

    python verify.py

It needs no engine running beforehand. ``verify.py`` starts its **own** private copy of the SN P
engine, on a free port, using the **same Python interpreter** that runs this script, and shuts it
down on exit. That is deliberate: an earlier version trusted whatever already answered on the usual
port, so a stale server left over from a previous session would silently serve old code and report
the wrong results. Self-hosting guarantees the verification always runs against the current code,
and never collides with a server you already have running.

For each scenario in ``traffic_generation/scenarios.json`` it finds the matching capture in
``traffic_generation/experiments/``, runs it through the full pipeline, and compares the detector's
verdict against the scenario's expected label. It prints a per-scenario table and exits non-zero if
any scenario is wrong, so it doubles as a smoke test. All intermediate output is written to a
temporary directory that is removed on exit.
"""

import contextlib
import glob
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
# verify.py sits alongside the modules it drives; make them importable from any directory.
sys.path.insert(0, HERE)
from simulator import Config, SNPSimulator  # noqa: E402

EXPERIMENTS = os.path.join(HERE, "traffic_generation", "experiments")
SCENARIOS = os.path.join(HERE, "traffic_generation", "scenarios.json")
INPUT_SOURCES = 3  # the reference captures each contain three attacker devices

# A scenario's `expected` list names the features that should fire; this maps each name to its
# slot in the (rate, ratio, pattern) verdict triple.
FEATURE_SLOT = {"syn_packet_rate": 0, "syn_ack_ratio": 1, "anomalous_syn_pattern": 2}


def free_port() -> int:
    """Ask the OS for an unused localhost port, then release it for the engine to rebind.

    There is a tiny race between releasing the port here and the engine binding it, but on a
    developer machine it is negligible -- and far safer than a fixed port that a leftover server
    might already hold.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def engine(port: int):
    """Start a private SN P engine on ``port`` with this interpreter; yield its URL; tear it down.

    Using ``sys.executable -m uvicorn`` (rather than relying on a server already running) is what
    guarantees the detector logic under test is the current code, not whatever stale process might
    be answering on the usual port.

    The engine's stdout/stderr are drained to a temporary file, not a pipe: the engine logs on every
    request, and an unread ``PIPE`` would fill its OS buffer and deadlock the server mid-run. The
    file still lets us show the engine's output if it fails to start.
    """
    base = f"http://127.0.0.1:{port}"
    log = tempfile.TemporaryFile()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "snp_engine.main:app",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=HERE,
        stdout=log,
        stderr=subprocess.STDOUT,
    )

    def engine_output() -> str:
        try:
            log.seek(0)
            return log.read().decode(errors="replace")
        except Exception:
            return ""

    try:
        for _ in range(120):  # wait up to ~60s for readiness
            if proc.poll() is not None:  # exited before becoming ready -> surface why
                raise RuntimeError(
                    f"the engine exited before it was ready (code {proc.returncode}):\n{engine_output()}"
                )
            try:
                requests.get(base, timeout=1)
                break
            except requests.exceptions.RequestException:
                time.sleep(0.5)
        else:
            raise RuntimeError(
                f"the engine did not become ready at {base} within 60s:\n{engine_output()}"
            )
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def expected_label(expected_features: list[str]) -> tuple[bool, bool, bool]:
    """Convert a scenario's list of expected feature names into a (rate, ratio, pattern) triple."""
    verdict = [False, False, False]
    for feature in expected_features:
        verdict[FEATURE_SLOT[feature]] = True
    return tuple(verdict)


def find_capture(scenario: str) -> str | None:
    """Return the capture CSV for a scenario (the most recent, if several exist), or None."""
    matches = sorted(glob.glob(os.path.join(EXPERIMENTS, f"{scenario}_*.csv")))
    return matches[-1] if matches else None


def run_scenario(
    name: str, capture: str, expected: tuple[bool, bool, bool], out_dir: str, api: str
) -> tuple[tuple[bool, bool, bool], bool]:
    """Run one capture through the detector; return its (rate, ratio, pattern) triple and alarm."""
    config = Config(
        system_json="per-source",  # ignored at runtime; the system is built by per_source_builder
        api=api,  # the private engine this run owns
        file_path=capture,
        input_sources=INPUT_SOURCES,
        export_dir_path=os.path.join(out_dir, name),
        expected_rate=expected[0],
        expected_ratio=expected[1],
        expected_pattern=expected[2],
    )
    with contextlib.redirect_stdout(io.StringIO()):  # mute the pipeline's own logging
        SNPSimulator(config).start()
    with open(os.path.join(out_dir, name, "output-decision_history.json")) as f:
        result = json.load(f)["result"]
    return (result["rate"], result["ratio"], result["pattern"]), result["alarm"]


def label(triple: tuple[bool, bool, bool]) -> str:
    """Render a (rate, ratio, pattern) triple as a three-character T/F string."""
    return "".join("T" if fired else "F" for fired in triple)


def main() -> int:
    with open(SCENARIOS) as f:
        scenarios = json.load(f)

    out_dir = tempfile.mkdtemp(prefix="snp_verify_")
    passed = total = 0
    try:
        with engine(free_port()) as api:
            print(
                f"{'scenario':<16}{'feat-exp':<10}{'feat-got':<10}{'alm-exp':<9}{'alm-got':<9}result"
            )
            print("-" * 62)
            for name, spec in scenarios.items():
                capture = find_capture(name)
                if capture is None:
                    print(
                        f"{name:<16}{'n/a':<10}{'n/a':<10}{'n/a':<9}{'n/a':<9}SKIP (no capture found)"
                    )
                    continue
                total += 1
                expected = expected_label(spec.get("expected", []))
                exp_alarm = (
                    sum(expected) >= 2
                )  # flat 2-of-3 majority: at least two features agree
                got, got_alarm = run_scenario(name, capture, expected, out_dir, api)
                ok = got == expected and got_alarm == exp_alarm
                passed += ok
                ae, ag = ("T" if exp_alarm else "F"), ("T" if got_alarm else "F")
                print(
                    f"{name:<16}{label(expected):<10}{label(got):<10}{ae:<9}{ag:<9}{'PASS' if ok else 'FAIL'}"
                )
    except RuntimeError as exc:
        print(f"ERROR: could not start the SN P engine.\n{exc}")
        return 1
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)

    print("-" * 62)
    print(f"{passed}/{total} scenarios correct")
    return 0 if total and passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
