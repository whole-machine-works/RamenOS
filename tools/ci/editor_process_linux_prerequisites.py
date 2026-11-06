#!/usr/bin/env python3
"""Execute Linux kernel prerequisite witnesses, separately from process acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import sys

import editor_process_preparation as preparation
import selected_test_runner as runner

ROOT = preparation.ROOT
CASES = {
    "process_linux_prerequisite_write_seal_rejects_writable_and_mprotected_aliases",
    "process_linux_prerequisite_future_write_does_not_freeze_existing_alias",
    "process_linux_prerequisite_all_write_aliases_close_before_complete_immutable_pair",
    "process_linux_prerequisite_ancillary_truncation_owns_only_received_aliases",
    "process_linux_prerequisite_kernel_rejects_unprivileged_forged_credentials",
    "process_linux_prerequisite_inherited_endpoint_reports_actual_helper_pid",
}
EXTRAS = {
    "tools/ci/editor_process_linux_prerequisites.py",
    "tools/ci/test_editor_process_linux_prerequisites.py",
}


def snapshot():
    rows = {row["path"]: row for row in preparation.snapshot(ROOT)}
    for name in sorted(EXTRAS):
        raw = (ROOT / name).read_bytes()
        rows[name] = {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return [rows[name] for name in sorted(rows)]


def validate(summary):
    preparation.require(summary.get("status") == "PASS" and summary.get("package") == "artifact_editor",
                        "Linux prerequisite selection failed")
    targets = summary.get("targets")
    preparation.require(isinstance(targets, list) and len(targets) == 1, "exactly one Linux harness required")
    target = targets[0]
    preparation.require(target.get("name") == "process_linux_prerequisites" and target.get("kind") == "test"
                        and target.get("selected") == sorted(CASES) and target.get("passed") == sorted(CASES),
                        "exact native prerequisite inventory must execute")
    commands = summary.get("commands")
    preparation.require(isinstance(commands, list) and bool(commands), "missing command ownership")
    for command in commands:
        preparation.require(command.get("exit_code") == 0 and command.get("reaped") is True
                            and command.get("group_stop_before_reap") is True and "error" not in command,
                            "failed or uncertain native command")


def execute(requested):
    if requested is None:
        parent = ROOT / "out/editor-process-linux-prerequisites"
        parent.mkdir(parents=True, exist_ok=True)
        requested = parent / ("run." + secrets.token_hex(8))
    output = preparation.fresh_output(requested)
    result = {"schema_version": 1, "status": "INCOMPLETE", "scope": "linux-kernel-prerequisites-only",
              "runtime": False, "all30_complete": False, "system": platform.system(),
              "test_threads": 1,
              "commands": [], "passed": []}
    previous_threads = os.environ.get("RUST_TEST_THREADS")
    try:
        preparation.require(platform.system() == "Linux", "requires actual Linux kernel; no substitute execution")
        # Tests probe descriptor closure by numeric ID; prevent peer harness tests
        # from allocating that ID between close and the EBADF observation.
        os.environ["RUST_TEST_THREADS"] = "1"
        before = snapshot()
        preparation.write_json(output / "source-before.json", before)
        result["source_manifest_sha256"] = hashlib.sha256((output / "source-before.json").read_bytes()).hexdigest()
        for label, argv in [
            ("kernel", ["uname", "-a"]),
            ("toolchain", ["rustc", "--version", "--verbose"]),
            ("native-selection", [sys.executable, str(ROOT / "tools/ci/selected_test_runner.py"),
                                  "--package", "artifact_editor", "--test", "process_linux_prerequisites",
                                  "--features", "host_editor_process_setup_v0_dev",
                                  "--filter", "process_linux_prerequisite_", "--output", str(output / "native")]),
            ("native-clippy", ["cargo", "clippy", "--locked", "-p", "artifact_editor", "--test",
                               "process_linux_prerequisites", "--features", "host_editor_process_setup_v0_dev",
                               "--", "-D", "warnings"]),
        ]:
            command = runner.run_owned(argv, output, label, work_seconds=600)
            result["commands"].append(command)
            preparation.require(command["exit_code"] == 0 and command["reaped"] is True
                                and command["group_stop_before_reap"] is True,
                                "failed or uncertain " + label)
        validate(json.loads((output / "native/summary.json").read_text()))
        after = snapshot()
        preparation.write_json(output / "source-after.json", after)
        preparation.require(before == after, "source changed during native prerequisites")
        result.update(status="PASS_PREREQUISITES_ONLY", passed=sorted(CASES))
        return 0
    except (preparation.PreparationError, runner.RunnerError, OSError, ValueError) as error:
        result["error"] = str(error)
        if platform.system() == "Linux":
            result["status"] = "FAIL"
        return 2 if result["status"] == "INCOMPLETE" else 1
    finally:
        if previous_threads is None:
            os.environ.pop("RUST_TEST_THREADS", None)
        else:
            os.environ["RUST_TEST_THREADS"] = previous_threads
        preparation.write_json(output / "result.json", result)
        print(f"EDITOR_PROCESS_LINUX_PREREQUISITES: {result['status']} runtime=false all30_complete=false output={output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="fresh exclusive output directory")
    args = parser.parse_args()
    # Cargo configuration is resolved from the repository, never the caller's cwd.
    os.chdir(ROOT)
    return execute(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
