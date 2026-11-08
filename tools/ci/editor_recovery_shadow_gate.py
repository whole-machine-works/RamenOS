#!/usr/bin/env python3
"""I1 real-owner and fault controls; separate from canonical editor acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import sys

import cargo_artifact
import editor_process_preparation as preparation
import selected_test_runner as runner

ROOT = preparation.ROOT
FIXTURE = "services/store_service/tests/fixtures/recovery-c1.wasm"
C1_SHA = "6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079"
STORE_CASE = "real_commit_pending_then_terminal_replay_refused_and_fresh_owner_remains_usable"
PROCESS_CASE = "genuine_lost_reply_terminal_and_fresh_save"
STORE_FAULT_CASES = [
    "actual_terminal_snapshot_barrier_checks_query_and_unrelated_progress",
    "actual_expired_query_rejects_native_publication_after_c1_then_fresh_query_succeeds",
    "actual_token_drop_aborts_before_c1_then_fresh_query_succeeds",
    "actual_watchdog_aborts_before_c1_then_fresh_query_succeeds",
    "actual_revocation_keeps_original_scope_and_never_grants_saved",
    "actual_reopened_store_compares_original_epoch_and_fresh_save",
]
PROCESS_FAULT_CASES = [
    "actual_child_death_after_permit_keeps_original_then_c1_recovery_and_fresh_save",
    "actual_child_death_before_permit_has_no_effect_or_shadow_then_fresh_save",
]
IDENTITY_CASES = ["editor_dev::native_authority::native_shadow_identity_tests::" + name for name in (
    "shadow_identity_exact_call_rejects_second_same_actor_query_and_recovers",
    "shadow_identity_foreign_witness_and_entry_authority_are_denied",
    "shadow_identity_missing_and_reserved_join_are_none_without_consumption",
    "shadow_identity_actual_returned_join_is_read_only_and_matches_proof",
    "shadow_identity_actual_panicked_join_is_not_promoted_to_returned",
    "shadow_identity_foreign_authority_origin_kind_and_proof_are_denied",
    "shadow_identity_generation_and_memo_identity_corruption_are_denied",
    "shadow_identity_retired_origin_and_non_save_origin_never_imply_join",
)]
EXTRAS = {"tools/ci/editor_recovery_shadow_gate.py",
          "tools/ci/test_editor_recovery_shadow_gate.py", "tools/ci/cargo_artifact.py",
          "tools/ci/stage_timer.py", ".github/workflows/ci.yml"}


def validate_fixture(raw):
    preparation.require(len(raw) == 1349 and hashlib.sha256(raw).hexdigest() == C1_SHA,
                        "reviewed C1 fixture identity differs")


def select_child(build_json, package, target):
    child = Path(cargo_artifact.select_executable(build_json, "editor-process"))
    preparation.require(child.resolve().is_relative_to(target.resolve()), "child outside I1 target")
    messages = runner.json_rows(build_json.read_text())
    selected = [row for row in messages if row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == "editor-process"
                and row.get("target", {}).get("kind") == ["bin"]]
    sources = [row["src_path"] for row in package["targets"]
               if row.get("name") == "editor-process" and row.get("kind") == ["bin"]]
    preparation.require(len(selected) == 1 and len(sources) == 1
                        and selected[0].get("package_id") == package["id"]
                        and selected[0].get("target", {}).get("src_path") == sources[0]
                        and selected[0].get("features") == ["host_editor_process_child_v0_dev"],
                        "I1 child package, source or feature scope differs")
    return child


def validate_summary(summary, package, target, required):
    preparation.require(summary.get("status") == "PASS" and summary.get("package") == package,
                        "unsuccessful I1 selection")
    preparation.require(summary.get("filters") == [], "I1 suite must be unfiltered")
    targets = summary.get("targets")
    preparation.require(isinstance(targets, list) and len(targets) == 1,
                        "one explicit I1 integration harness required")
    row = targets[0]
    discovered = row.get("discovered")
    required_cases = [required] if isinstance(required, str) else required
    preparation.require(row.get("name") == target and row.get("kind") == "test"
                        and isinstance(discovered, dict) and bool(required_cases)
                        and all(case in discovered for case in required_cases)
                        and all(value is False for value in discovered.values())
                        and row.get("selected") == sorted(discovered)
                        and row.get("passed") == sorted(discovered),
                        "missing, ignored or unexecuted I1 owner control")
    commands = summary.get("commands")
    preparation.require(isinstance(commands, list) and bool(commands), "missing I1 command ownership")
    for command in commands:
        preparation.require(command.get("exit_code") == 0 and command.get("reaped") is True
                            and command.get("group_stop_before_reap") is True and "error" not in command,
                            "uncertain I1 command completion")


def snapshot():
    rows = {row["path"]: row for row in preparation.snapshot(ROOT)}
    for name in sorted(EXTRAS):
        raw = (ROOT / name).read_bytes()
        rows[name] = {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return [rows[name] for name in sorted(rows)]


def execute(requested):
    parent = ROOT / "out/editor-recovery-shadow-i1"
    if requested is None:
        parent.mkdir(parents=True, exist_ok=True)
        requested = parent / ("run." + secrets.token_hex(8))
    output = preparation.fresh_output(requested)
    result = {"schema_version": 1, "status": "INCOMPLETE", "scope": "i1-first-and-owner-fault-controls",
              "full_i1": False, "process_pending": False, "update_rollback": False,
              "benefit": False, "activation": False, "commands": []}
    previous = os.environ.copy()
    previous_umask = os.umask(0o077)
    result["private_umask"] = "077"
    try:
        preparation.require(platform.system() == "Linux", "actual Linux process controls required")
        fixture = ROOT / FIXTURE
        raw = fixture.read_bytes()
        validate_fixture(raw)
        # Never overwrite the canonical gate's archived parent library or children.
        target = (ROOT / "target/i1-recovery-shadow").resolve()
        os.environ.update(CARGO_TARGET_DIR=str(target), RUST_TEST_THREADS="1")
        before = snapshot()
        preparation.write_json(output / "source-before.json", before)
        result["source_manifest_sha256"] = hashlib.sha256((output / "source-before.json").read_bytes()).hexdigest()

        def command(label, argv):
            row = runner.run_owned(argv, output, label, work_seconds=600)
            result["commands"].append(row)
            preparation.require(row["exit_code"] == 0 and row["reaped"] is True
                                and row["group_stop_before_reap"] is True,
                                "failed or uncertain " + label)

        command("gate-controls", [sys.executable, "-B", "-m", "unittest", "discover",
                                  "-s", "tools/ci", "-p", "test_editor_recovery_shadow_gate.py"])
        command("child-metadata", ["cargo", "metadata", "--locked", "--no-deps", "--format-version=1"])
        packages = [row for row in json.loads((output / "child-metadata.stdout").read_text())["packages"]
                    if row.get("name") == "artifact_editor"
                    and Path(row.get("manifest_path", "")).resolve() == ROOT / "apps/artifact_editor/Cargo.toml"]
        preparation.require(len(packages) == 1, "actual editor Cargo package required")
        command("child-build", ["cargo", "build", "--locked", "-p", "artifact_editor",
                                "--no-default-features", "--features", "host_editor_process_child_v0_dev",
                                "--bin", "editor-process", "--message-format=json"])
        child = select_child(output / "child-build.stdout", packages[0], target)
        child_identity = runner.input_identity(child)
        result["child"] = child_identity
        retained = {}
        (output / "binaries").mkdir(mode=0o700)

        def retain(label, identity):
            source = Path(identity["path"])
            preparation.require(runner.input_identity(source) == identity, "I1 binary changed before retention")
            destination = output / "binaries" / label
            shutil.copyfile(source, destination)
            copied = runner.input_identity(destination)
            preparation.require(copied["sha256"] == identity["sha256"]
                                and copied["bytes"] == identity["bytes"], "I1 binary retention differs")
            preparation.require(runner.input_identity(source) == identity, "I1 binary changed during retention")
            retained[label] = {"source": identity, "retained": copied}
            result["retained_binaries"] = retained

        retain("editor-process", child_identity)
        # Desktop captures these with option_env!: supply BEFORE parent compilation.
        os.environ["RAMEN_EDITOR_PROCESS_ARTIFACT_PATH"] = str(child)
        os.environ["RAMEN_EDITOR_PROCESS_ARTIFACT_SHA256"] = child_identity["sha256"]
        (output / "recordings").mkdir(mode=0o700)
        os.environ["RAMEN_NATIVE_TASK_EVIDENCE"] = str(output / "recordings")
        os.environ["RAMEN_NATIVE_TASK_RUN_NONCE"] = secrets.token_hex(16)

        def unit_group(label, package, case_filter, expected, exact=False,
                       features="editor_recovery_shadow_v0_dev"):
            command(label, ["cargo", "test", "--locked", "-p", package, "--lib",
                            "--features", features, case_filter,
                            "--", *(["--exact"] if exact else []),
                            "--format=json", "-Z", "unstable-options"])
            text = (output / (label + ".stdout")).read_text()
            end = runner.json_rows(text)[-1]
            runner.validate_outcomes(text, sorted(expected), 0, end["filtered_out"])

        unit_group("join-identity", "desktop_service", "shadow_identity_", IDENTITY_CASES)
        bounded = "editor_store::native_save::shadow_record_tests::shadow_bounded_error_preserves_failure_and_utf8_prefix"
        unit_group("bounded-errors", "store_service", bounded, [bounded], exact=True)
        watchdog_prefix = "editor_store::native_save::shadow_pause_boundary_tests::"
        watchdogs = [watchdog_prefix + name for name in (
            "late_release_refuses_at_internal_deadline", "release_requires_entered_and_is_one_use")]
        unit_group("snapshot-watchdog", "store_service", watchdog_prefix, watchdogs,
                   features="editor_recovery_shadow_assertions_v0_dev")
        for label, package, test, features, required in [
            ("store", "store_service", "editor_recovery_shadow", "editor_recovery_shadow_v0_dev", STORE_CASE),
            ("process", "artifact_editor", "recovery_shadow",
             "host_editor_recovery_shadow_v0_dev,host_editor_process_assertions_v0_dev", PROCESS_CASE),
            ("store-faults", "store_service", "editor_recovery_shadow_faults",
             "editor_recovery_shadow_assertions_v0_dev", STORE_FAULT_CASES),
            ("process-faults", "artifact_editor", "recovery_shadow_owner_faults",
             "host_editor_recovery_shadow_v0_dev,host_editor_process_assertions_v0_dev", PROCESS_FAULT_CASES),
        ]:
            command(label, [sys.executable, str(ROOT / "tools/ci/selected_test_runner.py"),
                            "--package", package, "--test", test, "--features", features,
                            "--required-input", str(fixture), "--required-input", str(child),
                            "--output", str(output / label)])
            summary = json.loads((output / label / "summary.json").read_text())
            validate_summary(summary, package, test, required)
            retain(label, summary["targets"][0]["binary_identity"])
            command(label + "-clippy", ["cargo", "clippy", "--locked", "-p", package,
                                        "--test", test, "--features", features, "--", "-D", "warnings"])
        preparation.require(runner.input_identity(child) == child_identity, "I1 child changed")
        after = snapshot()
        preparation.write_json(output / "source-after.json", after)
        preparation.require(before == after, "I1 source changed during assertions")
        result["status"] = "PASS_FIRST_AND_OWNER_FAULT_CONTROLS"
        return 0
    except (preparation.PreparationError, runner.RunnerError, OSError, ValueError, KeyError) as error:
        result["error"] = str(error)
        if platform.system() == "Linux":
            result["status"] = "FAIL"
        return 2 if result["status"] == "INCOMPLETE" else 1
    finally:
        os.umask(previous_umask)
        os.environ.clear()
        os.environ.update(previous)
        preparation.write_json(output / "result.json", result)
        print(f"EDITOR_RECOVERY_SHADOW_I1: {result['status']} full_i1=false output={output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="fresh exclusive evidence directory")
    args = parser.parse_args()
    os.chdir(ROOT)
    return execute(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
