#!/usr/bin/env python3
"""Source-bound complete P0 authoring/actual API RED, never process runtime PASS."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import sys

import editor_process_preparation as preparation
import selected_test_runner as runner

ROOT = preparation.ROOT
CATALOG = "apps/artifact_editor/tests/process_support/p0_obligations.json"
HANDOFF = "docs/contracts/editor-process-assertion-handoff-v0.json"
BODY = "apps/artifact_editor/tests/process_support/full_assertions.rs"
PROFILE_SOURCES = {
    "desktop-private": ("services/desktop/src/editor_dev/process_editor/assertions.rs",),
    "app-private": ("apps/artifact_editor/src/native/process_assertions.rs",
                    "services/desktop/src/editor_dev/process_editor/assertions.rs",
                    "apps/artifact_editor/tests/process_support/fixture.rs",
                    "apps/artifact_editor/tests/process_support/gate_record.rs"),
    "public": ("apps/artifact_editor/tests/process_task.rs", BODY,
               "apps/artifact_editor/tests/process_support/child_owner.rs",
               "apps/artifact_editor/tests/process_support/app_owner.rs",
               "apps/artifact_editor/tests/process_support/child_group.rs",
               "apps/artifact_editor/tests/process_support/obligations.rs",
               "apps/artifact_editor/tests/process_support/gate_record.rs",
               "services/desktop/src/editor_dev/process_editor/assertions.rs"),
}


def require(value, reason):
    if not value:
        raise preparation.PreparationError(reason)


def inventory(repo):
    catalog_raw = (repo / CATALOG).read_bytes()
    catalog = json.loads(catalog_raw)
    handoff = json.loads((repo / HANDOFF).read_bytes())
    require(handoff["status"] == "FROZEN_FOR_P0_ASSERTION_AUTHORING_ONLY", "unreviewed handoff")
    require(handoff["expanded_catalog_sha256"] == hashlib.sha256(catalog_raw).hexdigest(), "catalog freeze mismatch")
    raw = (repo / handoff["handoff_path"]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == handoff["handoff_sha256"], "handoff bytes changed without reviewed refresh")
    require(handoff["contract_sha256"] == hashlib.sha256((repo / handoff["contract_path"]).read_bytes()).hexdigest(),
            "production contract changed")
    families = catalog["families"]
    require([family["id"] for family in families] == [f"D{i:02}" for i in range(1, 31)], "exact thirty families required")
    expected = {family["consumer_entry"] for family in families}
    source = (repo / BODY).read_text()
    tests = set(re.findall(r"#\[test\]\s*fn\s+(\w+)\s*\(", source))
    require(expected <= tests, "missing named executable family bodies: " + ",".join(sorted(expected - tests)))
    require(all((repo / name).is_file() for files in PROFILE_SOURCES.values() for name in files), "missing private/public source")
    return {"families": sorted(expected), "all_public_tests": sorted(tests),
            "negative_scenarios": catalog["negative_scenario_count"],
            "positive_scenarios": catalog["positive_scenario_count"]}


def planned_symbols(repo):
    text = "\n".join((repo / name).read_text() for name in (
        "docs/DESKTOP_EDITOR_PROCESS_API_V0.md", "docs/DESKTOP_EDITOR_PROCESS_ASSERTIONS_V0.md"))
    types = set(re.findall(r"pub (?:struct|enum) (\w+)", text))
    types.update({"SaveChains", "ProcessAssertionSnapshot", "ProcessAssertionOwners",
                  "ProcessAssertionSyscall", "ProcessAssertionDescriptor", "ProcessAssertionControl",
                  "ProcessAssertionOperation", "ProcessAssertionOrigin", "ProcessAssertionDescriptorRole",
                  "ProcessAssertionMapping", "ProcessAssertionDisposition", "ProcessAssertionDirection",
                  "ProcessAssertionExecutable", "ProcessAssertionExecutableAction", "ProcessAssertionObject",
                  "ProcessAssertionDescriptorEvent"})
    methods = set(re.findall(r"\b(?:pub )?fn\s+(\w+)", text))
    return types, methods


def classify(stdout, exit_code, repo, profile):
    require(exit_code == 101, "must observe actual Cargo compiler exit101")
    types, methods = planned_symbols(repo)
    errors, cascades, notes, finished = [], [], [], False
    for row in runner.json_rows(stdout):
        require(not finished, "Cargo output after build-finished")
        if row.get("reason") == "build-finished":
            require(row.get("success") is False, "compiled code is not missing-API RED")
            finished = True
            continue
        if row.get("reason") != "compiler-message":
            require(row.get("reason") in {"compiler-artifact", "build-script-executed"}, "unexpected Cargo row")
            continue
        message = row.get("message", {})
        if message.get("level") == "failure-note":
            note = message.get("message")
            require(message.get("code") is None and message.get("spans") == []
                    and isinstance(note, str) and len(note) <= 1024 and note not in notes,
                    "invalid compiler failure note")
            notes.append(note)
            continue
        if message.get("level") != "error":
            require(message.get("level") in {"warning", "note", "help"}, "unknown compiler diagnostic level")
            continue
        code = (message.get("code") or {}).get("code")
        text = message.get("message", "")
        primary = [span for span in message.get("spans", []) if span.get("is_primary")]
        require(primary, "unlocated compiler error")
        names = []
        for span in primary:
            path = Path(span["file_name"])
            require(not path.is_absolute() or path.is_relative_to(repo), "compiler source outside repository")
            name = path.relative_to(repo).as_posix() if path.is_absolute() else path.as_posix()
            name = os.path.normpath(name)
            require(name in PROFILE_SOURCES[profile], "unrelated compiler source: " + name)
            names.append(name)
        record = {"code": code, "message": text, "sources": sorted(set(names))}
        if code == "E0282":
            require(re.fullmatch(r"type annotations needed(?: for `[^`\n]{1,1024}`)?", text) is not None,
                    "unexpected inference diagnostic")
            cascades.append(record)
            continue
        require(code in {"E0432", "E0433", "E0412", "E0425", "E0599"}, "unrelated compiler failure: " + str(code))
        modules = {"desktop", "native", "artifact_editor", "editor_dev", "super",
                   "crate::editor_dev", "desktop_service::editor_dev", "crate::native"}
        if code == "E0432":
            require(text.startswith(("unresolved import ", "unresolved imports ")), "unexpected import diagnostic")
            imports = re.findall(r"`([^`]+)`", text)
            providers = {"desktop_service::editor_dev", "crate::editor_dev", "artifact_editor", "crate::native", "super"}
            require(bool(imports) and all("::" in name and name.rsplit("::", 1)[0] in providers
                                        and name.rsplit("::", 1)[1] in types for name in imports),
                    "unrelated missing import provider or type")
        elif code == "E0433":
            match = re.fullmatch(r"failed to resolve: could not find `([^`]+)` in `([^`]+)`", text)
            undeclared = re.fullmatch(r"failed to resolve: use of undeclared type `([^`]+)`", text)
            require((match is not None and match[1] in types and match[2] in modules)
                    or (undeclared is not None and undeclared[1] in types), "unrelated resolution diagnostic")
        elif code == "E0412":
            match = re.fullmatch(r"cannot find type `([^`]+)` in this scope", text)
            require(match is not None and match[1] in types, "unrelated scope type diagnostic")
        elif code == "E0425":
            match = re.fullmatch(r"cannot find type `([^`]+)` in module `([^`]+)`", text)
            scope = re.fullmatch(r"cannot find type `([^`]+)` in this scope", text)
            exported = re.fullmatch(r"cannot find type `([^`]+)` in crate `artifact_editor`", text)
            require((exported is not None and exported[1] in {"ProcessArtifactEditor", "ProcessEditorOpenFailure", "ProcessOpenCleanup"})
                    or (match is not None and match[1] in types and match[2] in modules)
                    or (scope is not None and scope[1] in types),
                    "unrelated module type diagnostic")
        if code == "E0599":
            match = re.search(r"no (?:method|(?:function or )?associated item) named `([^`]+)`", text)
            require(match is not None and match[1] in methods, "unknown missing method")
            receiver = re.search(r"found for (?:struct|enum) `([^`]+)`", text)
            require(receiver is not None, "missing method receiver identity")
            receiver = receiver[1].removeprefix("std::sync::")
            if receiver.startswith("Arc<") and receiver.endswith(">"):
                receiver = receiver[4:-1]
            parts = receiver.split("::")
            require(parts[-1] in types | {"HostDesktop", "FixtureController"}
                    and all(part in {"desktop_service", "artifact_editor", "editor_dev", "host", "native",
                                     "process_editor", "assertion_control", "assertion_contract"} for part in parts[:-1]),
                    "missing method on unrelated receiver")
        errors.append(record)
    codes = {row["code"] for row in errors + cascades}
    kinds = set()
    for note in notes:
        summary = re.fullmatch(r"Some errors have detailed explanations: (E\d{4}(?:, E\d{4})*)\.", note)
        explain = re.fullmatch(r"For more information about an error, try `rustc --explain (E\d{4})`\.", note)
        if summary is not None:
            require(summary[1].split(", ") == sorted(codes), "inconsistent compiler summary")
            kind = "summary"
        elif explain is not None:
            require(explain[1] in codes, "unobserved compiler explain code")
            kind = "explain"
        else:
            raise preparation.PreparationError("unrecognized compiler failure note")
        require(kind not in kinds, "duplicate compiler failure note kind")
        kinds.add(kind)
    require(finished and bool(errors), "no completed missing-API compiler evidence")
    return {"status": "EXPECTED_MISSING_API_RED", "exit_code": exit_code,
            "missing_api_errors": errors, "inference_cascades_unproved": cascades, "failure_notes": notes,
            "runtime_executed": False}


def snapshot():
    rows = {row["path"]: row for row in preparation.snapshot(ROOT)}
    for name in (CATALOG, HANDOFF, "docs/DESKTOP_EDITOR_PROCESS_ASSERTIONS_V0.md",
                 "docs/contracts/editor-process-gate-record-v0.json",
                 "tools/ci/editor_process_p0.py", "tools/ci/test_editor_process_p0.py", "tools/ci/editor_process_recording.py",
                 "tools/ci/test_editor_process_recording.py", "tools/ci/editor_process_source_policy.py",
                 "tools/ci/test_editor_process_source_policy.py"):
        raw = (ROOT / name).read_bytes()
        rows[name] = {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return [rows[name] for name in sorted(rows)]


def execute(output, diagnostic=False):
    result = {"schema_version": 1, "status": "INCOMPLETE", "runtime": False,
              "all30_runtime_complete": False, "handlers_released": False, "commands": []}
    try:
        require(platform.system() == "Linux", "actual Linux compilation required")
        result["status"] = "FAIL"
        result["inventory"] = {"status": "IN_PROGRESS_NOT_ACCEPTED"} if diagnostic else inventory(ROOT)
        before = snapshot()
        preparation.write_json(output / "source-before.json", before)
        for profile, package, target in (("desktop-private", "desktop_service", ["--lib"]),
                                         ("app-private", "artifact_editor", ["--lib"]),
                                         ("public", "artifact_editor", ["--test", "process_task"])):
            command = runner.run_owned(["cargo", "test", "--locked", "-p", package, *target,
                                        "--features", "host_editor_process_assertions_v0_dev", "--no-run",
                                        "--message-format=json"], output, profile, work_seconds=600)
            result["commands"].append(command)
            require(command["reaped"] and command["group_stop_before_reap"], "uncertain compiler cleanup")
            result[profile] = classify((output / (profile + ".stdout")).read_text(), command["exit_code"], ROOT, profile)
        after = snapshot()
        preparation.write_json(output / "source-after.json", after)
        require(before == after, "source changed during P0 preparation")
        result["status"] = "DIAGNOSTIC_EXPECTED_API_RED" if diagnostic else "EXPECTED_API_RED_COMPLETE_SOURCE_INVENTORY"
        return 0
    except (preparation.PreparationError, runner.RunnerError, OSError, ValueError) as error:
        result["error"] = str(error)
        return 2 if result["status"] == "INCOMPLETE" else 1
    finally:
        preparation.write_json(output / "result.json", result)
        print(f"EDITOR_PROCESS_P0: {result['status']} runtime=false output={output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--diagnostic-only", action="store_true", help="authoring snapshot only; never accepts P0 inventory")
    args = parser.parse_args()
    os.chdir(ROOT)
    output = args.output or ROOT / "out/editor-process-p0" / ("run." + secrets.token_hex(8))
    return execute(preparation.fresh_output(output), args.diagnostic_only)


if __name__ == "__main__":
    raise SystemExit(main())
