import copy
import json
from pathlib import Path
import tempfile
import unittest

import editor_recovery_shadow_gate as gate


class GateControls(unittest.TestCase):
    def test_fixed_fixture_identity_before_build(self):
        raw = (gate.ROOT / gate.FIXTURE).read_bytes()
        gate.validate_fixture(raw)
        for bad in (b"", raw[:-1], raw[:-1] + bytes([raw[-1] ^ 1])):
            with self.assertRaises(gate.preparation.PreparationError):
                gate.validate_fixture(bad)

    def test_foreign_child_package_features_source_or_target_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            child = target / "editor-process"
            child.write_bytes(b"not executed by this parser control")
            child.chmod(0o700)
            source = str(gate.ROOT / "apps/artifact_editor/src/bin/editor-process.rs")
            package = {"id": "actual-editor-package", "targets": [
                {"name": "editor-process", "kind": ["bin"], "src_path": source}]}
            artifact = {"reason": "compiler-artifact", "package_id": package["id"],
                        "target": package["targets"][0], "profile": {"test": False},
                        "features": ["host_editor_process_child_v0_dev"], "executable": str(child)}
            build_json = target / "build.json"
            def write(row):
                build_json.write_text(json.dumps(row) + "\n" + json.dumps({
                    "reason": "build-finished", "success": True}) + "\n")
            write(artifact)
            self.assertEqual(gate.select_child(build_json, package, target), child)
            for key, bad in (("package_id", "foreign"), ("features", ["host_editor_recovery_shadow_v0_dev"]),
                             ("target", {"name": "editor-process", "kind": ["bin"], "src_path": source + ".other"})):
                row = copy.deepcopy(artifact)
                row[key] = bad
                write(row)
                with self.assertRaises(gate.preparation.PreparationError):
                    gate.select_child(build_json, package, target)
            write(artifact)
            with self.assertRaises(gate.preparation.PreparationError):
                gate.select_child(build_json, package, target / "different-target")

    def setUp(self):
        self.value = {"status": "PASS", "package": "artifact_editor", "filters": [],
                      "targets": [{"name": "recovery_shadow", "kind": "test",
                                   "discovered": {gate.PROCESS_CASE: False},
                                   "selected": [gate.PROCESS_CASE], "passed": [gate.PROCESS_CASE]}],
                      "commands": [{"exit_code": 0, "reaped": True, "group_stop_before_reap": True}]}

    def check(self, value):
        gate.validate_summary(value, "artifact_editor", "recovery_shadow", gate.PROCESS_CASE)

    def test_actual_success_inventory_required(self):
        self.check(self.value)
        for field, bad in [("status", "FAIL"), ("filters", ["subset"]), ("commands", [])]:
            value = copy.deepcopy(self.value)
            value[field] = bad
            with self.assertRaises(gate.preparation.PreparationError):
                self.check(value)

    def test_missing_ignored_and_unexecuted_case_refuse(self):
        for field, bad in [("discovered", {}), ("discovered", {gate.PROCESS_CASE: True}),
                           ("selected", []), ("passed", [])]:
            value = copy.deepcopy(self.value)
            value["targets"][0][field] = bad
            with self.assertRaises(gate.preparation.PreparationError):
                self.check(value)

    def test_each_required_owner_case_must_be_discovered_and_executed(self):
        cases = ["first_actual_owner", "second_actual_owner"]
        value = copy.deepcopy(self.value)
        row = value["targets"][0]
        row.update(discovered={case: False for case in cases}, selected=list(cases), passed=list(cases))
        gate.validate_summary(value, "artifact_editor", "recovery_shadow", cases)
        for missing in cases:
            denied = copy.deepcopy(value)
            row = denied["targets"][0]
            row["discovered"].pop(missing)
            row["selected"].remove(missing)
            row["passed"].remove(missing)
            with self.assertRaises(gate.preparation.PreparationError):
                gate.validate_summary(denied, "artifact_editor", "recovery_shadow", cases)

    def test_uncertain_or_failed_owned_command_refuses(self):
        for field, bad in [("exit_code", 101), ("reaped", False),
                           ("group_stop_before_reap", False), ("error", "timeout")]:
            value = copy.deepcopy(self.value)
            value["commands"][0][field] = bad
            with self.assertRaises(gate.preparation.PreparationError):
                self.check(value)


if __name__ == "__main__":
    unittest.main()
