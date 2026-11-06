"""Fail-closed inventory checks for actual Linux prerequisite witnesses."""
import copy
import unittest

import editor_process_linux_prerequisites as gate
from editor_process_preparation import PreparationError


class LinuxPrerequisiteInventory(unittest.TestCase):
    def summary(self):
        return {"status": "PASS", "package": "artifact_editor", "targets": [{
            "name": "process_linux_prerequisites", "kind": "test", "selected": sorted(gate.CASES),
            "passed": sorted(gate.CASES),
        }], "commands": [{"exit_code": 0, "reaped": True, "group_stop_before_reap": True}]}

    def test_exact_inventory(self):
        gate.validate(self.summary())

    def test_zero_partial_duplicate_and_foreign_cases_fail(self):
        for field in ("selected", "passed"):
            for values in ([], sorted(gate.CASES)[:-1], sorted(gate.CASES) * 2, sorted(gate.CASES) + ["foreign"]):
                summary = self.summary()
                summary["targets"][0][field] = values
                with self.subTest(field=field, values=values), self.assertRaises(PreparationError):
                    gate.validate(summary)

    def test_failed_or_unreaped_process_fails(self):
        for key, value in (("exit_code", 101), ("reaped", False), ("group_stop_before_reap", False), ("error", "lost")):
            summary = self.summary()
            summary["commands"][0][key] = value
            with self.subTest(key=key), self.assertRaises(PreparationError):
                gate.validate(summary)

    def test_wrong_harness_or_missing_commands_fails(self):
        for key, value in (("targets", []), ("commands", []), ("package", "foreign"), ("status", "INCOMPLETE")):
            summary = copy.deepcopy(self.summary())
            summary[key] = value
            with self.subTest(key=key), self.assertRaises(PreparationError):
                gate.validate(summary)

    def test_hosted_native_execution_and_evidence_are_registered(self):
        workflow = (gate.ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("-- just foundry-editor-process-linux-prerequisites-ui1-1d", workflow)
        self.assertIn("path: out/editor-process-linux-prerequisites/", workflow)
        self.assertIn("name: editor-process-linux-prerequisites-${{ github.run_id }}-${{ github.run_attempt }}", workflow)
        tooling = (gate.ROOT / "tools/ci/foundry_ci_optimization.sh").read_text()
        self.assertIn("python3 tools/ci/test_editor_process_linux_prerequisites.py", tooling)


if __name__ == "__main__":
    unittest.main()
