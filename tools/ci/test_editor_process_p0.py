"""P0 compiler admission fails closed on unrelated errors and incomplete output."""
import json
import unittest

import editor_process_p0 as gate
from editor_process_preparation import PreparationError


def message(code, text, source=gate.PROFILE_SOURCES["desktop-private"][0]):
    return {"reason": "compiler-message", "message": {"level": "error", "code": {"code": code},
            "message": text, "spans": [{"file_name": source, "is_primary": True}]}}


def output(*messages):
    return "\n".join(json.dumps(row) for row in (*messages, {"reason": "build-finished", "success": False}))


class P0CompilerAdmission(unittest.TestCase):
    def classify(self, *messages, code=101):
        return gate.classify(output(*messages), code, gate.ROOT, "desktop-private")

    def test_explicit_missing_type_is_red_only(self):
        result = self.classify(message("E0432", "unresolved import `crate::editor_dev::ProcessAssertionEvidence`"))
        self.assertEqual(result["status"], "EXPECTED_MISSING_API_RED")
        self.assertFalse(result["runtime_executed"])

    def test_exact_owner_module_type_path_admitted(self):
        result = self.classify(message("E0425", "cannot find type `ProcessAssertionSyscall` in module `crate::editor_dev`"))
        self.assertFalse(result["runtime_executed"])

    def test_exact_app_crate_export_is_red(self):
        self.classify(message("E0425", "cannot find type `ProcessArtifactEditor` in crate `artifact_editor`"))
        for text in ("cannot find type `ProcessArtifactEditor` in crate `foreign`",
                     "cannot find type `Accidental` in crate `artifact_editor`"):
            with self.subTest(text=text), self.assertRaises(PreparationError):
                self.classify(message("E0425", text))

    def test_unrelated_type_in_mixed_import_is_rejected(self):
        with self.assertRaises(PreparationError):
            self.classify(message("E0432", "unresolved imports `crate::editor_dev::ProcessAssertionEvidence`, `other::Accidental`"))

    def test_right_type_from_wrong_provider_and_method_used_as_type_rejected(self):
        for code, text in (("E0432", "unresolved import `foreign::ProcessAssertionEvidence`"),
                           ("E0412", "cannot find type `open_assertion` in this scope")):
            with self.subTest(code=code), self.assertRaises(PreparationError):
                self.classify(message(code, text))

    def test_unrelated_code_source_and_success_exit_rejected(self):
        for row, code in ((message("E0308", "mismatched types"), 101),
                          (message("E0432", "unresolved import `crate::editor_dev::ProcessAssertionEvidence`", "other.rs"), 101),
                          (message("E0432", "unresolved import `crate::editor_dev::ProcessAssertionEvidence`"), 0)):
            with self.subTest(row=row, code=code), self.assertRaises(PreparationError):
                self.classify(row, code=code)

    def test_known_method_on_foreign_receiver_is_rejected(self):
        text = "no method named `prepare_process_editor` found for struct `foreign::HostDesktop` in the current scope"
        with self.assertRaises(PreparationError):
            self.classify(message("E0599", text))

    def test_inference_gap_is_retained_not_accepted_alone(self):
        gap = message("E0282", "type annotations needed")
        with self.assertRaises(PreparationError):
            self.classify(gap)
        result = self.classify(message("E0432", "unresolved import `crate::editor_dev::ProcessAssertionEvidence`"), gap)
        self.assertEqual(len(result["inference_cascades_unproved"]), 1)

    def test_unknown_failure_note_or_inference_shape_rejected(self):
        valid = message("E0432", "unresolved import `crate::editor_dev::ProcessAssertionEvidence`")
        note = {"reason": "compiler-message", "message": {"level": "failure-note", "code": None,
                "message": "could not execute compiler", "spans": []}}
        with self.assertRaises(PreparationError):
            self.classify(valid, note)
        with self.assertRaises(PreparationError):
            self.classify(valid, message("E0282", "unrelated inference text"))


if __name__ == "__main__":
    unittest.main()
