import unittest
from pathlib import Path
import subprocess
import sys
import tempfile

import editor_process_source_policy as policy


class SelectedSourcePolicy(unittest.TestCase):
    def test_actual_parent_edit_and_raster_calls_rejected(self):
        self.assertEqual(policy.check(b"fn bad(){ h.step_native_editor(&editor,1); }"),
                         "PROCESS_SOURCE_FORBIDDEN_PARENT_EDIT")
        self.assertEqual(policy.check(b"fn bad(){ h.render_native_editor(&editor,1); }"),
                         "PROCESS_SOURCE_FORBIDDEN_PARENT_RASTER")
        self.assertEqual(policy.check(b"fn bad(){ model.rasterize_bgra(font,pixels); }"),
                         "PROCESS_SOURCE_FORBIDDEN_PARENT_RASTER")

    def test_comments_and_strings_do_not_claim_executable_calls(self):
        source = b'''// h.step_native_editor(&x,1);
        /* nested /* render_native_editor(x) */ comment */
        fn good(){ let s="render_native_editor(x)"; let r=r##"apply_key(x)"##; }
        '''
        self.assertIsNone(policy.check(source))

    def test_cli_retains_exact_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "mutant.rs"
            source.write_bytes(b"fn bad(){ h.step_native_editor(&editor,1); }")
            result = subprocess.run([sys.executable, policy.__file__, "--source", str(source)],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, b"PROCESS_SOURCE_FORBIDDEN_PARENT_EDIT\n")
            self.assertEqual(result.stdout, b"")

    def test_quote_character_cannot_hide_actual_call(self):
        source = b"fn bad(){ let q='\"'; h.step_native_editor(&editor,1); let z='\"'; }"
        self.assertEqual(policy.check(source), "PROCESS_SOURCE_FORBIDDEN_PARENT_EDIT")
        self.assertIsNone(policy.check(b"fn good<'a>(){ let q='\"'; let c='x'; }"))

    def test_invalid_source_not_accepted_as_policy_refusal(self):
        for source in (b"", b"/* unterminated", b'fn x(){ let a="unterminated; }'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                policy.check(source)


if __name__ == "__main__":
    unittest.main()
