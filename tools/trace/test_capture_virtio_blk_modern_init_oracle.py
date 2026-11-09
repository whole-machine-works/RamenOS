import fcntl
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import capture_virtio_blk_modern_init_oracle as capture


class ModernLauncherControls(unittest.TestCase):
    def test_read_only_launch_uses_seeded_inode_and_retains_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "fresh"
            plan = {
                "roms": {},
                "qemu": {"path": "/qemu"},
                "kernel": {"path": "/kernel"},
                "initrd": {"path": "/initrd"},
            }
            observed = []

            def refusal(argv, disk, output, phase, **kwargs):
                self.assertEqual(phase, "reopen")
                self.assertEqual(
                    fcntl.fcntl(disk, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY
                )
                self.assertNotIn("probe_disk", kwargs)
                self.assertEqual(argv.count("-add-fd"), 1)
                self.assertIn(f"fd={disk},set=1", argv)
                self.assertIn(
                    "readonly=on", next(a for a in argv if "file=/dev/fdset/1" in a)
                )
                observed.append(capture.verify_disk(disk, 0xA9))
                raise capture.CaptureError("fixture refusal")

            with (
                patch.object(capture.sys, "platform", "linux"),
                patch.object(capture, "snapshot", return_value={}),
                patch.object(capture, "run_boot", side_effect=refusal),
                self.assertRaisesRegex(capture.CaptureError, "fixture refusal"),
            ):
                capture.capture(plan, "a" * 64, root, {})
            receipt = json.loads((root / "capture.json").read_text())
            self.assertEqual(receipt["status"], "INCOMPLETE")
            self.assertEqual(receipt["error"], "fixture refusal")
            self.assertEqual(receipt["image_before"], observed[0])
            self.assertEqual(
                receipt["events"], list(capture.EVENTS + capture.MODERN_EVENTS)
            )

    def test_fresh_success_checks_both_images_and_delivers_raw_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "fresh"
            plan = {
                "roms": {},
                "qemu": {"path": "/qemu"},
                "kernel": {"path": "/kernel"},
                "initrd": {"path": "/initrd"},
            }
            owner = {"streams": {"serial": {}, "trace": {}}}
            with (
                patch.object(capture.sys, "platform", "linux"),
                patch.object(capture, "snapshot", return_value={}),
                patch.object(capture, "run_boot", return_value=owner) as launch,
                patch.object(
                    capture, "read_owned_stream", side_effect=[b"serial", b"trace"]
                ),
                patch.object(
                    capture, "verify_modern_init", return_value={"accepted": True}
                ) as verify,
            ):
                capture.capture(plan, "b" * 64, root, {})
            receipt = json.loads((root / "capture.json").read_text())
            self.assertEqual(receipt["status"], "PASS_RAW_READ_ONLY_TRACE")
            self.assertEqual(receipt["image_before"], receipt["image_after"])
            verify.assert_called_once_with(b"serial", b"trace", receipt["nonce"])
            self.assertEqual(launch.call_count, 1)

    def test_existing_output_refused_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "existing"
            root.mkdir(mode=0o700)
            (root / "sentinel").write_text("preserved")
            with (
                patch.object(capture.sys, "platform", "linux"),
                self.assertRaises(FileExistsError),
            ):
                capture.capture({}, "a" * 64, root, {})
            self.assertEqual((root / "sentinel").read_text(), "preserved")


if __name__ == "__main__":
    unittest.main()
