import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from store0_oracle_owner import (
    CaptureError,
    create_disk,
    open_disk,
    read_owned_stream,
    run_boot,
    verify_disk,
)


@unittest.skipUnless(sys.platform == "linux", "requires Linux held child wait")
class OwnerTests(unittest.TestCase):
    def test_same_disk_reopens_read_only_after_actual_child_write_and_reap(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as anchors:
            root = Path(temp)
            identity = anchors.enter_context(create_disk(root))
            with (
                open_disk(root, identity, writable=True) as disk,
                open_disk(root, identity, writable=False) as probe,
            ):
                verify_disk(disk, 0x55)
                script = (
                    "import fcntl,os,sys\n"
                    "disk,probe=map(int,sys.argv[1:])\n"
                    "assert fcntl.fcntl(disk,fcntl.F_GETFL)&os.O_ACCMODE == os.O_RDWR\n"
                    "assert fcntl.fcntl(probe,fcntl.F_GETFL)&os.O_ACCMODE == os.O_RDONLY\n"
                    "assert os.pread(probe,512,4096)==b'\\x55'*512\n"
                    "assert os.pwrite(disk,b'\\xa9'*512,4096)==512\n"
                    "print('written')\n"
                )
                run_boot(
                    [sys.executable, "-c", script, str(disk), str(probe)],
                    disk,
                    root,
                    "write",
                    probe_disk=probe,
                )
                verify_disk(disk, 0xA9)
            with open_disk(root, identity, writable=False) as disk:
                script = (
                    "import errno,fcntl,os,sys\n"
                    "fd=int(sys.argv[1])\n"
                    "assert fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE == os.O_RDONLY\n"
                    "try: os.pwrite(fd,b'x',4096)\n"
                    "except OSError as e: assert e.errno == errno.EBADF\n"
                    "else: raise AssertionError('reopen writable')\n"
                    "assert os.pread(fd,512,4096)==b'\\xa9'*512\n"
                )
                run_boot(
                    [sys.executable, "-c", script, str(disk)], disk, root, "reopen"
                )
                verify_disk(disk, 0xA9)
            for phase in ("write", "reopen"):
                record = json.loads((root / (phase + ".owner.json")).read_bytes())
                self.assertTrue(record["natural_exit"] and record["reaped"])
                self.assertEqual(record["exit_code"], 0)
            write = json.loads((root / "write.owner.json").read_bytes())
            stream = write["streams"]["serial"]
            self.assertEqual(
                read_owned_stream(root, "write", "serial", stream), b"written\n"
            )
            (root / "write.serial").write_bytes(b"changed\n")
            with self.assertRaisesRegex(CaptureError, "owned stream bytes differ"):
                read_owned_stream(root, "write", "serial", stream)

    def test_disk_replacement_is_refused(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as anchors:
            root = Path(temp)
            old = anchors.enter_context(create_disk(root))
            (root / "disk.raw").rename(root / "first.raw")
            new = anchors.enter_context(create_disk(root))
            with (
                self.assertRaisesRegex(CaptureError, "disk identity"),
                open_disk(root, old, writable=False),
            ):
                self.fail("replaced disk was opened")
            with open_disk(root, new, writable=False) as disk:
                verify_disk(disk, 0x55)
            with (
                open_disk(root, new, writable=True) as disk,
                self.assertRaisesRegex(CaptureError, "invalid read-only probe"),
            ):
                run_boot(
                    [sys.executable, "-c", "raise AssertionError('launched')"],
                    disk,
                    root,
                    "invalid",
                    probe_disk=disk,
                )
            self.assertFalse((root / "invalid.owner.json").exists())

    def test_excess_output_is_bounded_and_child_is_reaped(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as anchors:
            root = Path(temp)
            identity = anchors.enter_context(create_disk(root))
            with open_disk(root, identity, writable=False) as disk:
                script = "import os,time; os.write(2,b'x'*2048); time.sleep(30)"
                with self.assertRaisesRegex(CaptureError, "trace output exceeded"):
                    run_boot(
                        [sys.executable, "-c", script],
                        disk,
                        root,
                        "overflow",
                        trace_limit=17,
                    )
                self.assertEqual((root / "overflow.trace").read_bytes(), b"x" * 17)
                record = json.loads((root / "overflow.owner.json").read_bytes())
                self.assertTrue(record["reaped"])
                self.assertFalse(record["natural_exit"])
                run_boot([sys.executable, "-c", "pass"], disk, root, "fresh")
                verify_disk(disk, 0x55)


if __name__ == "__main__":
    unittest.main()
