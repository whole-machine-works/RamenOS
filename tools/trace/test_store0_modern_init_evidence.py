import unittest

from store0_modern_init_evidence import verify_modern_init
from test_store0_oracle_evidence import NONCE, serial, trace

INIT = (
    b"store0_pci_cfg_read pdev=0xabc1 bus=0 slot=3 func=0 offset=0x0 size=4 value=0x10421af4\n"
    b"store0_virtio_pci_common_read pdev=0xabc1 vdev=0xabc offset=0x0 size=4 value=0x1 selected=0\n"
    b"store0_virtio_pci_common_write pdev=0xabc1 vdev=0xabc offset=0x1c size=2 value=0x1 selected=0\n"
    b"store0_virtio_pci_queue_ready pdev=0xabc1 vdev=0xabc vq=0xdef queue=0 size=128 "
    b"desc=0x2000 avail=0x3000 used=0x4000 enabled=1 status=11\n"
)
MARKER = b"store0_debugcon_write debugcon 0xddd offset 0x0 width 1 value 0x15\n"


class ModernInitTests(unittest.TestCase):
    def test_queue_and_pci_device_are_joined_to_the_verified_read(self):
        combined = trace("reopen").replace(MARKER, INIT + MARKER, 1)
        result = verify_modern_init(serial("reopen"), combined, NONCE)
        self.assertEqual(result["bdf"], [0, 3, 0])
        self.assertEqual(result["queue"]["descriptor"], 0x2000)
        self.assertEqual(result["read"]["vq"], "0xdef")

    def test_missing_or_mismatched_setup_cannot_use_a_successful_read(self):
        good = trace("reopen").replace(MARKER, INIT + MARKER, 1)
        cases = [
            trace("reopen"),
            good.replace(b"vq=0xdef queue=0 size=128", b"vq=0xfee queue=0 size=128", 1),
            good.replace(b"size=128", b"size=127", 1),
            good.replace(b"func=0 offset=0x0 size=4", b"func=0 offset=0x0 size=0", 1),
            good.replace(
                b"store0_virtio_pci_common_write pdev=0xabc1",
                b"store0_virtio_pci_common_write pdev=0xbcd1",
                1,
            ),
            good.replace(INIT + MARKER, MARKER + INIT, 1),
        ]
        for bad in cases:
            with self.subTest(trace=bad[:160]), self.assertRaises(ValueError):
                verify_modern_init(serial("reopen"), bad, NONCE)
            self.assertEqual(
                verify_modern_init(serial("reopen"), good, NONCE)["queue"]["index"], 0
            )

    def test_conflicting_modern_records_inside_the_read_are_refused(self):
        good = trace("reopen").replace(MARKER, INIT + MARKER, 1)
        cases = [
            INIT.splitlines(keepends=True)[-1].replace(b"vq=0xdef", b"vq=0xfee"),
            INIT.splitlines(keepends=True)[1].replace(b"pdev=0xabc1", b"pdev=0xbcd1"),
            INIT.splitlines(keepends=True)[1].replace(b"vdev=0xabc", b"vdev=0xbcd"),
            INIT.splitlines(keepends=True)[0].replace(b"slot=3", b"slot=5"),
        ]
        for extra in cases:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                verify_modern_init(
                    serial("reopen"), good.replace(MARKER, MARKER + extra), NONCE
                )
            self.assertEqual(
                verify_modern_init(serial("reopen"), good, NONCE)["read"]["vq"], "0xdef"
            )
