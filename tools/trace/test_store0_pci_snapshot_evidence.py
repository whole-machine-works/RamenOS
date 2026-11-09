import json
import unittest

from store0_pci_snapshot_evidence import verify_pci_snapshot
from test_store0_modern_init_evidence import INIT, MARKER
from test_store0_oracle_evidence import NONCE, PREFIX, serial, trace

PCI_PREFIX = b"RAMEN_STORE0_PCI_V0 "
BEFORE = MARKER.replace(b"0x15", b"0x16")
AFTER = MARKER.replace(b"0x15", b"0x96")
CONFIG = bytes(range(256))


def observation():
    row = {
        "nonce": NONCE,
        "phase": "reopen",
        "bdf": "0000:00:03.0",
        "config_hex": CONFIG.hex(),
    }
    serial_lines = serial("reopen").splitlines(keepends=True)
    device_index = next(
        i for i, line in enumerate(serial_lines) if line.startswith(PREFIX)
    )
    serial_lines.insert(device_index + 1, PCI_PREFIX + json.dumps(row).encode() + b"\n")
    reads = b"".join(
        f"store0_pci_cfg_read pdev=0xabc1 bus=0 slot=3 func=0 offset={offset:#x} "
        f"size=4 value={int.from_bytes(CONFIG[offset : offset + 4], 'little'):#x}\n".encode()
        for offset in range(0, 256, 4)
    )
    traced = INIT + trace("reopen").replace(MARKER, BEFORE + reads + AFTER + MARKER)
    return b"".join(serial_lines), traced


class PciSnapshotTests(unittest.TestCase):
    def test_snapshot_is_bound_to_the_verified_pdev(self):
        actual_serial, actual_trace = observation()
        result = verify_pci_snapshot(actual_serial, actual_trace, NONCE)
        self.assertEqual(result["snapshot"]["bdf"], "0000:00:03.0")
        self.assertEqual(result["snapshot"]["config_hex"], CONFIG.hex())
        self.assertEqual(result["snapshot"]["config_reads"], 64)
        self.assertEqual(result["modern_init"]["read"]["vq"], "0xdef")

    def test_snapshot_refuses_corruption_then_fresh_success(self):
        actual_serial, actual_trace = observation()
        bracket_start = actual_trace.index(BEFORE)
        bracket_end = actual_trace.index(AFTER) + len(AFTER)
        early_snapshot = (
            actual_trace[bracket_start:bracket_end]
            + actual_trace[:bracket_start]
            + actual_trace[bracket_end:]
        )
        cases = (
            (actual_serial, early_snapshot),
            (actual_serial.replace(b"0000:00:03.0", b"0000:00:04.0"), actual_trace),
            (actual_serial.replace(CONFIG.hex().encode(), (b"00" * 256)), actual_trace),
            (actual_serial, actual_trace.replace(AFTER, b"", 1)),
            (
                actual_serial,
                actual_trace.replace(AFTER, AFTER.replace(b"0xddd", b"0xeee"), 1),
            ),
            (
                actual_serial,
                actual_trace.replace(b"offset=0xfc size=4", b"offset=0xf8 size=4", 1),
            ),
            (
                actual_serial,
                actual_trace.replace(
                    b"offset=0xfc size=4 value=0xfffefdfc",
                    b"offset=0xfc size=4 value=0x0",
                    1,
                ),
            ),
            (
                actual_serial,
                actual_trace.replace(
                    b"store0_pci_cfg_read pdev=0xabc1 bus=0 slot=3 func=0 offset=0xfc",
                    b"store0_pci_cfg_write pdev=0xabc1 bus=0 slot=3 func=0 offset=0xfc",
                    1,
                ),
            ),
        )
        for index, sample in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify_pci_snapshot(*sample, NONCE)
            self.assertEqual(
                verify_pci_snapshot(actual_serial, actual_trace, NONCE)["snapshot"][
                    "config_reads"
                ],
                64,
            )
