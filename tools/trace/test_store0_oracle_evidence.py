import json
import unittest

from store0_oracle_evidence import verify_boot

NONCE = "0123456789abcdef0123456789abcdef"
PREFIX = b"RAMEN_STORE0_ORACLE_V0 "


def serial(phase):
    rows = []

    def row(kind, **kw):
        rows.append(dict(seq=len(rows) + 1, nonce=NONCE, phase=phase, kind=kind, **kw))

    row("device", major=252, minor=0, sector_size=512, total_bytes=4194304)
    ops = (
        [
            ("pread_baseline", "55"),
            ("pwrite_new", "a9"),
            ("fsync", None),
            ("pread_after", "a9"),
        ]
        if phase == "write"
        else [("pread_reopen", "a9")]
    )
    for name, payload in ops:
        row(
            "before",
            operation=name,
            **({"payload_hex": payload * 512} if name == "pwrite_new" else {}),
        )
        row(
            "after",
            operation=name,
            **{"return": 0 if name == "fsync" else 512, "errno": 0},
            **({"payload_hex": payload * 512} if name.startswith("pread") else {}),
        )
    row("terminal", reason="ok", close_attempted=True, close_return=0, close_errno=0)
    row("completion", outcome="ok")
    return b"kernel boot\n" + b"".join(
        PREFIX + json.dumps(x, separators=(",", ":")).encode() + b"\n" for x in rows
    )


def trace(phase):
    features = "0x100000200" if phase == "write" else "0x100000220"
    rows = [
        "virtio_set_status vdev 0xabc val 15",
        f"store0_virtio_blk_driver_ready vdev 0xabc status 15 offered {features} accepted {features} writeback 1",
    ]

    def mark(x):
        rows.append(
            f"store0_debugcon_write debugcon 0xddd offset 0x0 width 1 value 0x{x:02x}"
        )

    def used(req, head, old):
        rows.append(
            f"store0_used_element vdev=0xabc vq=0xdef elem={req} queue=0 id={head} slot={old} old={old} result=0 direct=1 matches=1"
        )
        rows.append(
            f"store0_used_index vdev=0xabc vq=0xdef queue=0 old={old} new={old + 1} direct=1 matches=1"
        )

    def rw(kind, req, head, old):
        rows.extend(
            [
                f"virtio_blk_handle_{kind} vdev 0xabc req {req} sector 8 nsectors 1",
                f"virtio_blk_rw_complete vdev 0xabc req {req} ret 0",
                f"virtio_blk_req_complete vdev 0xabc req {req} status 0",
            ]
        )
        used(req, head, old)

    if phase == "write":
        mark(0x11)
        rw("read", "0x100", 0, 0)
        mark(0x91)
        mark(0x12)
        rw("write", "0x110", 1, 1)
        mark(0x92)
        mark(0x13)
        rows.extend(
            [
                "store0_virtio_blk_flush_submit vdev 0xabc req 0x120 queue 0 descriptor 2",
                "store0_virtio_blk_flush_return vdev 0xabc req 0x120 queue 0 descriptor 2 ret 0",
                "virtio_blk_req_complete vdev 0xabc req 0x120 status 0",
            ]
        )
        used("0x120", 2, 2)
        mark(0x93)
        mark(0x14)
        rw("read", "0x130", 3, 3)
        mark(0x94)
    else:
        mark(0x15)
        rw("read", "0x100", 0, 0)
        mark(0x95)
    rows.append("qemu_system_shutdown_request reason=6")
    return ("\n".join(rows) + "\n").encode()


class VerifyBoot(unittest.TestCase):
    def test_positive_write_and_reopen(self):
        for phase in ("write", "reopen"):
            self.assertIsInstance(
                verify_boot(serial(phase), trace(phase), phase, NONCE), dict
            )

    def test_rejects_corruption_then_fresh_success(self):
        good = trace("write")
        changes = [
            (b"accepted 0x100000200", b"accepted 0x0"),
            (b"writeback 1", b"writeback 0"),
            (b"value 0x13", b"value 0x12"),
            (
                b"debugcon 0xddd offset 0x0 width 1 value 0x93",
                b"debugcon 0xeee offset 0x0 width 1 value 0x93",
            ),
            (
                b"flush_return vdev 0xabc req 0x120 queue 0 descriptor 2 ret 0",
                b"flush_return vdev 0xabc req 0x120 queue 0 descriptor 2 ret -5",
            ),
            (b"elem=0x120 queue=0 id=2", b"elem=0x121 queue=0 id=2"),
            (b"elem=0x120 queue=0 id=2 slot=2", b"elem=0x120 queue=0 id=2 slot=0"),
            (b"queue=0 old=2 new=3", b"queue=0 old=2 new=4"),
            (
                b"elem=0x120 queue=0 id=2 slot=2 old=2 result=0 direct=1",
                b"elem=0x120 queue=0 id=2 slot=2 old=2 result=0 direct=0",
            ),
            (
                b"virtio_blk_handle_write vdev 0xabc req 0x110 sector 8",
                b"virtio_blk_handle_write vdev 0xabc req 0x110 sector 9",
            ),
        ]
        for old, new in changes:
            with self.subTest(old=old):
                self.assertIn(old, good)
                with self.assertRaises(ValueError):
                    verify_boot(
                        serial("write"), good.replace(old, new, 1), "write", NONCE
                    )
                verify_boot(serial("write"), good, "write", NONCE)

    def test_late_flush_reset_duplicate_gap_and_bad_serial(self):
        good = trace("write")
        cases = [
            good.replace(
                b"value 0x13",
                b"value 0x13\nstore0_used_gap vdev=0xabc vq=0xdef queue=0 reason=1",
            ),
            good.replace(
                b"value 0x93",
                b"value 0x93\nstore0_virtio_blk_flush_submit vdev 0xabc req 0x120 queue 0 descriptor 2",
            ),
            good.replace(
                b"value 0x93", b"value 0x93\nvirtio_set_status vdev 0xabc val 0"
            ),
            good.replace(
                b"value 0x93",
                b"value 0x93\nstore0_debugcon_write debugcon 0xddd offset 0x0 width 1 value 0x93",
            ),
            trace("reopen")
            + b"virtio_blk_handle_write vdev 0xabc req 0x222 sector 8 nsectors 1\n",
        ]
        for bad in cases:
            phase = "reopen" if bad.startswith(trace("reopen")) else "write"
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                verify_boot(serial(phase), bad, phase, NONCE)
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write").replace(b'"errno":0', b'"errno":5', 1),
                good,
                "write",
                NONCE,
            )
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write").replace(b"55" * 512, b"54" * 512, 1),
                good,
                "write",
                NONCE,
            )
        with self.assertRaises(ValueError):
            verify_boot(serial("write"), good, "write", "wrong")

    def test_discovery_read_is_real_complete_and_read_only(self):
        read = b"\n".join(trace("reopen").splitlines()[3:8])
        base = trace("write")
        for old in range(3, -1, -1):
            base = base.replace(
                f"slot={old} old={old}".encode(),
                f"slot={old + 1} old={old + 1}".encode(),
            )
            base = base.replace(
                f"old={old} new={old + 1}".encode(),
                f"old={old + 1} new={old + 2}".encode(),
            )
        good = base.replace(
            b"store0_debugcon_write debugcon 0xddd offset 0x0 width 1 value 0x11",
            read
            + b"\nstore0_debugcon_write debugcon 0xddd offset 0x0 width 1 value 0x11",
            1,
        )
        verify_boot(serial("write"), good, "write", NONCE)
        bad = good.replace(
            b"virtio_blk_handle_read vdev 0xabc req 0x100 sector 8 nsectors 1\n", b"", 1
        )
        with self.assertRaises(ValueError):
            verify_boot(serial("write"), bad, "write", NONCE)
        premature = read + b"\n" + good.replace(read + b"\n", b"", 1)
        with self.assertRaises(ValueError):
            verify_boot(serial("write"), premature, "write", NONCE)
        verify_boot(serial("write"), good, "write", NONCE)

    def test_receiver_rejects_duplicate_json_invalid_types_and_unknown_trace(self):
        good = trace("write")
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write").replace(b'"seq":1,', b'"seq":1,"seq":1,', 1),
                good,
                "write",
                NONCE,
            )
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write").replace(b'"seq":1,', b'"seq":true,', 1),
                good,
                "write",
                NONCE,
            )
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write"), good + b"unknown_event hidden\n", "write", NONCE
            )
        with self.assertRaises(ValueError):
            verify_boot(serial("write"), good[:-1], "write", NONCE)
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write"),
                good.replace(b"status 15 offered", b"status 143 offered", 1),
                "write",
                NONCE,
            )
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write"), good.replace(b"reason=6", b"reason=1"), "write", NONCE
            )
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write"),
                good.replace(b"qemu_system_shutdown_request reason=6\n", b""),
                "write",
                NONCE,
            )
        with self.assertRaises(ValueError):
            verify_boot(
                serial("write"),
                good + b"qemu_system_shutdown_request reason=6\n",
                "write",
                NONCE,
            )

    def test_receipt_pair_not_interleaved_or_orphaned(self):
        good = trace("write")
        cases = [
            good.replace(
                b"virtio_blk_rw_complete vdev 0xabc req 0x110 ret 0",
                b"virtio_blk_rw_complete vdev 0xabc req 0x110 ret -5",
            ),
            good.replace(
                b"virtio_blk_req_complete vdev 0xabc req 0x120 status 0",
                b"virtio_blk_req_complete vdev 0xabc req 0x120 status 1",
            ),
            good.replace(b"queue 0 descriptor 2 ret 0", b"queue 0 descriptor 3 ret 0"),
            good.replace(
                b"vq=0xdef queue=0 old=2 new=3", b"vq=0xdee queue=0 old=2 new=3"
            ),
            good.replace(
                b"queue=0 old=2 new=3 direct=1 matches=1",
                b"queue=0 old=2 new=3 direct=1 matches=0",
            ),
            good.replace(
                b"virtio_blk_req_complete vdev 0xabc req 0x120 status 0\n", b""
            ),
            good.replace(
                b"virtio_blk_req_complete vdev 0xabc req 0x120 status 0\n",
                b"virtio_blk_req_complete vdev 0xabc req 0x120 status 0\nvirtio_blk_req_complete vdev 0xabc req 0x120 status 0\n",
            ),
        ]
        for bad in cases:
            with self.subTest(bad=bad[-90:]), self.assertRaises(ValueError):
                verify_boot(serial("write"), bad, "write", NONCE)

    def test_modern_features_readonly_and_queue_bounds(self):
        write = trace("write")
        for bad in (
            write.replace(b"0x100000200", b"0x200", 1),
            write.replace(b"0x100000200", b"0x500000200", 1),
            write.replace(b"0x100000200", b"0x100000220", 1),
            write.replace(b"status 15 offered", b"status 7 offered", 1),
            write.replace(b"id=0 slot=0 old=0", b"id=128 slot=0 old=0", 1),
            write.replace(b"id=0 slot=0 old=0", b"id=0 slot=1 old=1", 1),
        ):
            with self.subTest(bad=bad[:150]), self.assertRaises(ValueError):
                verify_boot(serial("write"), bad, "write", NONCE)
        reopen = trace("reopen")
        with self.assertRaises(ValueError):
            verify_boot(
                serial("reopen"),
                reopen.replace(b"0x100000220", b"0x100000200", 1),
                "reopen",
                NONCE,
            )
        # A read-only boot does not need a FLUSH feature or writeback cache.
        verify_boot(
            serial("reopen"),
            reopen.replace(b"0x100000220", b"0x100000020").replace(
                b"writeback 1", b"writeback 0"
            ),
            "reopen",
            NONCE,
        )

    def test_accepted_features_must_be_offered_and_ready_not_lost(self):
        good = trace("write")
        cases = (
            good.replace(b"accepted 0x100000200", b"accepted 0x100000600"),
            good.replace(b"offered 0x100000200", b"offered 0x10000000000000200"),
            good.replace(
                b"value 0x91\n",
                b"value 0x91\nvirtio_set_status vdev 0xabc val 15\n",
            ),
        )
        for bad in cases:
            with self.subTest(bad=bad[:180]), self.assertRaises(ValueError):
                verify_boot(serial("write"), bad, "write", NONCE)
            verify_boot(serial("write"), good, "write", NONCE)

    def test_pre_io_setup_reset_and_terminal_repeat_are_bounded(self):
        good = trace("write")
        preliminary = (
            b"virtio_set_status vdev 0xabc val 15\n"
            b"store0_virtio_blk_driver_ready vdev 0xabc status 15 offered 0x100000200 accepted 0x100000000 writeback 0\n"
            b"virtio_set_status vdev 0xabc val 0\n"
        )
        terminal = b"\n".join(good.splitlines()[:2]) + b"\n"
        candidate = preliminary + good + terminal
        verify_boot(serial("write"), candidate, "write", NONCE)
        bad_cases = (
            candidate.replace(
                b"offered 0x100000200 accepted 0x100000000 writeback 0",
                b"offered 0x100000000 accepted 0x100000000 writeback 0",
                1,
            ),
            candidate.replace(b"virtio_set_status vdev 0xabc val 0\n", b"", 1),
            candidate.replace(
                b"virtio_set_status vdev 0xabc val 0\n",
                b"virtio_blk_handle_read vdev 0xabc req 0x100 sector 8 nsectors 1\nvirtio_set_status vdev 0xabc val 0\n",
                1,
            ),
            candidate.replace(
                b"virtio_set_status vdev 0xabc val 0\n",
                b"store0_debugcon_write debugcon 0xddd offset 0x0 width 1 value 0x11\nvirtio_set_status vdev 0xabc val 0\n",
                1,
            ),
            candidate.replace(b"writeback 0", b"writeback 1", 1),
            candidate.replace(
                b"qemu_system_shutdown_request reason=6\n" + terminal,
                b"qemu_system_shutdown_request reason=6\n" + terminal + terminal,
                1,
            ),
            candidate[:-2] + b"0\n",
            candidate + b"virtio_set_status vdev 0xabc val 0\n",
            candidate.replace(
                b"value 0x91\n", b"value 0x91\nvirtio_set_status vdev 0xabc val 0\n", 1
            ),
        )
        for bad in bad_cases:
            with self.subTest(bad=bad[:180]), self.assertRaises(ValueError):
                verify_boot(serial("write"), bad, "write", NONCE)
            verify_boot(serial("write"), candidate, "write", NONCE)
