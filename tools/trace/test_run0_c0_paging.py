"""Gate-first controls for the C0 paging transition and its retained consumer."""

from dataclasses import FrozenInstanceError
import struct
import unittest

import run0_c0_decode as decode

try:
    import run0_c0_paging as paging
except ModuleNotFoundError as error:
    if error.name != "run0_c0_paging":
        raise
    paging = None


def frame(index, value):
    data = bytearray(4096)
    struct.pack_into("<Q", data, 8 * index, value)
    return bytes(data)


class PagingControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(paging, "missing pure paging transition")

    def reject(self, status, reason, operation, *args):
        with self.assertRaises(decode.C0DecodeError) as raised:
            operation(*args)
        self.assertEqual((raised.exception.status, raised.exception.reason), (status, reason))

    def test_page01_requires_exact_canonical_constructor_inputs(self):
        for args, reason in (
            ((True, 0, 40, True), "integer_range"),
            ((1 << 47, 0, 40, True), "span_noncanonical"),
            ((0, True, 40, True), "integer_range"),
            ((0, 4095, 40, True), "frame_alignment"),
            ((0, 1 << 40, 40, True), "integer_range"),
            ((0, 0, True, True), "integer_range"),
            ((0, 0, 31, True), "integer_range"),
            ((0, 0, 53, True), "integer_range"),
            ((0, 0, 40, 1), "nxe_type"),
        ):
            with self.subTest(args=args):
                self.reject("DENY", reason, paging.PageWalk, *args)
        walk = paging.PageWalk((1 << 64) - 1, 0, 52, True)
        self.assertEqual(walk.next_frame, paging.NeedFrame(0, 4, 511))

    def test_page02_exact_four_kib_path_and_permissions(self):
        virtual = (1 << 39) | (2 << 30) | (3 << 21) | (4 << 12) | 0x123
        walk = paging.PageWalk(virtual, 0x1000, 40, True)
        self.assertEqual(walk.next_frame, paging.NeedFrame(0x1000, 4, 1))
        entries = (0x2007, 0x3005, (1 << 63) | 0x4003, 0x8007)
        for level, (index, entry) in enumerate(zip(range(1, 5), entries), start=1):
            step = walk.accept(frame(index, entry))
            if level < 4:
                self.assertEqual(step, paging.NeedFrame((level + 1) * 4096, 4 - level, index + 1))
                self.assertIs(step, walk.next_frame)
        self.assertEqual(step, paging.PageTranslation(
            0x8123, 4096, 0x123, tuple(
                paging.PageEntry(index * 4096, index, entry)
                for index, entry in zip(range(1, 5), entries)), False, False, False))
        self.assertIsNone(walk.next_frame)
        self.reject("DENY", "walk_complete", walk.accept, frame(4, 0x8007))

    def test_page03_two_mib_leaf_stops_before_level_one(self):
        walk = paging.PageWalk(0x1fffff, 0x1000, 40, True)
        walk.accept(frame(0, 0x2007))
        walk.accept(frame(0, 0x3007))
        step = walk.accept(frame(0, 0x201087))
        self.assertEqual((step.physical, step.page_bytes, step.page_offset),
                         (0x3fffff, 0x200000, 0x1fffff))
        self.assertEqual(len(step.path), 3)
        self.assertIsNone(walk.next_frame)
        with self.assertRaises(FrozenInstanceError):
            step.path[0].frame = 0

    def test_page04_rejects_unchecked_frame_types_before_callbacks(self):
        class HookedBytes(bytes):
            def __len__(self):
                raise AssertionError("foreign __len__ executed")

        walk = paging.PageWalk(0, 0x1000, 40, True)
        original = walk.next_frame
        with self.assertRaises(FrozenInstanceError):
            original.physical = 0
        for data in (bytearray(4096), memoryview(bytes(4096)), HookedBytes(4096), object()):
            self.reject("DENY", "frame_type", walk.accept, data)
        for length in (0, 4095, 4097):
            self.reject("INCOMPLETE", "frame_length", walk.accept, bytes(length))
        self.assertIs(walk.next_frame, original)
        self.assertEqual(walk.accept(frame(0, 0x2007)), paging.NeedFrame(0x2000, 3, 0))

    def test_page05_invalid_parent_has_no_new_child_demand(self):
        walk = paging.PageWalk(0, 0x1000, 40, False)
        original = walk.next_frame
        for entry, status, reason in (
            ((1 << 64) - 2, "INCOMPLETE", "unmapped"),
            (0x2087, "DENY", "entry_reserved"),
            ((1 << 40) | 0x2007, "DENY", "entry_reserved"),
            ((1 << 63) | 0x2007, "DENY", "entry_reserved"),
        ):
            self.reject(status, reason, walk.accept, frame(0, entry))
            self.assertIs(walk.next_frame, original)
        child = walk.accept(frame(0, 0x2007))
        self.reject("INCOMPLETE", "one_gib_unsupported", walk.accept, frame(0, 0x87))
        self.assertIs(walk.next_frame, child)
        walk.accept(frame(0, 0x3007))
        self.reject("DENY", "entry_reserved", walk.accept, frame(0, 0x202087))

    def test_page06_retained_consumer_checks_ram_and_level_before_lookup(self):
        sources = {
            0x1000: frame(0, 0x2007),
            0x2000: frame(0, 0x3007),
            0x3000: frame(0, 0x4007),
            0x4000: frame(0, 0x8007),
        }
        state = dict(phys_bits=40, cr0=0x80010001, cr3=0x1000, cr4=0x20,
                     efer=0xd00, cpl=0, cs64=True, a20=1, no_npt=True,
                     no_svm_guest=True, no_smm=True)

        class RecordingWalker(decode._Walker):
            def __init__(self, frames, ranges):
                self.reads = []
                super().__init__(state, frames, ranges)

            def _raw_frame(self, address, level):
                self.reads.append((address, level))
                return super()._raw_frame(address, level)

        hole = RecordingWalker(sources, ((0x1000, 0x2000), (0x3000, 0xa000)))
        self.reject("DENY", "ram_hole", hole.translate, 0, 1)
        self.assertEqual(hole.reads, [(0x1000, 4)])
        cyclic = RecordingWalker({**sources, 0x1000: frame(0, 0x1007)}, ((0x1000, 0xa000),))
        self.reject("DENY", "frame_level", cyclic.translate, 0, 1)
        self.assertEqual(cyclic.reads, [(0x1000, 4)])

        valid = RecordingWalker(sources, ((0x1000, 0xa000),))
        result = valid.translate(0, 4096)
        self.assertEqual(valid.reads, [(0x1000, 4), (0x2000, 3), (0x3000, 2), (0x4000, 1)])
        self.assertEqual(valid.counts.values["frames"], 4)
        self.assertEqual(valid.counts.values["translations"], 2)
        self.assertEqual([(part["translation"]["physical"], part["translation"]["length"])
                          for part in result], [(0x8000, 2048), (0x8800, 2048)])
        self.assertEqual(result[0]["translation"]["path"], [
            {"frame": address, "index": 0, "entry": value}
            for address, value in ((0x1000, 0x2007), (0x2000, 0x3007),
                                   (0x3000, 0x4007), (0x4000, 0x8007))
        ])


if __name__ == "__main__":
    unittest.main()
