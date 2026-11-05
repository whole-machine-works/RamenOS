"""Recorder boundary tests; synthetic rows do not claim native wire execution."""
import hashlib
import base64
from contextlib import ExitStack
import io
import json
from pathlib import Path
import tempfile
import unittest

import editor_process_recording as recording


def row():
    # Synthetic serializer/cap probes; this is not a native transmission claim.
    return {"k": "send", "d": 0, "b": base64.b64encode(bytes(88)).decode(), "c": None,
            "o": [], "q": 0, "s": 0, "t": 0, "f": 0, "r": 0}


class ControlRecording(unittest.TestCase):
    def test_scenario_cap_precedes_growth_and_other_scenario_remains_usable(self):
        ledger = recording.ControlLedger()
        output = io.BytesIO()
        for _ in range(recording.SCENARIO_CONTROLS):
            ledger.append(output, "boundary-a", row())
        before = output.getvalue()
        with self.assertRaisesRegex(recording.RecordingLimit, "scenario"):
            ledger.append(output, "boundary-a", row())
        self.assertEqual(before, output.getvalue())
        self.assertEqual(ledger.aggregate, recording.SCENARIO_CONTROLS)
        ledger.append(io.BytesIO(), "boundary-b", row())
        self.assertEqual(ledger.scenarios["boundary-b"], 1)

    def test_actual_aggregate_cap_file_hash_and_ordinal(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / f"controls-{index}.jsonl" for index in range(4)]
            ledger = recording.ControlLedger()
            with ExitStack() as stack:
                outputs = [stack.enter_context(recording.create(path)) for path in paths]
                for index in range(recording.AGGREGATE_CONTROLS):
                    leaf = index // recording.SCENARIO_CONTROLS
                    ledger.append(outputs[leaf], f"boundary-{leaf}",
                                  row())
                before = b"".join(path.read_bytes() for path in paths)
                with self.assertRaisesRegex(recording.RecordingLimit, "aggregate"):
                    ledger.append(outputs[-1], "boundary-next", row())
                self.assertEqual(hashlib.sha256(b"".join(path.read_bytes() for path in paths)).digest(), hashlib.sha256(before).digest())
                self.assertEqual(ledger.aggregate, recording.AGGREGATE_CONTROLS)
            rows = before.splitlines()
            self.assertEqual(len(rows), recording.AGGREGATE_CONTROLS)
            self.assertEqual(json.loads(rows[0])["i"], 1)
            self.assertEqual(json.loads(rows[-1])["i"], recording.SCENARIO_CONTROLS)
            with self.assertRaises(FileExistsError):
                recording.create(paths[0])

    def test_oversized_or_reserved_record_leaves_ledger_usable(self):
        ledger = recording.ControlLedger()
        output = io.BytesIO()
        for bad in ({"sequence": 9}, {"scenario": "forged"}, {**row(), "r": "x" * recording.ROW_BYTES}):
            with self.assertRaises((ValueError, recording.RecordingLimit)):
                ledger.append(output, "boundary", bad)
            self.assertEqual(output.getvalue(), b"")
            self.assertEqual(ledger.aggregate, 0)
        ledger.append(output, "boundary", row())
        self.assertEqual(json.loads(output.getvalue())["i"], 1)
        self.assertEqual(list(json.loads(output.getvalue())), ["i", "k", "d", "b", "c", "o", "q", "s", "t", "f", "r"])

    def test_partial_record_cannot_be_resumed_as_complete(self):
        class ShortOutput(io.BytesIO):
            def write(self, raw):
                return super().write(raw[:-1])
        ledger = recording.ControlLedger()
        output = ShortOutput()
        with self.assertRaisesRegex(OSError, "partial"):
            ledger.append(output, "boundary", row())
        before = output.getvalue()
        with self.assertRaisesRegex(OSError, "already incomplete"):
            ledger.append(output, "boundary", row())
        self.assertEqual(before, output.getvalue())
        self.assertEqual(ledger.aggregate, 0)

    def test_frozen_row_leaf_bounds_and_single_scenario_leaf(self):
        self.assertEqual(recording.ROW_BYTES, 512)
        self.assertEqual(recording.LEAF_BYTES, 16 * 1024 * 1024)
        ledger = recording.ControlLedger()
        output = io.BytesIO()
        ledger.append(output, "one", row())
        before = output.getvalue()
        with self.assertRaises(ValueError):
            ledger.append(output, "two", row())
        self.assertEqual(before, output.getvalue())
        other = io.BytesIO()
        with self.assertRaises(ValueError):
            ledger.append(other, "one", row())
        self.assertEqual(other.getvalue(), b"")
        self.assertEqual(ledger.aggregate, 1)


if __name__ == "__main__":
    unittest.main()
