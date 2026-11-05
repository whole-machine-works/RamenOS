"""Bounded append-only process control recording, separate from native authority."""
from __future__ import annotations

import json
import base64
import os
from pathlib import Path

SCENARIO_CONTROLS = 32768
AGGREGATE_CONTROLS = 131072
ROW_BYTES = 512
LEAF_BYTES = 16 * 1024 * 1024


class RecordingLimit(RuntimeError):
    pass


class ControlLedger:
    def __init__(self):
        self.aggregate = 0
        self.scenarios: dict[str, int] = {}
        self.failed = False
        self.leaves: dict[object, tuple[str, int]] = {}
        self.scenario_outputs: dict[str, object] = {}

    def append(self, output, scenario: str, record: dict):
        if self.failed:
            raise OSError("process control recording already incomplete")
        # Admission precedes serialization, ordinal assignment and file growth.
        if self.aggregate >= AGGREGATE_CONTROLS:
            raise RecordingLimit("aggregate control capacity")
        count = self.scenarios.get(scenario, 0)
        if count >= SCENARIO_CONTROLS:
            raise RecordingLimit("scenario control capacity")
        if not isinstance(scenario, str) or not scenario or len(scenario) > 128:
            raise ValueError("bounded scenario identity")
        keys = ("k", "d", "b", "c", "o", "q", "s", "t", "f", "r")
        if not isinstance(record, dict) or set(record) != set(keys):
            raise ValueError("exact frozen control row fields required")
        if record["k"] not in {"send", "recv", "kernel_reject"} or type(record["d"]) is not int or record["d"] not in (0, 1, 2):
            raise ValueError("closed control kind/direction")
        if not isinstance(record["b"], str) or len(record["b"]) > 120:
            raise ValueError("bounded canonical base64 frame")
        try:
            decoded = base64.b64decode(record["b"], validate=True)
        except ValueError as error:
            raise ValueError("invalid frame base64") from error
        if decoded and (len(decoded) != 88 or base64.b64encode(decoded).decode() != record["b"]):
            raise ValueError("complete control frame must be exactly88 bytes")
        if record["c"] is not None and (not isinstance(record["c"], list) or len(record["c"]) != 3
                or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in record["c"])):
            raise ValueError("credential tuple")
        if not isinstance(record["o"], list) or len(record["o"]) > 3 or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in record["o"]):
            raise ValueError("bounded ledger references")
        if any(type(record[key]) is not int or not 0 <= record[key] <= 0xffffffffffffffff for key in ("q", "s", "t")):
            raise ValueError("unsigned request/sequence/time")
        if type(record["f"]) is not int or not 0 <= record["f"] <= 0xffffffff:
            raise ValueError("native flags")
        if type(record["r"]) is not int or not 0 <= record["r"] <= 0xffffffff:
            raise ValueError("bounded outcome/raw-leaf reference")
        leaf_scenario, leaf_bytes = self.leaves.get(output, (scenario, 0))
        if leaf_scenario != scenario:
            raise ValueError("one control leaf belongs to exactly one scenario")
        if scenario in self.scenario_outputs and self.scenario_outputs[scenario] is not output:
            raise ValueError("one scenario has exactly one complete control leaf")
        row = {"i": count + 1, **{key: record[key] for key in keys}}
        raw = json.dumps(row, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(raw) > ROW_BYTES:
            raise RecordingLimit("control row byte capacity")
        if leaf_bytes + len(raw) > LEAF_BYTES:
            raise RecordingLimit("control leaf byte capacity")
        try:
            written = output.write(raw)
        except OSError:
            self.failed = True
            raise
        if written != len(raw):
            self.failed = True
            raise OSError("partial process control recording; run incomplete")
        self.aggregate += 1
        self.scenarios[scenario] = count + 1
        self.leaves[output] = (scenario, leaf_bytes + len(raw))
        self.scenario_outputs[scenario] = output


def create(path: Path):
    """The caller owns its fresh exclusive run directory and closes the file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, "wb", buffering=0)


def boundary(directory: Path, *, scenario_limit=False):
    """Exercise real retained serializer files, without claiming native traffic."""
    import hashlib
    from contextlib import ExitStack
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    paths = [directory / f"controls-{index}.jsonl" for index in range(1 if scenario_limit else 4)]
    ledger = ControlLedger()
    record = {"k": "send", "d": 0, "b": base64.b64encode(bytes(88)).decode(),
              "c": None, "o": [], "q": 0, "s": 0, "t": 0, "f": 0, "r": 0}

    def prefix():
        digest, size = hashlib.sha256(), 0
        for path in paths:
            with path.open("rb") as source:
                while block := source.read(65536):
                    digest.update(block)
                    size += len(block)
        return {"count": ledger.aggregate, "bytes": size, "sha256": digest.hexdigest()}

    with ExitStack() as stack:
        outputs = [stack.enter_context(create(path)) for path in paths]
        for leaf, output in enumerate(outputs):
            for _ in range(SCENARIO_CONTROLS):
                ledger.append(output, f"boundary-{leaf}", record)
        before = prefix()
        try:
            ledger.append(outputs[-1], "boundary-0" if scenario_limit else "boundary-next", record)
        except RecordingLimit as error:
            reason = str(error)
        else:
            raise RuntimeError("aggregate boundary was not enforced")
        after = prefix()
        if before != after or reason != ("scenario control capacity" if scenario_limit else "aggregate control capacity"):
            raise RuntimeError("aggregate refusal changed retained prefix")
    result = {"scope": "recorder-boundary-not-native", "before": before,
              "attempt_index": (SCENARIO_CONTROLS if scenario_limit else AGGREGATE_CONTROLS) + 1, "after": after, "error": reason}
    print("PROCESS_RECORDER_BOUNDARY " + json.dumps(result, separators=(",", ":")))
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--boundary-output", type=Path)
    group.add_argument("--scenario-boundary-output", type=Path)
    args = parser.parse_args()
    boundary(args.scenario_boundary_output or args.boundary_output, scenario_limit=args.scenario_boundary_output is not None)


if __name__ == "__main__":
    main()
