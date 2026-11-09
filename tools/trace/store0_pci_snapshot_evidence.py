"""Bind a guest PCI config snapshot to the same device that completed the read."""

import json
import re

from store0_modern_init_evidence import PCI, PTR, require, verify_modern_init
from store0_oracle_evidence import PREFIX, no_duplicates
from store0_oracle_owner import SERIAL_LIMIT, TRACE_LIMIT

SNAPSHOT_PREFIX = b"RAMEN_STORE0_PCI_V0 "
SNAPSHOT_MARKER = re.compile(
    rb"store0_debugcon_write debugcon (%s) offset 0x0 width 1 value 0x(16|96)" % PTR
)


def verify_pci_snapshot(serial, trace, nonce):
    require(
        type(serial) is bytes
        and 0 < len(serial) <= SERIAL_LIMIT
        and serial.endswith(b"\n")
        and type(trace) is bytes
        and 0 < len(trace) <= TRACE_LIMIT
        and trace.endswith(b"\n"),
        "incomplete PCI snapshot streams",
    )
    serial_lines = serial.splitlines()
    guest_rows = [
        index for index, line in enumerate(serial_lines) if line.startswith(PREFIX)
    ]
    snapshot_rows = [
        (index, line)
        for index, line in enumerate(serial_lines)
        if SNAPSHOT_PREFIX.rstrip() in line
    ]
    require(
        len(guest_rows) == 5 and len(snapshot_rows) == 1,
        "incorrect PCI snapshot row count",
    )
    row_index, row = snapshot_rows[0]
    require(
        row.startswith(SNAPSHOT_PREFIX) and guest_rows[0] < row_index < guest_rows[1],
        "PCI snapshot row outside device and read rows",
    )
    try:
        snapshot = json.loads(
            row[len(SNAPSHOT_PREFIX) :].decode("ascii"), object_pairs_hook=no_duplicates
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("malformed PCI snapshot row") from None
    require(
        type(snapshot) is dict
        and set(snapshot) == {"nonce", "phase", "bdf", "config_hex"}
        and snapshot["nonce"] == nonce
        and snapshot["phase"] == "reopen"
        and type(snapshot["config_hex"]) is str
        and re.fullmatch(r"[0-9a-f]{512}", snapshot["config_hex"]),
        "PCI snapshot identity or byte count differs",
    )

    lines = trace.splitlines()
    markers = [
        (index, match.groups())
        for index, line in enumerate(lines)
        if (match := SNAPSHOT_MARKER.fullmatch(line)) is not None
    ]
    require(len(markers) == 2, "one PCI snapshot marker pair is required")
    (before, (debugcon, start)), (after, (end_debugcon, finish)) = markers
    require(
        start == b"16" and finish == b"96" and debugcon == end_debugcon,
        "PCI snapshot marker order or identity differs",
    )
    filtered = lines[:before] + lines[before + 1 : after] + lines[after + 1 :]
    modern = verify_modern_init(serial, b"\n".join(filtered) + b"\n", nonce)
    bus, slot, function = modern["bdf"]
    bdf = f"0000:{bus:02x}:{slot:02x}.{function:x}"
    read_start = (
        b"store0_debugcon_write debugcon "
        + debugcon
        + b" offset 0x0 width 1 value 0x15"
    )
    require(
        modern["read"]["debugcon"].encode("ascii") == debugcon
        and snapshot["bdf"] == bdf
        and read_start in lines[after + 1 :],
        "PCI snapshot is outside the selected device read",
    )

    pdev = modern["pdev"].encode("ascii")
    vdev = modern["read"]["vdev"].encode("ascii")
    vq = modern["read"]["vq"].encode("ascii")
    read_index = lines.index(read_start, after + 1)
    reset = b"virtio_set_status vdev " + vdev + b" val 0"
    ready = b"store0_virtio_blk_driver_ready vdev " + vdev + b" status 15 "
    queue = (
        b"store0_virtio_pci_queue_ready pdev="
        + pdev
        + b" vdev="
        + vdev
        + b" vq="
        + vq
        + b" "
    )
    last_reset = max(
        (index for index, line in enumerate(lines[:read_index]) if line == reset),
        default=-1,
    )
    last_ready = max(
        (
            index
            for index, line in enumerate(lines[:read_index])
            if line.startswith(ready)
        ),
        default=-1,
    )
    require(
        last_reset < last_ready < before
        and any(line.startswith(queue) for line in lines[last_reset + 1 : last_ready]),
        "PCI snapshot preceded the operative queue and driver readiness",
    )

    config = bytearray()
    for line in lines[before + 1 : after]:
        event, _, fields = line.partition(b" ")
        match = PCI.fullmatch(fields) if event == b"store0_pci_cfg_read" else None
        require(match is not None, "non-PCI-read event in the config snapshot bracket")
        device, raw_bus, raw_slot, raw_function, raw_offset, raw_width, raw_value = (
            match.groups()
        )
        offset, width, value = int(raw_offset, 16), int(raw_width), int(raw_value, 16)
        require(
            device == pdev
            and tuple(map(int, (raw_bus, raw_slot, raw_function)))
            == (bus, slot, function)
            and offset == len(config)
            and width in (1, 2, 4)
            and offset + width <= 256
            and value < 1 << (8 * width),
            "PCI config snapshot identity, coverage or access width differs",
        )
        config.extend(value.to_bytes(width, "little"))
    require(
        len(config) == 256 and config.hex() == snapshot["config_hex"],
        "PCI config bytes differ",
    )
    return {
        "modern_init": modern,
        "snapshot": {
            "bdf": bdf,
            "config_hex": config.hex(),
            "config_reads": after - before - 1,
        },
    }
