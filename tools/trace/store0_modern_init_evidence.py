"""Join the captured modern queue setup to one real read-only Oracle boot."""

import re

from store0_oracle_evidence import verify_boot
from store0_oracle_owner import TRACE_LIMIT

PTR = rb"0x[1-9a-f][0-9a-f]*"
HEX = rb"0x[0-9a-f]+"
NUM = rb"[0-9]+"
PCI = re.compile(
    rb"pdev=(%s) bus=(%s) slot=(%s) func=(%s) offset=(%s) size=(%s) value=(%s)"
    % (PTR, NUM, NUM, NUM, HEX, NUM, HEX)
)
COMMON = re.compile(
    rb"pdev=(%s) vdev=(%s) offset=(%s) size=(%s) value=(%s) selected=(%s)"
    % (PTR, PTR, HEX, NUM, HEX, NUM)
)
QUEUE = re.compile(
    rb"pdev=(%s) vdev=(%s) vq=(%s) queue=(%s) size=(%s) "
    rb"desc=(%s) avail=(%s) used=(%s) enabled=([01]) status=(%s)"
    % (PTR, PTR, PTR, NUM, NUM, HEX, HEX, HEX, NUM)
)
FORMATS = {
    b"store0_pci_cfg_read": PCI,
    b"store0_pci_cfg_write": PCI,
    b"store0_virtio_pci_common_read": COMMON,
    b"store0_virtio_pci_common_write": COMMON,
    b"store0_virtio_pci_queue_ready": QUEUE,
}
MODERN_EVENTS = tuple(name.decode("ascii") for name in FORMATS)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_modern_init(serial, trace, nonce):
    require(
        isinstance(trace, bytes)
        and 0 < len(trace) <= TRACE_LIMIT
        and trace.endswith(b"\n"),
        "incomplete modern initialization trace",
    )
    lines = trace.splitlines()
    selected = []
    block_lines = []
    for index, line in enumerate(lines):
        name, _, fields = line.partition(b" ")
        pattern = FORMATS.get(name)
        if pattern is None:
            block_lines.append(line)
        else:
            match = pattern.fullmatch(fields)
            require(
                match is not None,
                f"malformed {name.decode('ascii')} at line {index + 1}",
            )
            selected.append((index, name, match.groups()))
    read = verify_boot(serial, b"\n".join(block_lines) + b"\n", "reopen", nonce)
    vdev, vq = read["vdev"].encode("ascii"), read["vq"].encode("ascii")
    first_effect = next(
        index
        for index, line in enumerate(lines)
        if line.startswith(
            (
                b"virtio_blk_handle_read vdev " + vdev + b" ",
                b"store0_debugcon_write ",
            )
        )
    )
    operative_ready = max(
        index
        for index, line in enumerate(lines[:first_effect])
        if line.startswith(b"store0_virtio_blk_driver_ready vdev " + vdev + b" ")
    )
    reset = b"virtio_set_status vdev " + vdev + b" val 0"
    epoch = max(
        (index for index, line in enumerate(lines[:operative_ready]) if line == reset),
        default=-1,
    )
    queues = [
        (index, fields)
        for index, name, fields in selected
        if epoch < index < first_effect
        and name == b"store0_virtio_pci_queue_ready"
        and fields[1] == vdev
    ]
    require(len(queues) == 1, "one operative queue snapshot is required before I/O")
    queue_index, queue_fields = queues[0]
    pdev, _, queue_pointer, queue, size, desc, avail, used, enabled, status = (
        queue_fields
    )
    addresses = [int(value, 16) for value in (desc, avail, used)]
    require(
        queue_pointer == vq
        and queue == b"0"
        and size == b"128"
        and enabled == b"1"
        and int(status) & 192 == 0
        and len(set(addresses)) == 3
        and all(addresses),
        "configured queue does not match the used queue",
    )
    read_end = max(
        index
        for index, line in enumerate(lines)
        if line.startswith(b"store0_debugcon_write ")
    )
    common = [
        (name, fields)
        for index, name, fields in selected
        if epoch < index < read_end
        and FORMATS[name] is COMMON
        and (fields[0] == pdev or fields[1] == vdev)
    ]
    common_before_io = {
        name
        for index, name, fields in selected
        if epoch < index < first_effect
        and FORMATS[name] is COMMON
        and fields[:2] == (pdev, vdev)
    }
    require(
        common_before_io
        == {b"store0_virtio_pci_common_read", b"store0_virtio_pci_common_write"}
        and all(
            fields[:2] == (pdev, vdev) and int(fields[3]) in (1, 2, 4)
            for _, fields in common
        ),
        "operative modern common access identity or width differs",
    )
    require(
        not any(
            epoch < index < read_end
            and index != queue_index
            and FORMATS[name] is QUEUE
            and (fields[0] == pdev or fields[1] == vdev)
            for index, name, fields in selected
        ),
        "additional queue configuration in the selected read epoch",
    )
    pci = [
        (index, name, fields)
        for index, name, fields in selected
        if index < read_end and FORMATS[name] is PCI and fields[0] == pdev
    ]
    require(
        any(
            index < first_effect and name == b"store0_pci_cfg_read"
            for index, name, _ in pci
        ),
        "missing selected PCI config reads",
    )
    bdfs = {tuple(map(int, fields[1:4])) for _, _, fields in pci}
    require(
        len(bdfs) == 1
        and all(
            int(fields[5]) in (1, 2, 4) and int(fields[4], 16) + int(fields[5]) <= 4096
            for _, _, fields in pci
        ),
        "selected PCI identity or effective access width differs",
    )
    bus, slot, function = bdfs.pop()
    require(bus < 256 and slot < 32 and function < 8, "invalid PCI BDF")
    return {
        "read": read,
        "pdev": pdev.decode("ascii"),
        "bdf": [bus, slot, function],
        "pci_config_events": len(pci),
        "common_events": len(common),
        "queue": {
            "index": 0,
            "size": 128,
            "descriptor": addresses[0],
            "available": addresses[1],
            "used": addresses[2],
        },
    }
