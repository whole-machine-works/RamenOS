"""Fail-closed receiver for one fixed STORE0 Oracle boot.

The caller owns the launch, immutable command, full serial/trace capture, child
reap, disk identity and loss checks. This parser does not establish those facts.
"""

import json
import re

PREFIX = b"RAMEN_STORE0_ORACLE_V0 "
MAX_SERIAL = 8 * 1024 * 1024
MAX_TRACE = 8 * 1024 * 1024
PTR = r"0x[0-9a-f]+"
U = r"[0-9]+"
I = r"-?[0-9]+"
H = r"0x[0-9a-f]+"
PATTERNS = {
    "virtio_set_status": rf"vdev ({PTR}) val ({U})",
    "store0_virtio_blk_driver_ready": rf"vdev ({PTR}) status ({U}) offered ({H}) accepted ({H}) writeback ([01])",
    "store0_debugcon_write": rf"debugcon ({PTR}) offset ({H}) width ({U}) value ({H})",
    "virtio_blk_handle_read": rf"vdev ({PTR}) req ({PTR}) sector ({U}) nsectors ({U})",
    "virtio_blk_handle_write": rf"vdev ({PTR}) req ({PTR}) sector ({U}) nsectors ({U})",
    "virtio_blk_rw_complete": rf"vdev ({PTR}) req ({PTR}) ret ({I})",
    "virtio_blk_req_complete": rf"vdev ({PTR}) req ({PTR}) status ({I})",
    "store0_virtio_blk_flush_submit": rf"vdev ({PTR}) req ({PTR}) queue ({U}) descriptor ({U})",
    "store0_virtio_blk_flush_return": rf"vdev ({PTR}) req ({PTR}) queue ({U}) descriptor ({U}) ret ({I})",
    "store0_used_element": rf"vdev=({PTR}) vq=({PTR}) elem=({PTR}) queue=({U}) id=({U}) slot=({U}) old=({U}) result=({I}) direct=([01]) matches=([01])",
    "store0_used_index": rf"vdev=({PTR}) vq=({PTR}) queue=({U}) old=({U}) new=({U}) direct=([01]) matches=([01])",
    "store0_used_gap": rf"vdev=({PTR}) vq=({PTR}) queue=({U}) reason=({U})",
    "qemu_system_shutdown_request": rf"reason=({I})",
}
LINE = re.compile(r"(?:[0-9]+@[0-9]+\.[0-9]+:)?([a-z0-9_]+) (.+)")
COMPILED = {k: re.compile(v) for k, v in PATTERNS.items()}


def require(ok, detail="invalid or incomplete STORE0 evidence"):
    if not ok:
        raise ValueError(detail)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def guest_rows(serial, phase, nonce):
    require(
        type(serial) is bytes
        and 0 < len(serial) <= MAX_SERIAL
        and serial.endswith(b"\n")
    )
    rows = []
    for line in serial.splitlines():
        if b"RAMEN_STORE0_ORACLE_V0" not in line:
            continue
        require(line.startswith(PREFIX))
        try:
            row = json.loads(
                line[len(PREFIX) :].decode("ascii"),
                object_pairs_hook=no_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
            )
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("invalid guest row") from None
        require(type(row) is dict)
        rows.append(row)
    require(rows)

    def exact(row, fields):
        label = f"serial row {fields.get('seq')} {fields.get('kind')} {fields.get('operation', '')}"
        require(set(row) == set(fields), label + " keys")
        require(
            all(type(row[k]) is type(v) and row[k] == v for k, v in fields.items()),
            label + " values",
        )

    def common(index, kind):
        return {"seq": index + 1, "nonce": nonce, "phase": phase, "kind": kind}

    first = rows[0]
    require(
        set(first)
        == set(common(0, "device")) | {"major", "minor", "sector_size", "total_bytes"}
    )
    require(
        all(
            type(first[k]) is int and 0 <= first[k] <= 0xFFFFFFFF
            for k in ("major", "minor")
        )
    )
    exact(
        first,
        {
            **common(0, "device"),
            "major": first["major"],
            "minor": first["minor"],
            "sector_size": 512,
            "total_bytes": 4194304,
        },
    )
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
    require(len(rows) == 1 + 2 * len(ops) + 2)
    for n, (op, payload) in enumerate(ops):
        idx = 1 + 2 * n
        before = {**common(idx, "before"), "operation": op}
        if op == "pwrite_new":
            before["payload_hex"] = payload * 512
        exact(rows[idx], before)
        after = {
            **common(idx + 1, "after"),
            "operation": op,
            "return": 0 if op == "fsync" else 512,
            "errno": 0,
        }
        if op.startswith("pread"):
            after["payload_hex"] = payload * 512
        exact(rows[idx + 1], after)
    idx = len(rows) - 2
    exact(
        rows[idx],
        {
            **common(idx, "terminal"),
            "reason": "ok",
            "close_attempted": True,
            "close_return": 0,
            "close_errno": 0,
        },
    )
    exact(rows[idx + 1], {**common(idx + 1, "completion"), "outcome": "ok"})
    return first


def parse_trace(trace):
    require(
        type(trace) is bytes and 0 < len(trace) <= MAX_TRACE and trace.endswith(b"\n")
    )
    try:
        text = trace.decode("ascii")
    except UnicodeError:
        raise ValueError("non-ascii trace") from None
    events = []
    for pos, line in enumerate(text.splitlines(), 1):
        m = LINE.fullmatch(line)
        require(m is not None and m[1] in COMPILED, f"trace line {pos}: unknown event")
        fields = COMPILED[m[1]].fullmatch(m[2])
        require(fields is not None, f"trace line {pos}: malformed {m[1]}")
        values = fields.groups()
        pointers = (
            ()
            if m[1] == "qemu_system_shutdown_request"
            else (0, 1, 2)
            if m[1] == "store0_used_element"
            else (0, 1)
            if m[1]
            in (
                "store0_used_index",
                "store0_used_gap",
                "virtio_blk_handle_read",
                "virtio_blk_handle_write",
                "virtio_blk_rw_complete",
                "virtio_blk_req_complete",
                "store0_virtio_blk_flush_submit",
                "store0_virtio_blk_flush_return",
            )
            else (0,)
        )
        require(
            all(int(values[index], 16) != 0 for index in pointers),
            f"trace line {pos}: null pointer",
        )
        events.append((m[1], values))
    require(events)
    return events


def verify_boot(serial: bytes, trace: bytes, phase: str, nonce: str) -> dict:
    require(type(phase) is str and phase in ("write", "reopen"))
    require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None)
    try:
        device = guest_rows(serial, phase, nonce)
    except ValueError as error:
        raise ValueError(f"serial: {error}") from error
    events = parse_trace(trace)
    markers = (
        [0x11, 0x91, 0x12, 0x92, 0x13, 0x93, 0x14, 0x94]
        if phase == "write"
        else [0x15, 0x95]
    )
    marker_positions = []
    debug = None
    vdev = None
    vq = None
    ready = False
    ready_features = None
    ready_event = None
    preliminary = False
    preliminary_offered = None
    preliminary_reset = False
    shutdown_seen = False
    last_index = None
    for i, (name, v) in enumerate(events):
        try:
            if name == "qemu_system_shutdown_request":
                require(
                    not shutdown_seen
                    and ready
                    and len(marker_positions) == len(markers)
                    and v == ("6",)
                    and (
                        i == len(events) - 1
                        or (
                            i == len(events) - 3
                            and events[i + 1] == ("virtio_set_status", (vdev, "15"))
                            and events[i + 2]
                            == ("store0_virtio_blk_driver_ready", ready_event)
                            and ready_event[1] == "15"
                        )
                    ),
                    f"trace line {i + 1}: guest shutdown",
                )
                shutdown_seen = True
                continue
            if name == "store0_debugcon_write":
                require(ready, "marker before accepted DRIVER_OK")
                require(int(v[1], 16) == 0 and int(v[2]) == 1)
                if debug is None:
                    debug = v[0]
                require(v[0] == debug)
                marker_positions.append(i)
                require(
                    len(marker_positions) <= len(markers)
                    and int(v[3], 16) == markers[len(marker_positions) - 1]
                )
                continue
            if name == "store0_used_gap":
                raise ValueError("used ring gap")
            if name not in ("virtio_set_status", "store0_virtio_blk_driver_ready"):
                require(ready, "device IO before accepted DRIVER_OK")
            if vdev is None:
                vdev = v[0]
            require(v[0] == vdev)
            if name == "virtio_set_status":
                require(not ready or (int(v[1]) & 4 != 0 and int(v[1]) & 192 == 0))
                if preliminary and not preliminary_reset and not ready:
                    require(int(v[1]) == 0, "preliminary configuration not reset")
                    preliminary_reset = True
                if int(v[1]) & 4:
                    require(
                        i + 1 < len(events)
                        and events[i + 1][0] == "store0_virtio_blk_driver_ready"
                        and events[i + 1][1][:2] == v,
                        "DRIVER_OK without matching ready trace",
                    )
            if name == "store0_virtio_blk_driver_ready":
                offered, accepted = int(v[2], 16), int(v[3], 16)
                require(
                    offered <= 0xFFFFFFFFFFFFFFFF
                    and accepted <= 0xFFFFFFFFFFFFFFFF
                    and accepted & ~offered == 0,
                    "invalid offered/accepted feature masks",
                )
                require(
                    int(v[1]) & 12 == 12 and int(v[1]) & 192 == 0,
                    f"trace line {i + 1}: driver status",
                )
                require(
                    offered & (1 << 32)
                    and accepted & (1 << 32)
                    and not (offered | accepted) & (1 << 34),
                    f"trace line {i + 1}: modern split-ring features",
                )
                require(i > 0 and events[i - 1] == ("virtio_set_status", (v[0], v[1])))
                if phase == "write":
                    qualified = (
                        not (offered | accepted) & (1 << 5)
                        and offered & 512
                        and accepted & 512
                        and v[4] == "1"
                    )
                else:
                    qualified = bool(offered & (1 << 5) and accepted & (1 << 5))
                if not qualified:
                    require(
                        not ready
                        and not preliminary
                        and not accepted & 512
                        and v[4] == "0"
                        and (phase != "write" or not (offered | accepted) & (1 << 5)),
                        "invalid preliminary configuration",
                    )
                    preliminary = True
                    preliminary_offered = offered
                    continue
                require(
                    not preliminary or preliminary_reset,
                    "preliminary configuration not reset",
                )
                require(
                    not preliminary or offered == preliminary_offered,
                    "offered features changed across preliminary reset",
                )
                features = (int(v[2], 16), int(v[3], 16), v[4])
                require(ready_features is None or features == ready_features)
                ready_features = features
                require(ready_event is None or ready_event == v, "ready trace changed")
                ready_event = v
                ready = True
            if name == "store0_used_element":
                require(i + 1 < len(events) and events[i + 1][0] == "store0_used_index")
                w = events[i + 1][1]
                old = int(v[6])
                new = int(w[4])
                require(
                    v[0] == w[0]
                    and v[1] == w[1]
                    and v[3] == "0"
                    and w[2] == "0"
                    and v[6] == w[3]
                )
                require(
                    int(v[5]) == old
                    and 0 <= old < 128
                    and new == old + 1
                    and int(v[4]) < 128,
                    f"trace line {i + 1}: used slot/index/descriptor",
                )
                require(v[7:] == ("0", "1", "1") and w[5:] == ("1", "1"))
                if vq is None:
                    vq = v[1]
                require(
                    v[1] == vq
                    and (old == 0 if last_index is None else old == last_index),
                    f"trace line {i + 1}: used index continuity",
                )
                last_index = new
            if name == "store0_used_index":
                require(i > 0 and events[i - 1][0] == "store0_used_element")
        except ValueError as error:
            raise ValueError(f"trace line {i + 1} ({name}): {error}") from error
    require(shutdown_seen, "trace: missing guest shutdown")
    require(
        ready
        and len(marker_positions) == len(markers)
        and vdev is not None
        and vq is not None
    )
    require(
        any(
            name == "store0_virtio_blk_driver_ready"
            for name, _ in events[: marker_positions[0]]
        )
    )
    expected_kinds = (
        ["read", "write", "flush", "read"] if phase == "write" else ["read"]
    )
    covered = set()
    for n, kind in enumerate(expected_kinds):
        try:
            start, end = marker_positions[n * 2 : n * 2 + 2]
            require(start < end)
            segment = events[start + 1 : end]
            covered.update(range(start + 1, end))
            if kind == "flush":
                require(
                    len(segment) == 5
                    and [e[0] for e in segment]
                    == [
                        "store0_virtio_blk_flush_submit",
                        "store0_virtio_blk_flush_return",
                        "virtio_blk_req_complete",
                        "store0_used_element",
                        "store0_used_index",
                    ]
                )
                a, b, c, d, _ = [e[1] for e in segment]
                require(
                    a[0] == b[0] == c[0] == d[0] == vdev
                    and a[1] == b[1] == c[1] == d[2]
                )
                require(
                    a[2] == "0"
                    and a[2:] == b[2:4]
                    and b[4] == "0"
                    and c[2] == "0"
                    and int(a[3]) == int(d[4])
                )
            else:
                require(
                    len(segment) == 5
                    and [e[0] for e in segment]
                    == [
                        "virtio_blk_handle_" + kind,
                        "virtio_blk_rw_complete",
                        "virtio_blk_req_complete",
                        "store0_used_element",
                        "store0_used_index",
                    ]
                )
                a, b, c, d, _ = [e[1] for e in segment]
                require(
                    a[0] == b[0] == c[0] == d[0] == vdev
                    and a[1] == b[1] == c[1] == d[2]
                )
                require(
                    int(a[2]) == 8 and int(a[3]) == 1 and b[2] == "0" and c[2] == "0"
                )
        except ValueError as error:
            raise ValueError(f"trace operation {n + 1} ({kind}): {error}") from error
    # Outside syscall brackets only full, read-only discovery lifecycles and
    # non-reset device status/ready records are admissible. An orphan generic
    # completion cannot be assumed to belong to a read.
    outside = 0
    while outside < len(events):
        try:
            if outside in covered or outside in marker_positions:
                outside += 1
                continue
            name, _ = events[outside]
            if name in (
                "virtio_set_status",
                "store0_virtio_blk_driver_ready",
                "qemu_system_shutdown_request",
            ):
                outside += 1
                continue
            require(name == "virtio_blk_handle_read" and outside + 4 < len(events))
            group = events[outside : outside + 5]
            require(
                not any(
                    j in covered or j in marker_positions
                    for j in range(outside, outside + 5)
                )
            )
            require(
                [e[0] for e in group]
                == [
                    "virtio_blk_handle_read",
                    "virtio_blk_rw_complete",
                    "virtio_blk_req_complete",
                    "store0_used_element",
                    "store0_used_index",
                ]
            )
            a, b, c, d, _ = [e[1] for e in group]
            require(
                a[0] == b[0] == c[0] == d[0] == vdev
                and a[1] == b[1] == c[1] == d[2]
                and b[2] == "0"
                and c[2] == "0"
            )
            outside += 5
        except ValueError as error:
            raise ValueError(
                f"trace line {outside + 1} (outside bracket): {error}"
            ) from error
    require(
        all(
            marker_positions[i] < marker_positions[i + 1]
            for i in range(len(marker_positions) - 1)
        )
    )
    return {
        "phase": phase,
        "nonce": nonce,
        "device": device,
        "vdev": vdev,
        "vq": vq,
        "debugcon": debug,
        "operation_count": len(expected_kinds),
    }
