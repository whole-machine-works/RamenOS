"""Own the private disk and child for the Linux STORE0 Oracle capture."""

import fcntl
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))
from selected_test_runner import group_snapshot, interrupted, reap, terminal_observation

DISK_BYTES = 4 * 1024 * 1024
SECTOR_OFFSET = 4096
SECTOR_BYTES = 512
SERIAL_LIMIT = 256 * 1024
TRACE_LIMIT = 2 * 1024 * 1024


class CaptureError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise CaptureError(reason)


def private_root(root):
    info = root.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "capture root must be private",
    )


def disk_identity(info):
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_size == DISK_BYTES,
        "disk must be a private regular image",
    )
    return (info.st_dev, info.st_ino, info.st_size)


@contextmanager
def create_disk(root):
    private_root(root)
    disk = os.open(
        root / "disk.raw", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        os.ftruncate(disk, DISK_BYTES)
        require(
            os.pwrite(disk, bytes([0x55]) * SECTOR_BYTES, SECTOR_OFFSET)
            == SECTOR_BYTES,
            "could not initialize scratch extent",
        )
        os.fsync(disk)
        verify_disk(disk, 0x55)
        # Keep an anchor open across both phases so its inode cannot be recycled.
        yield disk_identity(os.fstat(disk))
    finally:
        os.close(disk)


@contextmanager
def open_disk(root, identity, *, writable):
    private_root(root)
    path = root / "disk.raw"
    require(
        disk_identity(path.lstat()) == identity, "disk identity changed before open"
    )
    flags = os.O_RDWR if writable else os.O_RDONLY
    disk = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(
            disk_identity(os.fstat(disk)) == identity, "disk identity changed at open"
        )
        yield disk
        require(
            disk_identity(os.fstat(disk)) == disk_identity(path.lstat()) == identity,
            "disk identity changed after reap",
        )
    finally:
        os.close(disk)


def verify_disk(disk, sector_byte):
    before = os.fstat(disk)
    identity = disk_identity(before)
    actual = os.pread(disk, DISK_BYTES, 0)
    after = os.fstat(disk)
    require(
        disk_identity(after) == identity
        and after.st_mtime_ns == before.st_mtime_ns
        and after.st_ctime_ns == before.st_ctime_ns,
        "disk changed while checking bytes",
    )
    end = SECTOR_OFFSET + SECTOR_BYTES
    require(
        len(actual) == DISK_BYTES
        and actual[:SECTOR_OFFSET] == bytes(SECTOR_OFFSET)
        and actual[SECTOR_OFFSET:end] == bytes([sector_byte]) * SECTOR_BYTES
        and actual[end:] == bytes(DISK_BYTES - end),
        "scratch image bytes differ",
    )
    return hashlib.sha256(actual).hexdigest()


def run_boot(
    argv,
    disk,
    root,
    label,
    *,
    probe_disk=None,
    env=None,
    timeout=45,
    serial_limit=SERIAL_LIMIT,
    trace_limit=TRACE_LIMIT,
):
    """Retain two bounded streams and reap the actual process before returning."""
    require(sys.platform == "linux", "STORE0 capture requires Linux")
    require(label.isascii() and label.isalpha(), "invalid capture label")
    require(
        0 < timeout <= 45
        and 0 < serial_limit <= SERIAL_LIMIT
        and 0 < trace_limit <= TRACE_LIMIT,
        "invalid capture limits",
    )
    private_root(root)
    identity = disk_identity(os.fstat(disk))
    mode = fcntl.fcntl(disk, fcntl.F_GETFL) & os.O_ACCMODE
    pass_fds = (disk,)
    if probe_disk is not None:
        require(
            mode == os.O_RDWR
            and probe_disk != disk
            and disk_identity(os.fstat(probe_disk)) == identity
            and fcntl.fcntl(probe_disk, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
            "invalid read-only probe descriptor",
        )
        pass_fds += (probe_disk,)
    record = {
        "argv": argv,
        "disk": identity,
        "disk_fd": disk,
        "disk_access_mode": mode,
        "probe_disk_fd": probe_disk,
        "pid": None,
        "natural_exit": False,
        "reaped": False,
        "exit_code": None,
        "streams": {},
    }
    process = None
    digests = {}
    with (root / f"{label}.owner.json").open("x") as receipt:
        previous = {
            sig: signal.signal(sig, interrupted)
            for sig in (signal.SIGINT, signal.SIGTERM)
        }
        try:
            deadline = time.monotonic() + timeout
            with (
                (root / f"{label}.serial").open("xb") as serial,
                (root / f"{label}.trace").open("xb") as trace,
                selectors.DefaultSelector() as selector,
            ):
                process = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    pass_fds=pass_fds,
                    cwd=root,
                    env=env,
                )
                record["pid"] = process.pid
                with process.stdout, process.stderr:
                    for name, pipe, output, limit in (
                        ("serial", process.stdout, serial, serial_limit),
                        ("trace", process.stderr, trace, trace_limit),
                    ):
                        record["streams"][name] = {"bytes": 0, "eof": False}
                        digests[name] = hashlib.sha256()
                        selector.register(
                            pipe, selectors.EVENT_READ, (name, output, limit)
                        )
                    terminal = None
                    while terminal is None or selector.get_map():
                        remaining = deadline - time.monotonic()
                        require(remaining > 0, "boot owner deadline exceeded")
                        if terminal is None:
                            terminal = terminal_observation(process)
                        for event, _ in selector.select(min(remaining, 0.05)):
                            name, output, limit = event.data
                            row = record["streams"][name]
                            available = limit - row["bytes"]
                            chunk = os.read(event.fd, min(65536, available + 1))
                            if not chunk:
                                selector.unregister(event.fd)
                                row["eof"] = True
                                continue
                            saved = chunk[:available]
                            output.write(saved)
                            digests[name].update(saved)
                            row["bytes"] += len(saved)
                            require(
                                len(chunk) <= available, f"{name} output exceeded limit"
                            )
                record["natural_exit"] = terminal.si_code == os.CLD_EXITED
                record["terminal_status"] = terminal.si_status
                members = [
                    row for row in group_snapshot() if row["pgid"] == process.pid
                ]
                record["held_group"] = members
                require(
                    len(members) == 1
                    and members[0]["pid"] == process.pid
                    and members[0]["state"].startswith("Z"),
                    "unexpected owned group after exit",
                )
                record["exit_code"] = reap(process, record)
                record["reaped"] = True
                require(
                    record["natural_exit"]
                    and terminal.si_status == record["exit_code"] == 0,
                    "boot did not exit naturally with status zero",
                )
        except BaseException as error:
            record["error"] = str(error)
            if process is not None and not record["reaped"]:
                record["failure_group_absence_verified"] = False
                try:
                    record["exit_code"] = (
                        process.returncode
                        if process.returncode is not None
                        else reap(process, record)
                    )
                    record["reaped"] = True
                except Exception as cleanup:  # noqa: BLE001 - preserve the primary failure
                    record["cleanup_error"] = str(cleanup)
            raise
        finally:
            try:
                for name, digest in digests.items():
                    record["streams"][name]["sha256"] = digest.hexdigest()
                json.dump(record, receipt, indent=2)
                receipt.write("\n")
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
    return record


def read_owned_stream(root, phase, name, row):
    limit = {"serial": SERIAL_LIMIT, "trace": TRACE_LIMIT}[name]
    require(row["eof"] and 0 <= row["bytes"] <= limit, "incomplete owned stream")
    path = root / f"{phase}.{name}"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and info.st_size == row["bytes"],
            "owned stream identity differs",
        )
        data = stream.read(row["bytes"] + 1)
    require(
        len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"],
        "owned stream bytes differ",
    )
    return data
