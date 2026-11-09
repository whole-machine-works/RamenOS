#!/usr/bin/env python3
"""Run the private two-boot Linux virtio-blk Oracle on an exact capture plan."""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
from contextlib import ExitStack
from pathlib import Path

from store0_oracle_owner import (
    CaptureError,
    create_disk,
    open_disk,
    private_root,
    read_owned_stream,
    require,
    run_boot,
    verify_disk,
)

ROM_NAMES = {"bios-256k.bin", "linuxboot_dma.bin", "linuxboot.bin", "kvmvapic.bin"}
EVENTS = (
    "store0_debugcon_write",
    "store0_virtio_blk_driver_ready",
    "virtio_set_status",
    "virtio_blk_handle_read",
    "virtio_blk_handle_write",
    "virtio_blk_rw_complete",
    "virtio_blk_req_complete",
    "store0_virtio_blk_flush_submit",
    "store0_virtio_blk_flush_return",
    "store0_used_element",
    "store0_used_index",
    "store0_used_gap",
    "qemu_system_shutdown_request",
)
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
MAX_INPUT = 128 * 1024 * 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate plan key")
        result[key] = value
    return result


def digest_text(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def input_snapshot(pin):
    require(
        isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"},
        "invalid input pin",
    )
    require(
        type(pin["bytes"]) is int
        and 0 < pin["bytes"] <= MAX_INPUT
        and digest_text(pin["sha256"])
        and isinstance(pin["path"], str),
        "invalid input identity",
    )
    path = Path(pin["path"])
    require(
        path.is_absolute() and path.resolve(strict=True) == path,
        "input path must be canonical",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_size == pin["bytes"],
            "input type or size differs",
        )
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            require(chunk, "input ended during verification")
            digest.update(chunk)
            remaining -= len(chunk)
        require(not source.read(1), "input grew during verification")
        after = os.fstat(fd)

    def version(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    require(
        version(before) == version(after) == version(path.lstat())
        and digest.hexdigest() == pin["sha256"],
        "input identity changed",
    )
    return {
        **pin,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }


def read_plan(path, expected_sha):
    require(digest_text(expected_sha), "invalid plan digest")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "plan must be a regular file")
        raw = source.read(65537)
    require(
        len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == expected_sha,
        "plan digest differs",
    )
    plan = json.loads(raw, object_pairs_hook=unique_object)
    require(
        isinstance(plan, dict)
        and set(plan)
        == {"schema", "qemu", "kernel", "initrd", "roms", "libraries", "guest_sha256"},
        "invalid capture plan",
    )
    require(
        type(plan["schema"]) is int
        and plan["schema"] == 1
        and digest_text(plan["guest_sha256"]),
        "invalid plan schema or guest pin",
    )
    require(
        isinstance(plan["roms"], dict) and set(plan["roms"]) == ROM_NAMES,
        "incorrect ROM roster",
    )
    require(
        isinstance(plan["libraries"], list) and 1 <= len(plan["libraries"]) <= 64,
        "invalid runtime library roster",
    )
    return plan


def snapshot(plan):
    result = {key: input_snapshot(plan[key]) for key in ("qemu", "kernel", "initrd")}
    result["roms"] = {
        name: input_snapshot(pin) for name, pin in sorted(plan["roms"].items())
    }
    result["libraries"] = [input_snapshot(pin) for pin in plan["libraries"]]
    require(
        len({pin["path"] for pin in result["libraries"]}) == len(result["libraries"]),
        "duplicate runtime library",
    )
    return result


def boot_argv(plan, root, disk_fd, phase, nonce, *, probe_fd=None):
    command_line = (
        f"console=ttyS0 quiet loglevel=3 panic=0 rdinit=/init "
        f"ramen_store0_phase={phase} ramen_store0_nonce={nonce}"
    )
    access = "on" if phase == "reopen" else "off"
    require((probe_fd is not None) == (phase == "write"), "incorrect fdset roster")
    fdset = ["-add-fd", f"fd={disk_fd},set=1"]
    if probe_fd is not None:
        fdset.extend(("-add-fd", f"fd={probe_fd},set=1"))
    return [
        plan["qemu"]["path"],
        "-no-user-config",
        "-nodefaults",
        "-machine",
        "q35,accel=tcg,sata=off",
        "-smp",
        "1",
        "-m",
        "512",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-nic",
        "none",
        "-no-reboot",
        "-msg",
        "timestamp=off",
        "-L",
        str(root / "roms"),
        "-bios",
        str(root / "roms" / "bios-256k.bin"),
        "-kernel",
        plan["kernel"]["path"],
        "-initrd",
        plan["initrd"]["path"],
        "-append",
        command_line,
        "-chardev",
        "null,id=marker",
        "-device",
        "isa-debugcon,iobase=0xe9,readback=0xe9,chardev=marker",
        *fdset,
        "-drive",
        (
            f"file=/dev/fdset/1,format=raw,if=none,id=store0,cache=writeback,"
            f"rerror=report,werror=report,readonly={access}"
        ),
        "-device",
        (
            "virtio-blk-pci,drive=store0,num-queues=1,queue-size=128,ioeventfd=off,"
            "packed=off,disable-legacy=on,disable-modern=off"
        ),
        "-trace",
        f"events={root / 'events.txt'}",
    ]


def capture(plan, plan_sha, root, inputs_before):
    from store0_oracle_evidence import verify_boot

    require(sys.platform == "linux", "STORE0 capture requires Linux")
    require(
        root.is_absolute()
        and root.parent.resolve(strict=True) == root.parent
        and re.fullmatch(r"[A-Za-z0-9_./-]+", str(root)),
        "invalid private output path",
    )
    private_root(root.parent)
    root.mkdir(mode=0o700)
    result = {
        "scope": "linux-virtio-blk-flush-oracle",
        "plan_sha256": plan_sha,
        "status": "INCOMPLETE",
        "boots": [],
        "inputs_before": inputs_before,
    }
    with (root / "capture.json").open("x") as receipt:
        try:
            rom_dir = root / "roms"
            rom_dir.mkdir(mode=0o700)
            staged_roms = {}
            for name, pin in plan["roms"].items():
                staged = rom_dir / name
                shutil.copyfile(pin["path"], staged)
                staged_roms[name] = {**pin, "path": str(staged)}
            roms_before = {
                name: input_snapshot(pin) for name, pin in staged_roms.items()
            }
            event_bytes = ("\n".join(EVENTS) + "\n").encode("ascii")
            with (root / "events.txt").open("xb") as event_file:
                event_file.write(event_bytes)
            result["events"] = list(EVENTS)
            result["staged_roms"] = roms_before
            result["environment"] = ENV
            with create_disk(root) as identity:
                result["disk_identity"] = identity
                for phase, before_byte in (("write", 0x55), ("reopen", 0xA9)):
                    nonce = secrets.token_hex(16)
                    require(
                        all(row["nonce"] != nonce for row in result["boots"]),
                        "boot nonce reused",
                    )
                    require(
                        snapshot(plan) == inputs_before,
                        "capture inputs changed before boot",
                    )
                    require(
                        {name: input_snapshot(pin) for name, pin in staged_roms.items()}
                        == roms_before
                        and (root / "events.txt").read_bytes() == event_bytes,
                        "staged boot inputs changed",
                    )
                    row = {"phase": phase, "nonce": nonce}
                    result["boots"].append(row)
                    with ExitStack() as descriptors:
                        disk = descriptors.enter_context(
                            open_disk(root, identity, writable=phase == "write")
                        )
                        # QEMU probes the backing file read-only before opening it for write.
                        probe = (
                            descriptors.enter_context(
                                open_disk(root, identity, writable=False)
                            )
                            if phase == "write"
                            else None
                        )
                        row["image_before"] = verify_disk(disk, before_byte)
                        row["owner"] = run_boot(
                            boot_argv(plan, root, disk, phase, nonce, probe_fd=probe),
                            disk,
                            root,
                            phase,
                            probe_disk=probe,
                            env=ENV,
                        )
                        row["image_after"] = verify_disk(disk, 0xA9)
                    streams = row["owner"]["streams"]
                    serial = read_owned_stream(root, phase, "serial", streams["serial"])
                    trace = read_owned_stream(root, phase, "trace", streams["trace"])
                    row["evidence"] = verify_boot(serial, trace, phase, nonce)
            result["inputs_after"] = snapshot(plan)
            require(
                result["inputs_after"] == inputs_before,
                "capture inputs changed after boot",
            )
            require(
                {name: input_snapshot(pin) for name, pin in staged_roms.items()}
                == roms_before
                and (root / "events.txt").read_bytes() == event_bytes,
                "staged boot inputs changed",
            )
            require(
                result["boots"][0]["image_after"]
                == result["boots"][1]["image_before"]
                == result["boots"][1]["image_after"],
                "retained image differed across boots",
            )
            result["status"] = "PASS_LINUX_ORACLE"
        except BaseException as error:
            result["error"] = str(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)
            receipt.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--execute", type=Path, metavar="FRESH_OUTPUT")
    args = parser.parse_args()
    try:
        plan = read_plan(args.plan, args.plan_sha256)
        inputs_before = snapshot(plan)
        if args.execute is not None:
            capture(plan, args.plan_sha256, args.execute, inputs_before)
            print(f"STORE0_ORACLE: PASS_LINUX_ORACLE evidence={args.execute}")
        else:
            print(f"STORE0_ORACLE: PLAN_INPUTS_VERIFIED plan={args.plan_sha256}")
    except (OSError, CaptureError, ValueError, ImportError) as error:
        print(f"STORE0_ORACLE: INCOMPLETE {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
