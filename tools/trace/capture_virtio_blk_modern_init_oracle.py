#!/usr/bin/env python3
"""Capture one privately owned, read-only Linux virtio-blk modern-init boot."""

import argparse
import json
import os
import re
import secrets
import shutil
import sys
from pathlib import Path

from capture_virtio_blk_flush_oracle import (
    ENV,
    EVENTS,
    boot_argv,
    input_snapshot,
    read_plan,
    snapshot,
)
from store0_modern_init_evidence import MODERN_EVENTS, verify_modern_init
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
from store0_pci_snapshot_evidence import verify_pci_snapshot

SECTOR_OFFSET = 4096
SECTOR_BYTES = 512


def capture(plan, plan_sha, root, inputs_before, *, pci_snapshot=False):
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
        "scope": (
            "linux-virtio-blk-pci-config-read-only"
            if pci_snapshot
            else "linux-virtio-blk-modern-init-read-only"
        ),
        "plan_sha256": plan_sha,
        "status": "INCOMPLETE",
        "inputs_before": inputs_before,
    }
    with (root / "capture.json").open("x") as receipt:
        try:
            rom_dir = root / "roms"
            rom_dir.mkdir(mode=0o700)
            staged = {}
            for name, pin in plan["roms"].items():
                path = rom_dir / name
                shutil.copyfile(pin["path"], path)
                staged[name] = {**pin, "path": str(path)}
            roms_before = {name: input_snapshot(pin) for name, pin in staged.items()}
            events = EVENTS + MODERN_EVENTS
            require(len(events) == len(set(events)), "duplicate trace event")
            event_bytes = ("\n".join(events) + "\n").encode("ascii")
            with (root / "events.txt").open("xb") as output:
                output.write(event_bytes)
            result.update(events=list(events), staged_roms=roms_before, environment=ENV)
            with create_disk(root) as identity:
                result["disk_identity"] = identity
                # Seed through a second writable descriptor and close it before launch;
                # create_disk keeps its separate inode anchor private to the parent.
                with open_disk(root, identity, writable=True) as seed:
                    require(
                        os.pwrite(seed, b"\xa9" * SECTOR_BYTES, SECTOR_OFFSET)
                        == SECTOR_BYTES,
                        "could not seed scratch extent",
                    )
                    os.fsync(seed)
                    seed_sha = verify_disk(seed, 0xA9)
                nonce = secrets.token_hex(16)
                result["nonce"] = nonce
                require(
                    snapshot(plan) == inputs_before,
                    "capture inputs changed before boot",
                )
                require(
                    {name: input_snapshot(pin) for name, pin in staged.items()}
                    == roms_before
                    and (root / "events.txt").read_bytes() == event_bytes,
                    "staged boot inputs changed",
                )
                with open_disk(root, identity, writable=False) as disk:
                    result["image_before"] = verify_disk(disk, 0xA9)
                    require(result["image_before"] == seed_sha, "seed image changed")
                    result["owner"] = run_boot(
                        boot_argv(plan, root, disk, "reopen", nonce),
                        disk,
                        root,
                        "reopen",
                        env=ENV,
                    )
                    result["image_after"] = verify_disk(disk, 0xA9)
                    require(result["image_after"] == seed_sha, "scratch image changed")
                streams = result["owner"]["streams"]
                serial = read_owned_stream(root, "reopen", "serial", streams["serial"])
                trace = read_owned_stream(root, "reopen", "trace", streams["trace"])
                verify = verify_pci_snapshot if pci_snapshot else verify_modern_init
                result["evidence"] = verify(serial, trace, nonce)
            result["inputs_after"] = snapshot(plan)
            require(
                result["inputs_after"] == inputs_before,
                "capture inputs changed after boot",
            )
            require(
                {name: input_snapshot(pin) for name, pin in staged.items()}
                == roms_before
                and (root / "events.txt").read_bytes() == event_bytes,
                "staged boot inputs changed",
            )
            result["status"] = (
                "PASS_PCI_CONFIG_READ_ONLY_TRACE"
                if pci_snapshot
                else "PASS_RAW_READ_ONLY_TRACE"
            )
        except BaseException as error:
            result["error"] = str(error)
            raise
        finally:
            json.dump(result, receipt, indent=2)
            receipt.write("\n")
    return result["status"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--execute", type=Path, metavar="FRESH_OUTPUT")
    parser.add_argument("--expect-pci-snapshot", action="store_true")
    args = parser.parse_args()
    try:
        plan = read_plan(args.plan, args.plan_sha256)
        inputs_before = snapshot(plan)
        if args.execute is None:
            print(f"STORE0_MODERN_INIT: PLAN_INPUTS_VERIFIED plan={args.plan_sha256}")
        else:
            status = capture(
                plan,
                args.plan_sha256,
                args.execute,
                inputs_before,
                pci_snapshot=args.expect_pci_snapshot,
            )
            print(f"STORE0_MODERN_INIT: {status} evidence={args.execute}")
    except (OSError, CaptureError, ValueError, ImportError) as error:
        print(f"STORE0_MODERN_INIT: INCOMPLETE {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
