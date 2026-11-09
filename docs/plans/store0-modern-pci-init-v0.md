# STORE0 modern PCI initialization Oracle

This read-only Linux/QEMU profile supplies an observed reference for a RamenOS
block driver. It boots the same pinned Linux kernel and uses the same image
format and fixed virtio-blk device as the [write and reopen Oracle](store0-linux-flush-oracle-v0.md).
Each invocation initializes a fresh 4 MiB image on the host, closes the seed
writer and passes QEMU one read-only disk descriptor. The launcher verifies the
whole image before launch and after the emulator has exited and been reaped.

The [fourth QEMU patch](../../tools/trace/store0_qemu/04-modern-pci-init.patch)
adds the effective widths and returned values of PCI config reads, attempted
config and virtio common writes, and a queue snapshot at the enable path. The
receiver joins the operative PCI function, device and queue to the queue that
actually publishes the guest read. The captured guest ring addresses describe
Linux configuration. Native RamenOS mapping, ownership and revocation require
their own tests.

## Read-only initialization result

Capture 001 completed with 941 trace rows and a successful marked 512-byte read.
The selected device on bus 0, slot 1, function 0 used a 128-entry split queue.
The trace records four 4 KiB capabilities in the 16 KiB BAR, the programmed
ring addresses and the publication of the read completion on that same queue.
The complete private archive SHA-256 is
`91dd3ddb623d5f3ef24db41bc7d7bb600d056551b7d801bcef5203a9e3babed6`.
Independent receiving review reproduced the result. The first source staging
attempt carried unpinned metadata files and stopped before launching a guest.

The initialization trace did not include the capability header length bytes.
The optional snapshot guest reads the first 256 config bytes from the nearest
PCI ancestor of its admitted block device. It emits one nonce-bound row and
marks the read in the trace. The opt-in receiver requires that marker pair
after the selected queue and driver become ready, then compares the guest bytes
with the same device's actual config-read callbacks.

The snapshot run completed with 1,007 trace rows. Sixty-four ordered 4-byte
reads matched the complete 256-byte guest row. They recorded vendor `0x1af4`,
device `0x1042`, BAR 4 and the full capability chain. The common, ISR and
device headers are 16 bytes each. The notify header is 20 bytes and gives a
multiplier of four. Each mapped span is 4 KiB. BAR sizing came from the first
trace and the snapshot independently matched the BAR base. The selected queue
then completed the marked 512-byte read. The guest requested shutdown, the
emulator exited zero and was reaped, and the image hash stayed unchanged.

The private snapshot archive SHA-256 is
`0cf4b77fcfdb1900febc727db92dbaafbefaaa0971f8940a2700cae6eb1d3dea`.
Its reviewed plan binds a distinct initrd and the same instrumented QEMU binary
and 48-library closure. The observed addresses belong to these guest runs.
The native driver must discover and validate its own BAR and queue resources.
The PCI snapshot contains the notify capability. The common-register trace
records the queue's notify offset. An actual notify MMIO write requires
separate observation.

## Reproduce the captures

Build QEMU with the [four pinned patches](../../tools/trace/store0_qemu/README.md).
Build the original Linux guest using the write/reopen Oracle instructions.
For the snapshot profile add `-DSTORE0_PCI_SNAPSHOT` and package the resulting
static executable as the sole `/init` in a new initrd. Verify that member before
recording the guest and initrd identities in the input plan. The default build
continues to reproduce the original guest executable.

Run input verification without a guest first. The optional snapshot profile
requires `--expect-pci-snapshot` with its matching initrd and plan. Add
`--execute` only with a reviewed plan and a fresh path under a private parent.

```sh
python3 -B tools/trace/capture_virtio_blk_modern_init_oracle.py \
  --plan /absolute/path/to/manifest.json --plan-sha256 SHA256
```

The focused tooling checks cover the host owner, receiver refusal and fresh
success, and the opt-in guest config reader on Linux. The live captures are
separate. This profile supplies evidence for the driver design. Target block
I/O, Store persistence and durability still need their own qualification.
