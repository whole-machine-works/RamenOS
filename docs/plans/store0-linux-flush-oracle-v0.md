# STORE0 Linux flush and reopen Oracle

The Oracle exercises one private virtio block image under a pinned Linux guest
and instrumented QEMU. It supplies a reference for the target storage path.
The native RamenOS provider and the Store consumer have their own acceptance
gates.

The write boot reads the seeded sector, writes a distinct 512-byte payload at
offset 4,096, calls fsync, and reads the result. The receiver joins the actual
virtio FLUSH submission, backend return, completion status and used-ring RAM
publication inside the guest's synchronous fsync markers. It also requires the
actual syscall return, guest-origin shutdown and a reaped emulator. The launcher
checks every byte of the image before opening that same held inode read-only
for a distinct boot. The second boot must read the expected bytes from the device
and leave the image unchanged.

The profile uses QEMU 8.2.2, q35 TCG, one vCPU, one modern split virtio block queue,
and a private 4 MiB raw image. Each phase supplies QEMU only the descriptors it
needs. The write phase supplies separately opened read-only and read-write
descriptors for the same inode because QEMU's file backend initially requests
read-only access. The reopen phase supplies only a read-only descriptor.

## Prepare inputs

Build QEMU with the [pinned source patches](../../tools/trace/store0_qemu/README.md).
Compile [the Linux init](../../tools/trace/virtio_blk_flush_oracle_capture.c) on
x86-64 Linux with `cc -std=c11 -O2 -static -Wall -Wextra -Werror -Wpedantic`.
Place the resulting binary at `/init` as a root-owned regular file with mode
0755 in a gzip-compressed newc archive. Check the archived member and its hash.
Use the project-pinned compatibility Linux image. Freeze the selected executable,
kernel, initrd, firmware, loader and actual library bytes on the capture host.

The version-one plan has the keys `schema`, `qemu`, `kernel`, `initrd`, `roms`,
`libraries`, and `guest_sha256`. `schema` is `1`. Each file pin has a canonical
absolute `path`, a `bytes` count, and a lowercase `sha256`. `roms` maps
`bios-256k.bin`, `linuxboot_dma.bin`, `linuxboot.bin`, and `kvmvapic.bin` to their
pins. `libraries` lists the canonical runtime paths, including the loader.
`guest_sha256` binds the independently verified `/init` member.

Verify the reviewed plan before launching. The `--execute` option takes a fresh
output directory under a private mode-0700 parent. Supply it only for an
approved capture. The plan-only invocation verifies inputs and exits.

```sh
python3 -B tools/trace/capture_virtio_blk_flush_oracle.py \
  --plan /absolute/path/to/manifest.json --plan-sha256 SHA256
```

Retain the plan digest, both owner receipts, raw serial and trace files, and
capture result. Incomplete attempts retain their original failure and partial
outputs. Begin any changed attempt with a new image and output directory.

The focused checks use ordinary host processes and synthetic receiver inputs.
They run without a QEMU build or guest in the Foundry quality lane. The live
two-boot result requires the owned execution above. Its claim is limited to the
fixed Linux/QEMU profile and clean restart. Abrupt power loss, physical media,
native target I/O and Store persistence require their own evidence.

## Development result

Capture 003 passed with two distinct guest nonces and the same held scratch
inode. The write trace joined FLUSH submission and backend return 0 to status 0
and used-ring publication inside the fsync markers. The read-only boot read
the new bytes from the same image. Both guests requested shutdown, both QEMU
owners exited zero and were reaped, and the final input snapshots matched.
The 4 MiB image changed only at offsets 4,096 through 4,607. Its SHA-256
`5a489aa019b4742dc831945b5d52415f22ae85e8b969de216ed014221cd1c552` matched at
the end of the write boot and before and after the read-only boot.

The private capture archive has SHA-256
`2cae4e0d377e91c8e1bd5f89b6a2bf4970ff98c71e6dc6789a43097b0b4e8735`.
Its reviewed input plan pins instrumented QEMU
`c527fbcc89b66f070d5cad6035e6df749acd6ac495293423d4213f38071add1e` and has
SHA-256 `1577bca0867efea5ac0ccb8cfe11676abff4c5565c471915884c94aee6ab4394`.
The packaged Python owner and launcher normalize to the executed syntax trees
after import ordering. The receiver and guest source match the executed packet
byte for byte. The packaged focused Linux checks passed three owner tests and
nine receiver tests.

Attempt 001 exited before guest startup because QEMU requested a read-only
descriptor and the fdset only supplied a read-write descriptor. Its image stayed
unchanged. Attempt 002 wrote and flushed the expected extent, then stopped at
the earlier device configuration in the verifier. It never launched a reopen.
Both attempts and their original dispositions remain in the private evidence.
