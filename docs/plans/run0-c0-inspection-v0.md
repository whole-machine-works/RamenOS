# RUN0 reset capability and C0 inspection preparation

This packet freezes the next external inspection boundary at base
`3a1c5210a9431e2bc9bbc7a787918841eb5aafb8`. The machine-readable
[contract](../contracts/run0-c0-inspection-v0.json) contains the API, exact
operation allowlists, artifact shapes, bounds and assertion inventory. RSP1 and
CAP1 are implemented. The reviewed reset execution below qualifies those
capabilities for its exact profile. A fresh C0 still requires a reviewed
translation boundary, collector and invocation.

The first executable outcome is a reset-paused capability report. It can establish
which XML/register layout, realized CPU width and memory view this exact QEMU
actually exposes without resuming the guest or reading guest memory. The later C0
outcome is a fresh loaded-entry observation with checked ordinary-RAM reads. Full
[external Oracle acceptance](boot-profile-oracle-v0.md) still requires C0, C1 and
C2 from one run, including the same real GetMemoryMap call and its returned map.
No native CPU harness, driver trace, guest adapter, allocation or hardware claim
is introduced.

## Existing evidence and its limits

The accepted DEBUG firmware handoff is retained at
`/Users/maxwell/projects/whole-machine-works/evidence/debug-d21-batch-20261106/run0`
in the Whole Machine Works workspace alongside the RamenOS checkout, and at
`bigman:/tmp/wmw-debug-d21-YFXXNEg5/run0`. Those inputs and observations are
read-only for this work. The bounded probe used the actual unmodified EFI,
matching PDB, init, independently checked read-only ESP and private VARS clone.
Its actual complete 12,323-byte debug stream contains one matching line, line241:

```text
Loading driver at 0x0001E3FB000 EntryPoint=0x0001E3FD090 kernel_uefi-f1a8bffb2268a041.efi
```

The raw stream SHA-256 is
`b2cfaba458ff161f5e4282ea0404f826519b7e09ea4003df6b5ae2f43de9fd46`.
The actual probe report is
`7ef5bc9223e4158b7794b6600dde2d2066744848aecc8d45e05e6d71745cb8f8`.
All five original probe streams reached actual EOF, the owned child reaped with
return0 and no signals, and original pins remained unchanged. This establishes
a retained prior hint, not a fresh stop or a guarantee of the next run's address.

The canonical **probe** profile digest is
`e8c2957a83596bdc9919a8c71a6c7fb083a2d14e1a64edea3cd30330c602a35f`;
its exact JSON file digest is
`3e5916da4e1ec79eda8d967f4bd2fc26909fb509479c086db4576baa506a910e`.
The distinct canonical **entry-admission** profile digest is
`e79f8415df2057a2f2c5afdf96b5cff303db9527f8c3dd3d4b0f6ba486c8e3a7`.
The explicit field mapping, digest
`90a6d8be08521037cb9707020cf193388db26093f0d601faf6b4376bd99e0020`,
binds equal guest/tool/firmware/VARS/ESP bytes and opaque invocation/CPU evidence
across those schemas. Do not compare those different profile hashes as though
they should be equal or use ADMIT to claim CPU semantics.

The prior entry RVA is `0x2090`, yielding candidate entry `0x1e3fd090` from
candidate base `0x1e3fb000`. The existing admission helper produced 32 expected
file-derived entry bytes under its supported relocation rules. A future collector
must load the actual admitted packet and exact profile mapping; constants in this
prose cannot supply address authority. An absent hint is INCOMPLETE. A present
malformed or mismatched hint is DENY. No scan, alternate address or automatic
retry is allowed.

The DEBUG firmware was built from EDK II
`edc6681206c1a8791981a2f911d2fb8b3d2f5768`. Two clean firmware builds on the same
host/path produced identical CODE, VARS and full flash bytes; pinned BaseTools
were reused. The explicitly unavailable Subhook gitlink was not materialized or
consumed by the verified OVMF closure. This is the recorded build equality scope,
not general cross-host reproducibility or a complete recursive checkout. This
packet reuses those bytes and performs no firmware build.

## Source-supported interfaces and unobserved capabilities

The reviewer archived upstream QEMU8.2.2 source under the workspace evidence root
`/Users/maxwell/projects/whole-machine-works/evidence/run0-rsp-ipc-20261106/review/qemu-v8.2.2-source`, with
`review/primary-references.json`. The coordinator owns the separate official
Ubuntu source-package and installed-binary correspondence dossier under
`/Users/maxwell/projects/whole-machine-works/evidence/run0-rsp-ipc-20261106/qemu-source`. Its signed publisher metadata,
archives, patched source and exact differences must be bound to an execution
packet. Upstream source alone does not establish an installed downstream build.

| Primary source | Interface or restriction |
|---|---|
| [QEMU gdbstub/system.c](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/gdbstub/system.c) | Physical-memory mode set/query and asynchronous system-mode stop replies. Physical reads return success without rejecting MMIO or exposing transaction failure. |
| [QEMU gdbstub/gdbstub.c](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/gdbstub/gdbstub.c) | ACK framing, thread operations, feature chunks, generated target XML and breakpoint commands. `?` fabricates a current-thread T05 and removes breakpoints. Receiving any RSP byte while running can pause the VM. |
| [QEMU target/i386/gdbstub.c](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/target/i386/gdbstub.c) | TARGET_X86_64 reads use GDB_FORCE_64 even at reset. CR8 takes an APIC helper path. The mode-dependent write helper is outside authority. |
| [QEMU core XML](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/gdb-xml/i386-64bit.xml), [embedding generator](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/scripts/feature_to_c.py) | Exact66-register,608-byte layout. The generator embeds original XML bytes, including comments and whitespace. |
| [QEMU target/i386/cpu.c](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/target/i386/cpu.c) | Realization updates `phys_bits`; configured model expansion with `phys-bits=0` is insufficient. Use the read-only property on the actual reported CPU object. |
| [QEMU system/physmem.c](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/system/physmem.c), [system/memory.c](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/system/memory.c) | Physical reads use global `address_space_memory`; flattened view rendering exposes resolved ranges and offsets. CPU/SMM views cannot be substituted. |
| [QEMU APIC](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/hw/intc/apic.c), [APIC common](https://raw.githubusercontent.com/qemu/qemu/v8.2.2/hw/intc/apic_common.c) | CR8 can synchronize VAPIC through a guest physical read when `vapic_paddr!=0`. APIC reset sets that address0; this narrowly supports reset-only bulk `g`. |
| [GDB remote protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html) | Packet checksums, escaped binary replies and ACK semantics; archive the consulted protocol text in the dossier. |

Important upstream file pins already retained are:

| File | SHA-256 |
|---|---|
| `gdbstub/system.c` | `7ebdffa82f33873f401b94064f0dae18f41bd6d7efd41a947698362c2e1b4496` |
| `gdbstub/gdbstub.c` | `fc070617bba2a741a5e678de4bfc48c3044d8802a7a46469e11ec080bb106d90` |
| `target/i386/gdbstub.c` | `98816e6df40c877f52a6e3f4d829cb3af4b92107f47ea211f3d0de043d0a6a23` |
| `gdb-xml/i386-64bit.xml` | `1b3acc75743d5cea86aadda52e75a9ecdcbaefa89050d1aae8c4d8f3dd880953` |
| `system/memory.c` | `bc766316d570ce4798b118524f47a87bbd9fb3cceff8ce43ed39abf17e269b17` |
| `system/physmem.c` | `95a6536594b9f88b8820a296d9e8340934dd233f1ec24e050cf7de13d9017b57` |

The actual reset execution used the official Ubuntu `1:8.2.2+ds-0ubuntu1.18`
binary. Its bytes match the executable extracted from the package authenticated
by Ubuntu's signed archive index. The source dossier retains all 130 applied
patches and the comparison of 31 relevant files, including four explicit
downstream differences.

## Accepted reset observation

The exact prelaunch plan has SHA-256
`c652290447186a711c074e9f70395052d7b95263b8af3e6c8f834c99d3ef6cf1`.
One fresh reset-paused run returned a 40-bit realized CPU width, the pinned
66-register XML and 608-byte reset register payload, a matching monitor CPU dump
and the shared system memory view. Physical mode changed from 0 to 1 and read
back as 1. The 30 retained operations and 85 referenced blobs bind these
observations to the actual command and raw replies. All six streams reached
EOF, the owned child exited 0, and its wait was reaped without signals.
The report SHA-256 is
`19926604ec1ab43a77ac66af878c7641561777ade6243dd28f4685e47e4fedb6`.

The complete record is retained at
`/Users/maxwell/projects/whole-machine-works/evidence/run0-rsp-ipc-20261106/cap1/`
and `bigman:/tmp/wmw-rsp-ipc-pB6u3SJF/cap1/`. Twenty-one RSP controls and
fifteen launcher controls cover the gate-first assertions. Complete hosted
qualification remains required on the delivery PR's final head.

The separate IPC diagnosis reproduced two original ten-second transactions
with zero response bytes. A third connection received a valid reply. All three
requests share the same request ID, so the response cannot be assigned to a
particular request. A separately reviewed single-client successor succeeded on
its first request. Both monitor snapshots followed successful replies. The
failure-time CPU state and timeout cause remain unresolved. The retained
diagnostic and independent reviews are in the batch's `ipc/` and `review/`
directories.

## First executable slice: reset only

RSP1 owns `tools/trace/run0_rsp.py` and its dedicated tests. It has an incremental
bounded ACK codec, source-bound target/register decoder and typed fixed methods.
CAP1 owns `tools/trace/run0_rsp_capability.py` and its tests. It integrates one
socket reader with the owned VM's QMP/serial/debug/stdout/stderr drain, reusing
the accepted input/ESP/argv/private-file/cleanup primitives. Neither author
changes the existing probe or invokes its resume-capable `run_probe` function.

The public seam is `RSPClient(wire, budget)`. `wire.read_chunk(deadline,max_bytes)`
and `wire.write_all(data,deadline)` move bytes and preserve raw traffic; they do
not accept QMP commands or own semantic authority. CAP1 owns the fresh socket and
one multiplexed drain. The existing `boot_profile_capture.Budget` supplies the
shared deadline/message/storage limits. RSP1 adds cumulative wire, ACK and XML
caps. The contract lists exact immutable return shapes and methods; there is no
public arbitrary `request(payload)` escape hatch.

`client.operations` exposes immutable per-dispatch rows, including each XML
chunk, with exact request/response packet bytes, decoded response payload,
monotonic start/end and result. The launcher persists those as referenced
operations. A pending row precedes any write; a semantic reply failure remains
an error even when framing was valid. Local pre-dispatch rejection creates no
fictional wire row, and ACKs remain distinct raw traffic.

Only this RSP sequence is admissible:

1. `qSupported:qXfer:features:read+`, without client `multiprocess+`.
2. `qfThreadInfo`→`m01`, `qsThreadInfo`→`l`, `qC`→`QC01`, `Hg01`/`Hc01`→`OK`.
3. Contiguous bounded `qXfer:features:read` chunks for `target.xml`, then only
   `i386-64bit.xml`. Require final `l`, the source-generated single include and
   exact pinned core bytes/inventory. The generated `xi` prefix has no namespace
   binding, so accept its exact source grammar; do not repair arbitrary XML.
4. Reset-only `g`: exactly1,216 hex characters decoding608 bytes and66 registers,
   with no padding, guessed width or unavailable-value replacement.
5. `qqemu.Supported`, `qqemu.PhyMemMode`→`0`,
   `Qqemu.PhyMemMode:1`→`OK`, `qqemu.PhyMemMode`→`1`.

ACK mode remains enabled. Checksums cover encoded payload bytes; `}` escaping
is decoded only after checksum validation. Unescaped RLE is unsupported and
terminal because this pinned server does not need it. Retain ACKs and responses
separately; no retransmission, reconnect or silent recovery. A locally rejected
forbidden command emits no bytes and must leave a subsequent allowed operation
usable. An ambiguous or malformed remote reply ends that session's observations.

QMP has a separate exact allowlist. It identifies the sole actual CPU0 object,
then reads only that object's `realized` and `phys-bits` properties. Require true
and an exact integer32–52; configured `phys-bits=0`, a boolean or a guessed
default cannot substitute. Only literal `info registers` and `info mtree -f`
HMP commands are allowed. Initial/final status must remain paused/prelaunch,
and the CPU0/SMM0 register fields must agree across RSP/HMP. No `?`, breakpoint,
individual `p`, `m`, resume, interrupt byte or guest input is permitted.

The result is `run0_reset_capability_v0`, with all guest/full-capture claims
false, `fresh_c0_verified=false`, `resumed=false`, zero guest-memory-read bytes
and no hardware-breakpoint test. Mode set/readback establishes debugger state
only. Reset `g` is scoped by APIC reset and the absence of any guest execution.

CAP1 has one60-second VM deadline, a5-second teardown reserve and5-second
response/connect bounds clipped to that deadline. Shared QMP objects/RSP packets
are capped128, RSP raw bytes256KiB and assembled XML16KiB; ACKs and decoded
payloads have additional bounds. Total retained evidence, private VARS and the
reserved final report fit32MiB. Limits stop before another observation dispatch.
The final report survives output exhaustion as bounded INCOMPLETE evidence.
Actual graceful quit/reap and stream EOF remain mandatory and distinct facts.

The gate-first controls are RSP01–RSP08 and CAP01–CAP09. They include real socket
fragmentation, hostile framing/XML/width inputs, pre-dispatch denial followed by
success, strict QMP identity, no hidden resume/read, actual child cleanup and
late-tail/error behavior, cumulative bounds and a fresh unrelated successful
session after rejection. Existing27 probe controls remain evidence for their
unchanged helper; they do not satisfy these new controls.

## Later C0 boundary

C0D and C0C remain separate later assignments. The actual CAP1 result supplies
the reset capabilities. The decoder and collector still require an independently
reviewed paging bitmask table, per-register implicit-read audit and exact
collector extension review.

The pinned CPU model exposes SVM. Patched QEMU can retain hidden nested-page
translation state independently of the visible EFER.SVME bit. A valid C0
ordinary-RAM walk therefore requires an actual reviewed witness or a
source-bound exclusion of nested translation, plus A20 enabled. A changed CPU
profile needs a newly bound prior hint and reset-capability observation.

The collector installs one `Z1,<admitted-candidate>,1` hardware execution
breakpoint, requires `OK` and sends one `c`. After its acknowledgement it sends
**no RSP bytes** until the actual asynchronous stop arrives. In this server,
ordinary traffic while running can itself pause the guest. A fabricated `?`
reply, keepalive or duplicate ACK must not become a C0 witness.

Require the actual T05/thread01 stop bound to that resume and sole breakpoint,
RIP equal to the admitted candidate, QMP stopped/debug and HMP CPU0/SMM0. QEMU's
T05 response lacks a hardware-breakpoint reason; acceptance comes from the
combined bounded sequence, not the signal alone. Wrong or missing stops do not
authorize scanning or a second address.

Bulk `g` is forbidden after resume. Use only individually audited `p` reads for
registers0–23,27–30,32 and the source-reviewed HMP CPU dump for CPL/CS64/SMM and
GDTR/IDTR. Register31/CR8 is excluded because its APIC path can read VAPIC memory
without the collector's RAM checks. Other unused register paths remain excluded.

Physical mode uses global address space `memory`. Before every physical read,
select its unique complete flattened view and require the sole CPU's
`cpu-memory-0` view is identical and SMM=0. Admit ordinary `ram` named `pc.ram`
only, with identity backing offsets and no overlap, aliases, device/ROM ranges,
holes or arithmetic overflow. QEMU returning bytes or `OK` does not establish
RAM backing. Neither `info mem`/`info tlb` nor virtual debugger reads may perform
the collector's unchecked page walk.

Use fresh actual CR3/control registers and realized physical width. The initial
subset supports four-level48-bit canonical addressing, CPL0 and long mode with
4KiB/2MiB leaves. Reject unsupported active features before dispatch; the pinned
qemu64's disabled1GiB-page feature cannot be inferred enabled. Read each whole
table frame only after physical RAM admission, in two reads of at most2048 bytes.
Retain the raw frames, parent entries and translations. The first C0 slice is
limited to32 frames,64KiB other RAM including rechecks,512 paired operations and
90 seconds total, within the parent Oracle's larger full-run bounds.

Paused CPU state does not prove pending device activity has ceased. Bracket the
snapshot with fresh register/layout observations and reread every retained frame
and object. Require equality and retain differences as INCOMPLETE. These checks
support observed consistency only; `atomic_snapshot` and
`device_quiescence_verified` remain false. If a later claim requires stronger
quiescence, the coordinator must review a separate device/profile constraint.

Read the loaded PE identity fields and32 entry bytes through that fresh walk.
EDK II's pinned `BasePeCoffLib` explicitly rewrites PE32+ OptionalHeader.ImageBase
to the load address when relocating; raw whole-header equality would be wrong.
Check only the frozen identity fields and documented fixups, denying unknown or
unsupported modifications. Entry comparison uses the existing admission helper's
supported relocation calculation. This binds inspected bytes and the relocation
relationship, not every byte of the loaded image.

## Public EFI layouts and onward call binding

The [UEFI table definitions](https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html),
[x64 ABI](https://uefi.org/specs/UEFI/2.10/02_Overview.html#x64-platforms) and
[GetMemoryMap definition](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#getmemorymap)
are checked independently against pinned EDK II public C declarations and
`uefi-raw0.5.2` public `repr(C)` types. No private Rust layout is inferred.

| Public x64 object | Checked layout |
|---|---|
| EFI_TABLE_HEADER |24 bytes; signature0/u64, revision8/u32, HeaderSize12/u32, CRC32 at16/u32, reserved20/u32. |
| EFI_SYSTEM_TABLE |120 bytes, alignment8; BootServices pointer at96. Signature `0x5453595320494249`. |
| EFI_BOOT_SERVICES |376 bytes, alignment8; GetMemoryMap pointer at56. Signature `0x56524553544f4f42`. |

Pinned EDK II uses `(2<<16)|70`, exactly `0x00020046`, for these table revisions.
Require the profile's exact size/revision, reserved0 and CRC over the whole
table with the CRC field zeroed. Validate pointer canonicality/alignment,
translation and full ordinary-RAM span before reading or chasing it. RCX's image
handle remains opaque. The resolved GetMemoryMap pointer must map executable
ordinary RAM; retaining its code bytes is not a separate firmware-authenticity
proof.

Public source file byte pins in the accepted firmware/cargo closure:

| Source | SHA-256 |
|---|---|
| EDK II `MdePkg/Include/Uefi/UefiSpec.h` | `d98335e17008ab80811b787e4057bc18cb104da14722eadec184601efabdf379` |
| EDK II `MdePkg/Include/Uefi/UefiMultiPhase.h` | `2378821560691e16a42b523305dd08000c40109fba4e6e1e6ef1b1cc360bc5ab` |
| EDK II `MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c` | `cc7eb346b6c1ef5e89fb6f77f89baa79d2dc4fa45620decb70ab92607f91196d` |
| EDK II `MdePkg/Library/BasePeCoffLib/BasePeCoff.c` | `3b6099554b04794c48063fcb93e594cc42491ebdfc7de5bed498dd7f6da6ec61` |
| `uefi-raw0.5.2/src/table/system.rs` | `268ef483bfec4925177b0102d2fd94b01bb3ce59cd6634c9890ff31942737d42` |
| `uefi-raw0.5.2/src/table/boot.rs` | `c75b7d6e9b22a750fa1d5b646e149fa367a20c317b45df2d2d690bb4c4490559` |

C0 has no call reference or raw memory map. C1 must stop on the actual resolved
GetMemoryMap pointer, bind its saved return to pinned EFI caller code and retain
the five public argument pointers: RCX, RDX, R8, R9, and the pointer at RSP+40.
The return address is the64-bit word at RSP. C2 must be that same call's actual
saved return with EFI_SUCCESS and matching output pointers. Only then may the
collector read the returned size/key/stride/version and live raw map, perform the
complete bounded current table walk and classify all inspected backing with EFI
descriptors. No unrelated later successful call may replace it.

The subset artifacts deliberately have distinct kinds
`run0_reset_capability_v0` and `run0_c0_inspection_subset_v0`. Every object has
strict fields, bounded blob references and raw request/response linkage. Seven
guest/hardware claims plus `capture_complete` and `profile_preconditions_met`
remain false even after a valid C0 subset. The parent three-checkpoint contract,
Reference Vault registration, C1/C2 collector, guest-access proof and production
retention remain subsequent work.

## Handoff and acceptance

The coordinator owns shared schemas/registration, maintained status, CI/justfile,
source/package correspondence, immutable prelaunch manifests and execution
windows. RSP1 and CAP1 can proceed independently after their interface/assertions
are frozen, with one owner per named file. C0D/C0C and their transport additions
remain held as described above. Authors must preserve each other's edits and
return exact candidate hashes, RED/PASS evidence and limitations to an independent
reviewer. No acceptance follows from prose, a source-supported interface, a
synthetic fixture or a previous profile's successful probe.
