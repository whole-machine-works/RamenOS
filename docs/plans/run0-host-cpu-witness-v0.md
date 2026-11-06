# RUN0 host CPU witness preparation

This gate-first packet at base `9f343d4cf9a708429aa914a83eeb058dfd266b20`
defines the next actual hidden-state prerequisite. The [contract](../contracts/run0-host-cpu-witness-v0.json)
owns the exact API, frames, fields, bounds and HC01–HC16 assertions. It does not
implement a reader or authorize a VM. Independent review and a green maintained
main baseline precede implementation; exact source/input/observer/plan review
and coordinator authorization precede the first reset-only execution.

The existing [reset capability](run0-c0-inspection-v0.md) remains accepted in its
scope. The selected QEMU can retain hidden nested paging independently of visible
EFER.SVME. A future C0 page-table walk therefore needs actual no-NPT evidence or
a complete source exclusion. CPU flag changes and missing log messages did not
establish that exclusion. This packet observes the existing emulator fields
without changing the selected guest profile or manufacturing a new prior hint.

## Retained basis

The preparation dossier is in the Whole Machine Works workspace alongside the
checkout, at `evidence/run0-rsp-ipc-20261106/c0d-preparation`. Its descriptor
decision is SHA-256
`452631ce3f2e2f5248bae920abfcddf62732357304593b891110aab2e2ef6c27`.
Signed Ubuntu package evidence binds QEMU `1:8.2.2+ds-0ubuntu1.18`, executable
SHA-256 `8a35ccba41582fc6c38b9df85fc9e35fa1d42f414d2d7d8090ee9b2f5e7c0854`,
Build ID `0bbe3fc40f3335f9ccdcd61cd96e02bf871f2449`, and matching debug/DWZ bytes.
Named offline queries bind the queue and field offsets; no guessed host address,
symbol scan or inferior execution supplies them. The generation address also
has a direct RIP-relative load in the exact installed executable.

The real toy descriptor receipt records a parent-opened read-only memory fd,
one supervised four-byte read, target exit/reap, and EOF through that same fd in
a second supervised reader. All three children reaped. This verifies that
fixture's behavior, not QEMU flags, adversarial cancellation or the new protocol.
Its receipt-only source/transcript limits remain explicit.

The actual host reports Ubuntu `6.8.0-142.142`, with the official source tag
pointing to `53e5d07aac028a1523ab0b115f079d6d1bc831ef`. `mem_open` stores a
referenced mm in the file; later reads use that mm and `mmget_not_zero`, not a new
numeric PID lookup. Exit/exec still invalidates the observation. The descriptor
pins mm identity, not pages or layout. The installed configuration enables
`FOLL_FORCE`, so read-only mode alone is insufficient admission policy.

## Exact ownership and read sequence

The true parent verifies native SIGCHLD disposition `SIG_DFL`, absence of
`SA_NOCLDWAIT`, and sole reaper ownership before creating QEMU and again before
opening proc files. `signal.getsignal` alone cannot establish the flags. No
Popen poll/wait, signal handler or other thread may reap QEMU during observation.
One pidfd corroborates lifetime; it does not repair a concurrent reaper race.
The private QMP socket's `SO_PEERCRED`, actual CPU0 host TID, proc identity and
executable descriptor bind the same owned process.

Only the parent opens the fixed owned proc-directory members. The memory fd is
`O_RDONLY|O_CLOEXEC`, with its actual access mode checked. Helpers receive fixed
descriptor roles and bounded pipes; they receive no QMP/RSP/device descriptors,
general PID/path/offset interface, attach authority or write operation.

One supervised metadata reader obtains raw stat/maps/smaps and executable
identity before the field reader. A fixed mountinfo fd binds the actual ext4
filesystem. Native descriptor `fstatfs` uses the pinned 120-byte, alignment8
LP64 struct with signed64-bit f_type at offset0; the coordinator
sizeof/offset/constant probe must confirm that ABI before execution. A second metadata reader uses fresh final proc descriptors to catch
exec/exit or changed layout. Reusing the original descriptors could merely
reread the old mm. Raw metadata is retained; volatile smaps accounting values
are not mistaken for identity changes.

The field reader uses a closed two-frame handshake. `Begin` admits only the two
source-pinned globals. After exact head/generation progress, the parent admits
the complete head-derived CPU object in actual maps/smaps and sends `AdmitCPU`.
The helper independently requires that same pointer and all identity checks
before dispatching hidden-field reads.

| Phase | Fixed bytes | Gate before advancing |
|---|---:|---|
| Head/generation before | 16 + 4 | Complete CPU object map admitted; second frame received |
| Node/index/TID before | 16 + 4 + 4 | Sole queue links, CPU0 and exact QMP host TID |
| hflags/hflags2 before | 4 + 4 | NPT, guest and SMM bits clear |
| hflags/hflags2 after | 4 + 4 | Exact repeated words |
| Node/index/TID after | 16 + 4 + 4 | Exact repeated identity |
| Head/generation after | 16 + 4 | Exact repeated queue; helper wait; fresh final brackets |

These are 14 preads and 104 bytes. A pending row precedes every syscall and its
actual result is emitted before another read. Short/zero/error replies stop the
sequence without retry or padding. Invalid pointer or CPU identity never reaches
the flags. Full hflags additionally supplies CPL, CS64 and LMA for later mode
consistency checks without another read.

## Map categories and bounded supervision

Only the pinned executable's ext4 data mapping, its checked BSS continuation,
and ordinary anonymous CPU allocation are supported. `statfs` magic `0xef53`
is shared by ext-family filesystems: actual matching mountinfo must say ext4.
Each raw maps row must match one smaps row and one exact VmFlags set. Unknown,
IO, PFNMAP, mixed, userfaultfd, unreadable or shared mappings stop admission.
The complete 25,888-byte CPU object must fit one permitted mapping.

The exact kernel sources in the contract establish why those categories have
no VMA access callback: ordinary anonymous mmap/brk sets `vm_ops=NULL`, and
the ext4 file operation tables omit `.access`. QEMU's object allocator source
connects the CPU object to ordinary allocation. Prelaunch retains these exact
source bytes and unchanged loader/library/environment bindings. A readable
maps line alone is not an ordinary-memory proof. The observer is trusted policy;
the inherited fd itself grants a wider read surface and `FOLL_FORCE` does not
enforce the helper's range restrictions.

There is one five-second aggregate witness deadline, clipped to the existing
60-second VM deadline and five-second teardown reserve. It covers both metadata
readers, the handshake, every pread and actual helper waits. At most one helper
runs at a time. All byte limits are charged before growth; retained metadata,
field traffic, stderr, report and VARS share the existing 32 MiB cap.

The parent remains responsive to a blocked helper and applies only the existing
owned TERM/KILL/wait policy. Proc open, fstat, sigaction and kernel reads have no
proved hard return bound. Neither a timeout nor a requested signal proves reap.
The parent keeps the request writer open through normal field-reader completion,
closing it on cancellation. The helper checks input EOF/extra bytes and the
aggregate deadline before each pread and terminal success. Observed cancellation
prevents subsequent dispatch; a close racing after that check may leave one read
in flight. Its actual/pending result is retained, without retroactive cancellation.
The report preserves the first failure, cancellation, secondary cleanup errors
and separate actual outcomes for every helper and QEMU. An unreaped child or
missing stream EOF prevents PASS; no further read or resume follows failure.

## API and acceptance handoff

After review, one author can own `run0_host_cpu_reader.py` and its tests for
the pure map/ABI validators and fixed internal worker modes. A separate author
can own `run0_host_cpu_witness.py` and its tests for the true-parent adapter,
reset-only plan/collect CLI, process/protocol ownership and artifact validation.
The coordinator assigns these files and owns all shared registration. These are
proposed dependent assignments, not current implementation authority.

The public CLI takes only the exact input/source/ABI bundles, fresh run root and
frozen plan digest. It has no PID, address, length or C0-mode option. The parent
adapter consumes an already owned child and typed QMP client; it does not launch
or resume a child on its own. Pure validation takes `validate_report(report_ref, immutable Mapping[str, bytes])`
and returns only `ValidatedHostState` after complete acceptance. Its exact fields
are origin, report_ref, binding, state and final_status. It performs no file, proc
or network acquisition. Closed metadata, peer, sigaction, process, read and control
indexes resolve every identity and sequence to retained raw bytes. Future C0 uses
the same operation sequence namespace, never an independently numbered join. HC01–HC16 cover identity-first denial, exact ABI, closed
framing, forced-read exclusion, original-mm exit/exec, partial data, metadata and
field stalls, real waits, and a fresh unrelated successful fixture after failure.

`run0_host_cpu_witness_v0` has separate live admission and final termination.
An `ADMIT` can gate only separately authorized reads in the same stopped
interval; final artifact `PASS` additionally requires complete raw evidence,
unchanged pins, required EOF and actual owned cleanup. The pure C0 decoder uses
the separately validated final report, not caller-supplied booleans.

The first actual witness remains reset-paused: no RSP connection, guest resume,
memory read or breakpoint. A later C0 integration must match every `StopBinding`
field: context/stop `c0`/`C0`, exact run and canonical probe profile, CPU0/TID,
RSP thread01, actual stop reference, original resume and breakpoint sequences,
and the same stopped control interval. Canonical profile digest uses the
existing input helper's sorted compact JSON without a newline; it differs from
raw profile-file SHA and the separate entry-admission profile digest. A20=1 is
still a separate actual HMP observation. Reset, synthetic, partial or cleanup-
unknown evidence cannot certify C0. All nine inherited capture/runtime claims
and `fresh_c0_verified` remain false for this packet.
