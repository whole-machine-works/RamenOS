# Owned C0 collector and shared dispatch

The collector now joins the accepted entry stop, host observation and typed RAM
acquisition through one owned VM and one wire. Independent source review and
354 sealed Linux trace controls pass. Three earlier actual reset captures still
validate. Actual C0 execution and retained-runtime acceptance remain pending.

## Implemented boundary

`run0_c0_capture.py` prepares immutable inputs and supplies the private current
and after-state issuers. It owns the actual child, fresh private VARS, endpoints,
helpers, final drain and wait. The existing 14-read/104-byte reader, paging walker,
acquisition schedule and offline C0 decoder remain unchanged. No public fixture
permit, replacement address, arbitrary transport callback or skip flag exists.

`run0_c0_budget.py` accounts the prefix, acquisition reservations, individual
physical reads, 33 final operations and terminal files in one envelope. The
512-operation and 32MiB limits remain unchanged. A read consumes its typed grant
once, after a pending operation and quiet-channel check; a blocked first send
rechecks the same grant's owner, epoch, cancellation and original deadline.
Copies use their own named credit or remaining common space before growth.

The completed current prefix is retained before the one acquisition-ledger
factory. The same `ReadsComplete` receipt precedes the after-register/HMP/view
checks, original breakpoint clear and undelimited quit. Success requires actual
VM and helper EOFs, successful owned waits and descriptor closure. A failure
records its first cause and drains remaining descriptors within the original
owner deadline, including when no quit receipt could be issued. Late replies or
EOFs cannot repair a failed operation.

## Runtime source and plan

The root runtime branch accepts only the exact SATA/VAPIC-disabled profile,
reviewed host ABI, accepted conditional persistence record, immutable prior
admission/profile/CAP1 closure and seventeen observer source files. It checks the
prepared registration before spawn and before issuing current RAM authority.
Runtime C0 uses distinct plan, source-manifest and observer kinds; the earlier
reset branch and synthetic fixtures keep their existing shapes.

The four prior/persistence input pins use exact three-item arrays in the new
plan. Their bytes and complete transitive input manifest are revalidated. This
keeps prior CAP1 inputs separate from the unchanged decoder's current-output
accounting; current outputs still use ordinary BlobRefs and remain charged.
Reserved current and failure output names are rejected during preparation.

The source persistence decision remains conditional on the actual current stop,
CPU state, ordinary-RAM view and closed command history. It proves neither global
work quiescence nor an atomic RAM snapshot. Python observer internals remain
trusted host development scaffolding.

## Qualification and review

Evidence root: `evidence/run0-c0-owned-collector-20261107/`.

- `policy-review-001/disposition.json`: independent root runtime-policy review,
  eight controls and separate malformed-input/ABI/manifest counterexamples.
- `runtime-abi-review-006/disposition.json`: actual retained-input recomputation
  includes the exact verified ABI root; strict full-manifest equality is preserved.
- `wire-review-001/disposition.json`: independent wire/accounting review,
  103 focused controls and operation/terminal-boundary counterexamples.
- `collector-root-review-002.json` and `collector-root-review-003.json`:
  non-author collector review, 24 controls and the final teardown correction.
- `linux-integrated-006.log`: all 354 controls pass under Linux Python 3.14.6;
  all 35 source/test hashes match before and after. The sealed manifest is
  `de166c13c84c4a08911e72abec1b94eeeb915b707f7cc4b2197823eea971efb5`.
- `endpoint-review-004/disposition.json`: independent acceptance of the fixed
  debugger socket mapping and actual UNIX connections derived from `build_argv`.
- `historical-reset-replay-006.json`: three unchanged retained reset captures pass.
- `gate-review-001/disposition.json`: four additive test commands preserve every
  earlier gate command byte-for-byte.

Review corrected preparation/cleanup gaps before live execution: reserved
output names missing from input collision checks, a quit dispatch after a poll
newly observed QMP EOF, and failure-only draining before the collector latched a
local quit refusal. Original candidates, failing controls and corrected evidence
are retained separately. The earlier default-denying readiness hook also had an
unbound exception name; its typed-refusal control now passes. Exact launch-plan
review rejected preparation003 before execution because its collector opened
`rsp.sock` while the unchanged QEMU argv created `gdb.sock`. The corrected closed
mapping is covered by actual UNIX listeners and connectors derived from the real
argv builder. The rejected prepared packet remains unexecuted and preserved. The later
single attempt005 entered the public collector but stopped at its first
registration check before run creation or VM spawn: preparation included the
verified ABI root in its 124-entry manifest, while validation reconstructed 123.
The corrected validator receives that exact ABI reference explicitly at both
current-registration and final-report call sites. Independent replay of the
retained 124-entry closure passes, and missing/altered/extra inputs still refuse.
The consumed attempt, traceback and unchanged source/input posthashes are retained;
no unchanged retry occurred.

## Next outcome

Independently review the exact frozen preparation and one-attempt execution
plan, then qualify actual C0 using unchanged public preparation/capture APIs.
Replay the retained host and C0 records independently before claiming acceptance.
C1/C2, complete retained-range collection, the final firmware exit map, allocator
installation and application execution remain separate outcomes.
