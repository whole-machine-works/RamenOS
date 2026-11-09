# Independent recovery module update and rollback

A Linux development test updated the recovery comparison module while a real
editor was recovering a Save, then rolled back during another Save recovery.
Each lookup finished with the module it pinned at creation. A later lookup used
the restored version, and another Save succeeded. The same host process and
editor child served all three recoveries. Store runs inside the host process.

## Selection and recovery

The development selector starts with the reviewed C1 module. It accepts only
the two exact module identities from the C1 and [C2 correspondence
records](recovery-c2-correspondence-2026-11-08.md). The loader opens a private,
owner-held, single-link regular file without following symlinks, reads at most
1,350 bytes, and checks stable file identity and metadata. It authenticates the
bytes and prepares the module before taking the selector lock. A successful swap
releases the old selection after unlocking. An already-held pin retains its
module through the swap. Failed file admission or preparation leaves the prior
selection usable. A poisoned selector refuses new pins and swaps.

The editor pins the module when it creates an eligible process-owned recovery
lookup, before registration. Retries of that flight use its original pin. The
comparison observes the same authorized Store snapshot as before, and Rust
owns the Save effects and receipt publication. The comparison exposes the
identity of the module actually invoked in its bounded in-memory record. The
encoded I1 record retains its original format. The existing C1 preparation
path and the new selection path are separate opt-in development features.

## Focused development evidence

The Linux test loses three real Commit replies and matches each recovered receipt
to the Store operation and its original epoch. It pauses a genuine first lookup
with C1 pinned, selects C2, and verifies the comparison actually used C1. The
second lookup pins C2, then uses C2 after rollback. The third lookup uses C1.
The test checks selected document bytes, one Commit per Save, the same child PID,
birth time and executable hash, and the host executable hash. It also covers a
foreign Store controller refusing the same lookup and invalid file length,
same-length corrupt bytes and nonprivate mode refusing selection.

The focused unfiltered Linux suite passed all four cases, including three cleanup
controls, and strict Clippy passed. The four legacy update-off tests also passed.
Two selector controls and strict Store library Clippy passed on macOS. An earlier
Linux development attempt reached an input acknowledgment timeout before the first
Save because the fixture skipped initial app composition. It retained an incomplete
cleanup report. The successor establishes the initial frame before input and uses
the original deadlines.

The existing required Linux supplement adds the selector controls and the full
update harness. It requires the actual C2 file identity for the new harness and
retains the Cargo-selected binary before discovery. The canonical process checks
and prior fault suites remain required. Hosted integration and separate receiving
review follow the focused evidence.

## Decision scope

This experiment covers independent selection and rollback for the two frozen
modules. The compiler change preserves recovery semantics. The competent Rust
comparison therefore requires zero executable replacements for that specific
request. A deployment comparison needs a separately specified release change
and measures actual release costs, warm recovery latency, cold setup and peak
host memory. Full live-owner acceptance, admitted adapter-error fallback and
activation are separate milestones.
