# Diagnostic firmware and reopened-Save evidence batch

Status: source, focused controls and actual prior-hint evidence independently
accepted; the delivery PR must record complete joined qualification before merge.

The fixed base is `530f91040dd48c72a5b653437b292fc27f27ff5e` (PR #58).
Before dispatch, the coordinator checked its post-merge
[CI run 42178680168](https://github.com/whole-machine-works/RamenOS/actions/runs/42178680168):
all nine checks passed. The retained audit verifies all eight artifact digests,
881 regular source files and six links, 57 canonical stages through 69 successful
owned command receipts, eight preservation stages, 244 recording runs and the
three actual archived build artifacts. This is fresh post-merge evidence, not
reuse of the earlier PR run. It does not explain earlier failed attempts.

## Parallel ownership and resources

The coordinator owns shared registration, Cargo targets/features, CI hooks,
source registries, authoritative status/history, commits and final qualification.
One author owns diagnostic-firmware preparation; another owns the D21 failure
diagnostics. A non-author reviewer checks plans, assertions, source and actual
evidence before integration. Authors preserve each other's changes.

The checkout is `/tmp/wmw-debug-d21-batch`, branch
`codex/debug-firmware-d21`. Fresh Linux resources are reserved under
`bigman:/tmp/wmw-debug-d21-YFXXNEg5/{run0,d21}`. The prior batch root remains
read-only. Builds use separate outputs and bounded parallelism; timed D21
execution and VM probing are serialized by the coordinator. Compact evidence
is retained at `/Users/maxwell/projects/whole-machine-works/evidence/debug-d21-batch-20261106/`,
outside generated checkout outputs. Large build inputs and raw evidence stay on
Linux. The main checkout's generated `out/` directory disappeared during this
batch; its cause is unknown. The eight immutable baseline ZIPs were restored
from GitHub and independently rechecked, and new author evidence was copied from
the retained worktree/Linux outputs. No source or Linux evidence was removed.

## RUN0 diagnostic prerequisite

Prepare a pinned DEBUG OVMF source/toolchain/build profile that actually emits
the existing image-loader diagnostic. Reuse the accepted entry-input helper and
bounded probe. Retain source origins, revisions, build configuration, tool and
output hashes, and independently verified input identities. No system firmware
installation, physical actuation or guest patch is involved.

The reviewer must accept the concrete source/build plan, resulting provenance,
profile and exact probe invocation before a new VM launches. A fresh private
VARS clone, immutable guest/tool inputs, capped logs, original deadlines and
actual owned cleanup remain required. Obtain one actual profile-bound prior
loaded-entry hint, then validate it with the existing admission helper. A prior
hint is only a candidate for a later fresh-run C0 stop. No guessed address,
automatic firmware fallback, full-memory scan or C0/C1/C2 claim is permitted.
Missing prerequisites remain `INCOMPLETE`.

## D21 failure diagnostics

The retained shared-frame campaign failed its original one-second fresh Save
after reopen. Hosted success later demonstrated a successful reopened-epoch
commit but did not establish that earlier failure's cause.

On the failure path, preserve immediate current-epoch Store/IO/permit/reply and
pending-original observations before cleanup can change them. Separately retain
actual cleanup attempts, child exit/join evidence and root ownership. Preserve
the original panic payload even if diagnostics or cleanup also fail. Unknown
join or reconciliation state must retain owners and remain explicitly unknown.
The normal assertions, one-second operation deadline and existing cleanup
deadline remain unchanged. No production behavior fix is inferred from this
instrumentation.

Gate-first controls must exercise a real failure, retained evidence and the
original unwind, plus unchanged successful operation. New diagnostics must
reuse existing Store and child observations rather than inventing authority or
interpreting a snapshot as quiescence proof. Independent review precedes any
source-registry successor and integration.

## Acceptance and successor

Authors run focused checks against reserved inputs. The coordinator qualifies
the fixed joined candidate with all hosted CI lanes, preserving original18,
Reader93, all thirty process families, shared-frame controls and all eight
preservation stages. Full local preflight is not duplicated with complete hosted
acceptance. Every failed setup, control or execution attempt is retained.

The next RUN0 join is the separately reviewed bounded C0/C1/C2 collector using
the accepted profile and real prior hint. The D21 successor depends on what the
new evidence actually shows; a later PASS cannot close a historical cause.

## Accepted DEBUG firmware and prior hint

The firmware uses upstream EDK II `edk2-stable202402`, commit
`edc6681206c1a8791981a2f911d2fb8b3d2f5768`, with an actual inventory of 43,331
materialized entries across 19 repositories. The official Subhook repository
lookup failed; its gitlink `83d4e1ebef3588fae48b69a7352cc21801cb70bc` remains
explicitly unmaterialized, without a mirror or placeholder. Both successful
build reports and 2,305 generated metadata files per build show no consumption
of Subhook/UnitTestFrameworkPkg. This qualifies the actual OVMF build closure,
not a complete recursive EDK II checkout.

Recorded tools include GCC 13.3.0, NASM 2.16.01 and Python 3.12.3. The verified
Ubuntu `acpica-tools_20230628-1_amd64.deb` was privately extracted for IASL;
no system package or firmware installation occurred. The standard X64/GCC5
DEBUG build uses two jobs, `FD_SIZE_4MB`, disabled secure-boot/SMM/source-debug
options, and `PcdDebugPrintErrorLevel=0x80000004` (ERROR|LOAD). Actual generated
DXE configuration and code confirm the diagnostic strings, mask, property
`0x2F`, debug port `0x402` and no `MDEPKG_NDEBUG`.

Two builds exited 0 and were actually reaped without signals in 114.003 s and
100.187 s. The entire firmware `Build` directory was removed between attempts;
pinned BaseTools were deliberately reused and unchanged. Each attempt retained
its exact environment, report, logs and dependency paths before cleanup. Bounds
were 1,200 s execution, 30 s teardown, 64 MiB logs and a sampled 5 GiB root guard.
Equality is observed on this host/path/toolchain, not claimed across hosts or
under a hermetic build. Both attempts produced these identical bytes:

| Output | Length | SHA-256 |
|---|---:|---|
| CODE | 3,653,632 | `272ff9e61a837f59beb0fbb3334461135419d5e255b4a8784a53f19acd503a8b` |
| VARS | 540,672 | `5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e` |
| Full flash, VARS followed by CODE | 4,194,304 | `235366a12cdf00c81527bb978d4d45de833bfd0434eb1348a672785b6423b4c0` |

A fresh unmodified `530f910` guest build used the pinned Rust nightly. Its source
archive still matches all 881 files and six links after building. Actual EFI/PDB
GUID and age match; independent `fsck.fat` and `7z` extraction checks confirm the
read-only FAT12 ESP contains the exact EFI and init bytes. The accepted observer
and entry helper are unchanged. All 27 Linux observer controls pass. An initial
missing test-fixture import and a source-preparation shell-variable error are
retained separately; neither was a build or VM failure.

Independent review accepted the exact inputs and invocation before the sole
fresh DEBUG `probe-001`. It ran for 20.096573 s, acknowledged nine requests and
retained 23 messages. All five streams reached actual EOF; no stream error or
supervisor signal occurred, QEMU was reaped with exit 0, and every input pin
remained unchanged. The complete debug stream is 12,323 bytes, below the unchanged
65,536-byte admission bound. One matching line at 241 supplies prior loaded base
`0x1e3fb000` and entry `0x1e3fd090`; no extraction, truncation or address search
was used. These addresses are candidates only.

| Evidence identity | SHA-256 |
|---|---|
| Probe profile bytes | `3e5916da4e1ec79eda8d967f4bd2fc26909fb509479c086db4576baa506a910e` |
| Canonical probe profile | `e8c2957a83596bdc9919a8c71a6c7fb083a2d14e1a64edea3cd30330c602a35f` |
| Actual probe report | `7ef5bc9223e4158b7794b6600dde2d2066744848aecc8d45e05e6d71745cb8f8` |
| Full raw debug stream | `b2cfaba458ff161f5e4282ea0404f826519b7e09ea4003df6b5ae2f43de9fd46` |
| Admission packet | `c3601b96913824e267fb4b0a1d0f6541b291d5f93349833a0750aaf29c10e9dc` |
| Explicit input mapping | `90a6d8be08521037cb9707020cf193388db26093f0d601faf6b4376bd99e0020` |
| Admission result | `1379d4790a91f89eac6575687cdfd6441e578678300c3276f49f94e8d9c19b85` |

The existing admission CLI returns `ADMIT / prior_candidate_inputs_checked`.
Its distinct canonical admission profile is
`e79f8415df2057a2f2c5afdf96b5cff303db9527f8c3dd3d4b0f6ba486c8e3a7`;
the explicit mapping binds all nine original input identities plus the opaque
invocation/CPU references to the exact probe profile, report and whole diagnostic.
On Linux, `run0/admission/packet.json` uses `run0/` as its input root. The compact
`run0/HANDOFF.md`, `run0/admission/mapping.json` and retained preparation scripts
provide exact commands and origins. No full-profile semantic acceptance, fresh
C0, memory dereference or address stability follows from this admission. All
capture/profile-precondition and seven broader claim fields remain false.

## Accepted D21 diagnostics and controls

Five test-support files implement the failure path and private controls. The
original `app_until_at`, native task, process task, full assertions and cleanup
helper sources remain byte-identical where asserted by the author's mechanical
check; only the named support seams change. Normal operation borrows its existing
endpoint without extending Core/Grant ownership. The original panic payload is
resumed unchanged after bounded secondary-error recording, actual child proof
retention and cleanup attempts. Diagnostic work starts within the existing
two-second cleanup budget, with one actual retirement and no deadline renewal.

Gate-first RED retains the absent helper and expected inference cascade.
`compile-001` retains an unused-helper Clippy failure; corrected `compile-002`
passes strict Clippy for the new control target and both existing consumers.
`controls-001` selects exactly four controls (three inherited helpers remain
filtered here and execute through their unchanged original gate). All four pass
in 6.614 s for the owned command. Seven actual subprocess waits record three
intentional exit-101 failures and four exit-0 successful operations. The separate
unchanged D21 case passes in 5.863 s, with actual reap. Firmware builds/VMs were
not running during these correctness controls.

The injected IO case executes the existing `JournalDirectorySync`
`SimulatedFailure` seam; it is not a physical disk failure. The held-pause case
retains `pending_originals=0`, `held_producers=1` and `Desktop(Timeout)` after a
genuine child `Exited(0)`/supervisor join, without claiming parent-transfer success.
Recorder refusal retains the actual error, marker and compact stderr observations;
it does not claim the Store snapshot that could not be written. All three failed
roots remain retained and all four successful fixture roots are actually removed.
No successful summary is manufactured for a failed scenario.

Independent review verified the source, real snapshots, typed errors, original
panic equality, authentic exit/join records and six archived binary references
across the focused runs. Compact records are in `d21/author-handoff.json`,
`d21/author-audit.json` and `d21/mechanical-source-check.json`; full evidence is
under the reserved Linux `d21/{red-001,compile-001,compile-002,controls-001,focused-d21-001}`
directories. The four controls join the required editor gate and strict Clippy
under `host_editor_process_assertions_v0_dev`, outside the original recording
roots. Only the two affected assertion hashes/lengths, new control path and
derived source-registry consumers change. Six source-inventory tests, 24 CI-lane
tests, the exact 274-row native collector and pinned Rust formatting checks pass.
Complete hosted qualification remains mandatory; the historical D21 cause is
still unresolved, including any relation to the earlier shared-frame change.
