# Linux editor child qualification — 2026-11-05

Status: the standalone child implementation was delivered in commit
[`ecae214ad67ec590747bcd6c220e8a326a987026`](https://github.com/whole-machine-works/RamenOS/commit/ecae214ad67ec590747bcd6c220e8a326a987026),
on `codex/editor-process-p0-p3`, draft [PR 52](https://github.com/whole-machine-works/RamenOS/pull/52).
Later child changes, including the conditional D27 return path described below,
are qualified against immutable candidate 013 and remain pending repository
integration. This record does not establish acceptance of the complete P0–P3
workflow. Independent review of the 013 synthetic runtime evidence is
**accepted within the synthetic protocol/data scope**. The reviewer independently
verified the source, ELF, Cargo, script, report, driver and raw-control bindings,
61 distinct native child reaps, and 458 retained control rows. Harness/source
review preceded execution; the separate result audit followed the retained run.

## Immutable candidate and build identity

The coordinator's immutable candidate is
`/tmp/ramen-p0-p3-NerTsUjj/integrated-faults-013` on `bigman`. The standalone
successor used copies of its already-built executables in the unique directory
`/tmp/ramen-p0-p3-NerTsUjj/p2-successor-013-001`; it ran no Cargo commands and
changed no source or shared build target.

[Binding checks][binding] verified every byte length and hash in the candidate's
**869-entry source manifest**, the copied ELF files, both Cargo JSON target and
feature records, successful build-finished records, actual build-command exits
and reaps, the unchanged lockfile, and the frozen font. The child build dependency
records contain no Desktop, Store, or artifact-store-schema package.

| Identity | SHA-256 |
| --- | --- |
| [013 source manifest][source] | `40a46b065f6c4536a7c11763de938365c0ff136e851c110c56791cccd04fb8bc` |
| [013 gate record][gate] | `d338df472e2748e7fc24d3d1bc664a87ec07929ff039e6fab7296c8ed86edf72` |
| Lockfile before and after | `8495485fb5d3b0aa5c02a60634d0c05e212650cdc4412af1ff55cea3a7112ad0` |
| [Production ELF][production] | `440a0b23a599e78c617949ae29d18967da8a1542145522ada12d62e9de195eea` |
| [Assertion ELF][assertion] | `0bbda10771deee993d1eacd0bc6a02d634db97f52b2205d7597cdf9460083e03` |
| Production Cargo JSON stdout | `adb8eb44f8c6aaacdca4dde75b322a73595d72f6506c28bd1b38e94ea9f2b1fc` |
| Assertion Cargo JSON stdout | `02f4351f12055223946db8ff431d347c1761d3049813fa7a036d1436e181cef2` |
| Frozen `ascii8x16_v0.bin` | `50ab6522c495f06a69590ccb6958458be15e02a2ca4c6b1024b052e826d21c64` |

Both builds selected only the `editor-process` binary, with
`--locked --no-default-features`. Production used
`host_editor_process_child_v0_dev`; the assertion build used
`host_editor_process_child_assertions_v0_dev` and its production-child dependency.
The retained [production build command][production-command] (PID 822330) and
[assertion build command][assertion-command] (PID 822926) each exited zero and
were actually reaped. Their command-record hashes are, respectively,
`886caacf238b45ad0ec7969b8bd92dfa8b42aab64ca0d61b861c6a55f71a894c`
and `6dbc22e37177302a853e7fd5311650616bd75e931443563560c301cbb7efc946`.

The manifest pins these child sources:

| Source | SHA-256 |
| --- | --- |
| `src/bin/editor-process.rs` | `e0c28a349f94089b577ac4d635cbf2dab2c8638c73bc5f5c8ae5efeaf856e88c` |
| `src/bin/editor_process_child/linux.rs` | `46628e104037e1c3b6b22641c0e6b473477cacd1448743d28260e2d39e01612c` |
| `src/bin/editor_process_child/assertions.rs` | `687be2253974d3e19ed07a58539d10147e88916212330b6608136e607783e2f9` |
| Private assertion transport catalog | `c388631900ba4cf860e01675d423d875476e0e6223da8963b209cdbb7039440b` |

## Standalone synthetic result

The [result index][result] retains the script identities, report hashes and
explicit scope flags. Its SHA-256 is
`1b3e40c6e4482e125ff1cfa013ea16d1a659a546a06015e1fd9bfca9e5e216ba`.
The [owned driver receipts][drivers] record three actual zero exits and reaps:
PIDs 1030470, 1030504 and 1030866. Each case also retains its own actual child
PID, exit result, reap, raw controls, stdout and stderr. All **61 child PIDs are
distinct and were reaped**; **458 raw control rows** are retained.

| Driver | Checks passed by driver | Children / control rows | Summary SHA-256 |
| --- | --- | --- | --- |
| [Normal][normal] | Editing, independent full frozen-font raster, immutable mapped publications, input/capture/receipt sequencing, unsupported input rejection | 2 / 56 | `dcfc1926b45e8a7328eb82b98a4ddeb19a6b471d20e016db2731bc7fcd435766` |
| [Fault/data][faults] | 57 closed controls over raw frames, FD counts, malformed text/state/surface data, seals, actual retained mappings and `EBUSY`, RPF0 notification, streams, EOF, backpressure and copied capture replay | 57 / 374 | `d8eb4e3b930e0e4c93c342590d789c31a9dd8f66e0f19036309728ad3f69ddd3` |
| [Conditional returns][conditional] | `D16ExistingInodeAsNewCredit` and `D27OldSurfaceGeneration`: healthy bootstrap; new writable ordinary pair follows normal map/write/seal; a subsequent genuine sealed prior pair is echoed unchanged under the new request | 2 / 28 | `a2152e272b529479adf89225785ada328ea210491326af335c35aa68a95161ec` |

The normal child exits were 0 and 2; fault-child exits were deliberate termination
by the owning driver or error exit 2; both supplemental children exited 0. Every
case's raw kernel credential tuple was checked against its actual owned child
PID. Retained writable/mprotect cases checked actual shared mappings and native
`F_ADD_SEALS` failure with `EBUSY`, then successful sealing after actual reap.

Harness identities are `smoke.py` `9dd1a5df88f74bdd1bb64c0b722f32f83abc86a4c91f3f67d50a900445c09b1e`,
`faults.py` `29a209c98a4c5d1e7058adb2320b8dedb3f01c684b4846d99c9a7d493307dfea`,
`conditional.py` `4636c259aaa6ea5e3e5e9a9f95c583b5d140a199ddb66381bd0c5d4915645453`,
and `runner.py` `501fae1432e16911778e42eb3321aa42ac105eacf9653e5e0d2151e90a3464b5`.
The fault driver differs from the earlier reviewed driver only by first accepting
a healthy ordinary publication before examining the D10 mutation on the second
ordinary publication. The driver receipts' combined SHA-256 is
`2a7a12b6f0bcb7f16d13aaa00f64aeff96f3d17b5e3ecaadc9a32ce2d2a98558`.

These tests use **synthetic parent protocol data**. They prove neither genuine
Core Save capture nor Store Save/recovery, Core quota/generation admission,
held-inode execution, protected chrome, complete P1/P3 integration, all 72
selectors, the full native gate, or the complete Linux campaign. The supplemental
D27 result establishes the child's conditional transport behavior; the actual
Core stale-generation result is a separate execution below. No generic
descendant-cleanup claim follows from an arbitrary nonzero driver exit: normal
case cleanup owns each child, and the wrapper's process-group termination is a
timeout fallback.

## Separate genuine Core D27 execution

The coordinator separately ran
`full_assertions::process_d27_focus_compositor_service_reset_and_reserved_reset`
on immutable 013. Its [native command receipt][core-command] records an actual
zero exit, PID 831956, actual reap, and 2,656,318,774 ns elapsed. The
[test output][core-output] reports exactly one selected test passed, with no
failures. This is the genuine Core family result, including the actual
Compositor-restart/stale-adoption oracle; it is not an assertion made by the
standalone child driver. Its detailed process evidence remains in the
coordinator's 013 `p3-focused/process-io` and `parent-io` corpus.

Command SHA-256:
`d22974c0bf0161a16d2fe769561de6d50866c4bd0024054d9ace59857048aa37`.
Stdout SHA-256:
`fe701291d946add2c1326ac473915ae60da8bb8d939e93daccbfcbd0d856cc0f`.
This focused family pass does not upgrade other failing or unexecuted 013
families to acceptance.

## Earlier unchanged capture-replacement baseline

The separately reviewed [three-case capture report][capture] remains a limited
baseline on immutable **010**, production ELF
`b8a59432e0fcb70552ae28b13429ce14a44d4e3bf2077e66fbfb5ab83631fae4`,
source-manifest hash
`1fa8cac64a8f85b004f78fbba080f6b21c6bd9d59689f1524d8101720afd5771`,
and child Linux source hash
`79f5df159cc9913386848fdc8ea5e06d1cba41052161708f88b83d2a3c751f4a`.
All three actual children were reaped: acknowledged capture replacement without
an intervening notice exited 0; old-notice rejection after replacement and
unacknowledged replacement rejection each exited 2. Full controls demonstrated
the genuine kernel transport and independent object/raster hashes.

That report's SHA-256 is
`ba7772d6a24427f7f385995937c82336a5306691f861010bd90bc50cd032ac60`.
It does not prove a genuine Core NoAllocation outcome or Store Save. The guard
was unchanged in 013 and these three cases were not rerun or relabeled as 013
executions. Their earlier independent scoped acceptance does not substitute for
the separate audit of the new 013 evidence.

## Delivery continuation

The coordinator must integrate reviewed successor source on the delivery branch,
update PR 52 or the applicable successor
PR, and retain the exact final-candidate build/runtime evidence. Complete all
required native assertion families, genuine P3 Save/recovery/lifecycle behavior,
unchanged consumers and complete acceptance gates before accepting the product
milestone. A child commit, synthetic test count or qualified source snapshot is
not that finish line.

[binding]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/binding-check.json
[source]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/source.json
[gate]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/gate-record.json
[production]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/editor-process
[assertion]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/editor-process-assert
[production-command]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/child-build.command.json
[assertion-command]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/assert-child-build.command.json
[result]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/result.json
[drivers]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/driver-summary.json
[normal]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/normal/summary.json
[faults]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/faults/summary.json
[conditional]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/conditional/summary.json
[core-command]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/process_d27_focus_compositor_service_reset_and_reserved_reset.command.json
[core-output]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/process_d27_focus_compositor_service_reset_and_reserved_reset.stdout
[capture]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-capture-replacement-001/linux-010/summary.json
