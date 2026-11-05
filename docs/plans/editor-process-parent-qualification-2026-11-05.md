# Linux editor parent and Core qualification — 2026-11-05

This packet records independently reviewed, focused Linux behavior on immutable
candidates **002, 013 and 022**. It supports review of the parent carrier,
genuine Core integration and selected application/Store recovery flows on
`codex/editor-process-p0-p3`, draft [PR 52](https://github.com/whole-machine-works/RamenOS/pull/52).
It does **not** accept the complete P0–P3 workflow. At this packet's 022
acceptance boundary, D15 and D16 successors awaited candidate 023; their later
receipts belong to the continuing delivery record. Full thirty-family execution,
the complete 57-stage preflight, final-candidate qualification and repository
integration are outside this packet's acceptance.

The [delivery record](editor-process-delivery-2026-11-04.md) owns continuation and
integration. The [child qualification](editor-process-child-qualification-2026-11-05.md)
separately records synthetic child protocol/data evidence. Its child counts do
not become genuine parent/Core/Store workflow results here.

## Immutable source and executable identities

Each source manifest contains actual file lengths and SHA-256 values. These are
three different tested source snapshots, not interchangeable receipts for the
current working tree. Builds used the repository-pinned `nightly-2026-02-08` on
Linux x86_64. Candidate 002 records caller umask `022`; the earlier 001 recorder
failure under permissive permissions remains a failed attempt, not a pass.

| Candidate / source rows | Source manifest SHA-256 | Retained command index SHA-256 |
| --- | --- | --- |
| [002 / 855][source002] | `7debc4c10c35f8d54b7de6fdb6336e2f96cad799478c495842cdda66d14f0dd4` | [002 summary][summary002]: `8e62119cb66b30cb6a6f5f80b8ee3c5e3df4bc131e1d99a934ecdcdddcc43805` |
| [013 / 869][source013] | `40a46b065f6c4536a7c11763de938365c0ff136e851c110c56791cccd04fb8bc` | [013 summary][summary013]: `a34d57dfd3027d2a6859f856b8c4f30b56dcaae705be80e2f1401eadded853af` |
| [022 / 872][source022] | `11c00e4a2eca0b345780fbb3d356e17ca820c0ca923aecfcecd3069d9cbbf25d` | [022 summary][summary022]: `3631bd1b8e9d16982667c717196c751af79460019f2838a1a29946b5dc70f732` |

| Candidate | Production child ELF SHA-256 | Parent test ELF SHA-256 |
| --- | --- | --- |
| 002 | `0ae7ce2903c6988ca502fc8994dd02dbff06414d229c3de331d5f4c964686a82` | `a88fafe98e2fdfddfa933fe5b019ba31f7bf0bfaa67344a899a4052dc9036647` (`process-task`) |
| 013 | `440a0b23a599e78c617949ae29d18967da8a1542145522ada12d62e9de195eea` | `e39b63de793b3d3967c98faa418ba41c52e81fcce235d485a48aae341dedebcd` (`process-task`) |
| 022 | `79545ee37956d7b73ce0f0e00315e3bc29c0152e117beac0495ff249948e6a0f` | `19028b4c7f782a11203e6c89a342312d3c8a7e9cf6f5674996060b0c0b5264db` (`process-task`); `2fa99d939bfe1477d276ab4f578ad6a17659761ebf0e00ac65effd83c3516332` (`app-tests`) |

The supplemental assertion children are distinct artifacts: 013
`0bbda10771deee993d1eacd0bc6a02d634db97f52b2205d7597cdf9460083e03`,
and 022 `fbca12d4a723628e7be65dc46c968d6ed586e74916e30ceaef54c3cf0c37bbf1`.
Normal production-child evidence is not inferred from the assertion artifact.
The [retained 013 parent ELF][parent013] was independently hashed to the value
above. Its [Cargo JSON][parent-build013] selects the actual `process_task` test
binary with `host_editor_process_assertions_v0_dev`; the [build command receipt][parent-command013]
records exit zero and actual reap. Their respective SHA-256 values are
`f804820bc5e1cfb6a233a54f5680c497353540e7b933af2f8d703357e415ba19`
and `09887aee94024baf51eed464c7be769e2de1b5929b0954a37ee50cb206106320`.
The 002 and 022 retained executable bytes were also independently hashed.
The 013 and 022 lockfile before/after hash is
`8495485fb5d3b0aa5c02a60634d0c05e212650cdc4412af1ff55cea3a7112ad0`.
The [013 gate record][gate013] hashes to
`d338df472e2748e7fc24d3d1bc664a87ec07929ff039e6fab7296c8ed86edf72`;
the [022 gate record][gate022] hashes to
`59bcb41949b3301d18a6a201fb850fa8150f8bf49cbf626db93c104e5eeb22b7`.
These partial records do not imply all required gate probes ran successfully.

## Accepted parent and Core behavior

Candidate 002 built the production child with
`--locked --no-default-features --features host_editor_process_child_v0_dev`,
and built `process_task` with `host_editor_process_v0_dev`. Its actual
`process-task process_p0_ --test-threads=1 --nocapture` invocation exited zero,
was reaped, and completed in 400,996,544 ns. The [four-consumer output][output002]
checks genuine approved Read enrollment, fencing of legacy aliases and repeated
Read extraction, actual child editing/raster publication, single-use genuine
Ctrl-S capture, and consuming join returning the live owner promptly until
actual native exit and supervisor join permit cleanup. It released P3 authoring;
it did not accept the unimplemented fault inventory at that time.

On 013, the following exact `full_assertions::` tests each selected one test,
exited zero and were reaped. Their receipts retain the actual executable argv,
serial test invocation, deadlines and process-group cleanup facts.

| Exact test suffix | Elapsed ns | Command receipt SHA-256 |
| --- | --- | --- |
| [process_d04_actual_sender_credentials_not_bootstrap_pid][d04] | 2,655,832,213 | `0856cbc58e32980c84ac78657519bbdc2c565c19a575e1f0dcad23625db5e75d` |
| [process_d23_actual_fault_fresh_restart_approval][d23] | 2,054,404,895 | `3527ba9e730f93ccdcbf7840b64ce847b1f4080796d177f51d991a200d13a6b4` |
| [process_d26_revoke_fences_unpermitted_publication_preserves_permit][d26] | 2,254,895,626 | `fb9d5c192d2bf1536085942fd32651c1eda0a73b05d5ad2f7541c305a71d6571` |
| [process_d27_focus_compositor_service_reset_and_reserved_reset][d27] | 2,656,318,774 | `d22974c0bf0161a16d2fe769561de6d50866c4bd0024054d9ace59857048aa37` |

D04 binds actual native receive credentials to the approved child and rejects
foreign senders. Fork-only assertion helpers have separate actual fork/birth,
wait and Rust-thread join provenance; they do not claim execution of a child ELF.
Parser-only ancillary refusals are explicitly structural diagnostics, with no
invented native receive, FD ownership or errno.

D23 exercises a real child fault, terminal ownership and fresh approved recovery.
Retired Bootstrap history is separate descriptive evidence from a genuinely
joined old owner; replay to a fresh child cannot become a new grant. D26 exercises
actual Core revocation and denial of late publication with retained child/FD
ownership. Core revocation and child reap do not themselves settle an already
issued Store permit. D27 exercises real focus/service/compositor transitions,
old-generation refusal and reserved Reset behavior. The stale-surface check uses
actual Core epoch/frame retirement and a valid owned pair, rather than substituting
an unrelated-inode failure. These are focused family passes on 013; other failed
or unexecuted families in that candidate remain outside acceptance.

## Accepted application and Store behavior on 022

| Exact selected test / command | Elapsed ns | Command receipt SHA-256 |
| --- | --- | --- |
| [full_assertions::process_d09_cursor_selection_scroll_exact_state_pixels][d09] | 7,064,568,268 | `97a3c50f248acb01d9b9c123b68cd6cb093d5b9e07b4cbd0160d5bda17dd5868` |
| [native::process_assertions::process_d17_genuine_ctrl_s_full_receipt_and_reopen][d17] | 3,056,148,923 | `982e63c5624811a232c0c883373650624a0c1ce907607462195807c8e5956074` |
| [native::process_assertions::process_d21_child_death_before_permit_retains_known_allocation][d21] | 7,014,663,542 | `63968b8d456e87614e792e2c5c1229c91e411321d7897cac717d0c973987a111` |
| [cargo test --locked -p store_service --features editor_native_save_v0_dev --test editor_unpermitted_commit_closure -- --test-threads=1 --nocapture][store] | 10,473,086,810 | `66d7df7d6830481d0cac8eea0f7890d82778f20afdd9d3ff5123b3a9d72eb564` |

All four command receipts record zero exit and actual reap. D09 preserves every
explicit process/reference Core composition and full app-area pixel comparison
(rows 48 through 527), alongside cursor, selection, scrolling and text/view
observations. The legacy reference owns a separate genuinely approved Host; both
Hosts retain their unchanged Core composition limit. Removing redundant automatic
composition did not remove the per-step golden comparison or reset a quota.

D17 uses a genuine Core Ctrl-S dequeue, opaque single-use capture and the common
SaveChains pipeline. Actual Allocate/Commit and full 176-byte receipt validation
precede protected Saved state; a freshly approved child reads the committed
revision. Copied child observations do not mint a Save intent or receipt.

D21 retains a known allocation and both authentic original operation owners when
the child dies before Commit permission. Its late-publication case queues a real
publication, then fences Core and performs actual native death/wait and supervisor
join before receiving and strictly verifying the retained pair. Actual Core
adoption is refused as `Stale` after death. The [retained late-publication
metadata][late022] binds native wait index 2537 to later receive index 2551,
actual child PID 1506719/birth 290472853, `Signaled(9)`, real supervisor join,
credentials `[1506719, 1000, 1000]` and received descriptor IDs 36/37. The
admission, child, capture and Save deadlines remain unchanged across the decision.
Its metadata SHA-256 is
`a8064666af9f84e113c11f82790a320cb55b685db9743b2ff45c20ba94c6a127`.
A cached joined result supports cleanup retry
without a second join; failed cleanup remains retained or quarantined.

The Store closure path distinguishes **the old unpermitted operation's genuine
noncommit** from the **fresh authorized operation's actual Commit**. Child death
or a timeout does not manufacture NoAllocation, release the original or refund
its authority. The [two authentic Store tests][store-output] require the deadline,
actual producer joins for both original claims, q9 disk readback and the typed
`unpermitted_commit_closed()` witness. `allocation_closed()` remains false for
the bound Commit case. The issued-permit negative test proves that actual permit
issuance cannot yield this unpermitted closure witness. Subsequent genuine Ctrl-S
Save and fresh child progress remain part of the application flow.
The [final Store record for the closure/reopen case][closure022] retains old
operation 1 with no permit and `definitive_noncommit`, then operation 2 with
a permit and `committed`: selected revision 2, exactly one permit and one
transition. Its SHA-256 is
`37bc785fc147cde0ff99869ebd07924cd8428de524bf1b3192d1bfa1a8fa282b`.

## Recording, native ownership and claim boundaries

The [independent 022 audit][audit022] (`ACCEPTED_SCOPED_BEHAVIOR_RECEIPTS`)
accepted all **872 source-manifest rows**, the retained
**20 Run leaves / 197 files / 95,723,396 bytes / 1,452 control rows**, and
**1,368 raw parent references**. These are corpus integrity quantities, not a
count of passing behavior cases. The corpus includes the retained D15 and D16
failures. The audit SHA-256 is
`a056241c238545b4fb62d41e8c646b210996257252f4dbb7693f8392fc1d008c`.
Its separate [retained evidence inventory][inventory022] covers 1,203 regular
files and hashes to
`25c80773072a1c33f4a5720b193b8f9c227a03779127b3102617c53284fa476b`;
this larger inventory also includes builds, parent IO and failed-case artifacts.
Its process and parent recording nonces are both
`e212f72466a91819f5a97fb0dcca89c7`; 013 uses
`1f1ef3f672edcbb84af071a1353dfc1b`.

`RECORDING_COMPLETE` establishes bounded file, hash, source, scope and raw-reference
closure. It does not establish runtime acceptance. Actual kernel credential,
FD/inode/seal/map and syscall records are distinct from parser-only observations.
Actual wait status and the sole supervisor's Rust join are distinct from Store
producer joins and semantic original-operation closure. Sibling and retired-owner
proofs remain separately scoped; the primary supervisor never claims their waits.
Parent IO joins use the same candidate source, case and Root nonce, and retain
actual raw bytes and hashes. Existing reader suites retain their own identity;
they are not relabeled as new process tests.

These are default-off Linux host-development results. They do not establish
native OS deployment, sandbox containment, metal/HIL graduation or release
readiness. Held main-ELF identity does not attest the dynamic loader or libraries.
The fixed source snapshots and their scoped review cannot substitute for a fresh
final-candidate all-family run, unchanged-consumer gates, complete acceptance and
independent integration review.

[source002]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-snapshots/carrier-runtime-002/source.json
[source013]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-snapshots/integrated-faults-013/source.json
[source022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-snapshots/terminal-closure-022/source.json
[summary002]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-carrier-runtime-002/summary.json
[summary013]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/summary.json
[summary022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/summary.json
[gate013]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/gate-record.json
[gate022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/gate-record.json
[output002]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-carrier-runtime-002/baseline.stdout
[d04]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/process_d04_actual_sender_credentials_not_bootstrap_pid.command.json
[d23]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/process_d23_actual_fault_fresh_restart_approval.command.json
[d26]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/process_d26_revoke_fences_unpermitted_publication_preserves_permit.command.json
[d27]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-p2-successor-013-001/from-root-013/process_d27_focus_compositor_service_reset_and_reserved_reset.command.json
[d09]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/process_d09_cursor_selection_scroll_exact_state_pixels.command.json
[d17]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/process_d17_genuine_ctrl_s_full_receipt_and_reopen.command.json
[d21]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/process_d21_child_death_before_permit_retains_known_allocation.command.json
[store]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/authentic-closure-tests.command.json
[store-output]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/authentic-closure-tests.stdout
[audit022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-review-022-kxenv930/audit.json
[inventory022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-review-022-kxenv930/evidence-inventory.json
[late022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/process-io/app_d21publicationafterdeath/D21PublicationAfterDeath-8/metadata.json
[closure022]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-022-reviewed-behaviors/parent-io/app_d21genuineunpermittedclosurethenapprovedchild/process_preparation/0/store-epoch-0-snapshot-1.json
[parent013]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/process-task
[parent-build013]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/app-build.stdout
[parent-command013]: /Users/maxwell/projects/whole-machine-works/RamenOS/out/p0-p3-parent-qualification-013-receipts/app-build.command.json
