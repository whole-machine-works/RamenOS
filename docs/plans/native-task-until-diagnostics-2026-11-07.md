# Native task timeout diagnostics

The corrected PR75 hosted run reached the original native task capacity case
and timed out in `Fixture::until`. Retained frames locate it at history Save47:
object103's fifteenth Save, requesting revision16. The preceding46 Saves
published successfully. The failed Save's actual operation ID, admission,
phase and producer state were not recorded. Its cause remains unknown.

Run42363115429 tested `28e1999dc50e8f65c165db0499199970220fa012`.
All274 retained source-manifest entries match that head. Both this failure and
the preceding policy failure in run42361545118 are preserved with every
available archive and verified ZIP digest. Neither run supplies complete
qualification for this candidate. The policy failure was separately repaired;
it does not explain the Save timeout.

## Implemented observation

The test helper now retains its same-iteration editor observation. Only after
the original1500ms deadline expires, it attempts bounded JSON diagnostics and
the existing Store `final_before_cleanup` snapshot before the original panic.
The record includes the actual matching-session chrome or its explicit error,
producer counts, authenticated join observations and retained join IDs. It
marks acceptance and quiescence false. A joined boolean includes possible
panicked producers and supplies no success or authority proof.

The branch performs no reconciliation, resend, join, fence or cleanup. Normal
step/observe/predicate order, deadline, panic text and successful-path recording
remain unchanged. Diagnostic failures are caught; they cannot replace the
original timeout. Existing Store snapshot limits apply, and compact diagnostic
output is capped at64KiB. No failed native operation number is inferred from
the source-planned iteration.

The instrumentation changes one Rust file,
`apps/artifact_editor/tests/native_task_support/mod.rs`, SHA256
`f25607edb5a5f8f4ee31868ad5a3778f865bb8929648fd7a8ea9e69a14dace91`.
Four coordinator registration files separately bind its reviewed length/hash
and direct containing-file hashes. Their independent review preserves every
other field and guard. Canonical eighteen test names, recording scenarios,
admission profiles, deadlines and assertions are unchanged.

## Evidence and next execution

Locked host compilation, strict Clippy and formatting pass. An isolated host
fixture control demonstrates the missing Store snapshot on the preceding
source, then the candidate's original timeout/panic and retained snapshot.
Actual stale chrome is recorded as an error. A second control records genuine
chrome248 after Saved and forces a recorder failure without replacing the
original panic. Both controls then complete a fresh genuine Save in a separate
fixture. These are Darwin host controls, not Linux capacity reproduction.

Workspace evidence is under
`evidence/recovery-q1-t2-preparation-20261107/`. Author handoff
`pr75-until-diagnostics-author-018/handoff-001.json` is
`b770d8ace829dc6ab2009ed2de7fc5182aae4e16304247f5611ac5f98e0e71ef`;
distinct source review `pr75-until-diagnostics-review-019/disposition.json` is
`0e761f81072f14fd831564e4bafd4e0c4fee24f95e785682f8503daddba1f4ea`.
Registration review `pr75-assertion-registration-review-022/disposition.json` is
`80e99b30962e4a3d487ff8ccdb02857af6f9150385b80aabb7618c8c10a9c6f5`.
The source-bound failure diagnosis is
`cfca36f918dc1d7bdba28002b613acf189e99cb5bd4d6a3a4bb89b206bda301c`.

The coordinator must release the fixed candidate's ordinary hosted CI plan
before another Linux observation. Reuse the existing guarded build and exact
test-executable/source admission, all original deadlines and every check.
Retain any new failure and its actual operation/owner state. This diagnostic
packet establishes no timeout fix, successful Linux repetition, earlier D19
cause, full P0-P3 requalification, target durability or release authority.
