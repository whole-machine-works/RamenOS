# Editor runner storage and frame IO observations

This is CI preparation and diagnostic work for PR76, not a change to editor
behavior or a claim that either earlier failure's cause is fixed. Complete
hosted qualification is independently accepted at the exact code revision below.

## Retained failure

[Run42367071792](https://github.com/whole-machine-works/RamenOS/actions/runs/42367071792)
at source2f2d9e3764205dc10bab8c7d9dfa81fb833c717f passed six checks,
56 of57 canonical stages, all eight preservation stages and all57 new trace
controls. The runtime's PublicThirtyFamilies command selected42 tests:
18 passed and24 failed. Its first failure was D09 cursor/selection during a
reference frame export; the other23 failures followed the retained incomplete
reservation. The reference frame37 was created with zero bytes. The generic
RecordingError discarded the original IO operation/errno. Later, during artifact
upload, the runner reported zero MB free disk space. This supports investigating
storage pressure but does not prove ENOSPC or identify the failed suboperation.

Both cache restores missed. The retained runtime archive expands to more than
5GB; this is an archive total, not measured simultaneous runner disk usage.
Fresh compiler targets were also present. There is no evidence of stale restored
cache bloat. All eight available ZIP digests and57,920 members were independently
audited; no missing later stage is counted as passed. Audit:
`evidence/run0-c1-c2-next-20261107/hosted-pr76-final-audit-001/disposition.json`,
SHA256 `efed40c6737e728f4e1dc5ffd4a01077bfc83da7deb21853f8d43f5fe2ac01f7`.

## Changed preparation and diagnostics

The editor job retains its standard hosted runner. GitHub documents
[14GB storage for standard public Ubuntu runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
The official image installs unused SDKs at
[/usr/share/dotnet](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/install-dotnetcore-sdk.sh)
and [/usr/local/lib/android](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/install-android-sdk.sh).
The editor workflow has no .NET or Android consumer. `tools/ci/editor_storage.py`
removes only these two real directories, if present, before setup/cache restore,
after requiring a GitHub-hosted Linux Actions context. It refuses symlink leaves
and accepts no caller removal paths. This is an accidental-use guard in trusted
CI, not a security boundary. No workspace, source, compiler, cache or evidence
path is removed. No minimum free-space threshold or new paid runner is added.

Before/after preparation and before/after the unchanged canonical editor lane,
the job reports actual available bytes/inodes and a bounded summary of the four
existing compiler/output roots. Errors or absent roots are recorded rather than
invented space values. These observations are retained in the job log. The
post-lane report runs on failure too; all existing artifact steps remain intact.
The focused tooling assertions mock every removal; no local SDK removal is run.

The recorder adds bounded, failure-only stderr observations at its six existing
frame-leaf IO error boundaries. It retains the original error API/reasons, actual
nullable errno/error kind, bounded target path and completed-write byte count.
It changes no success-path IO, retry, cleanup, identity check, capacity,
reservation or frame sequence. The existing Linux RLIMIT_FSIZE partial-write
control checks a genuine EFBIG observation, sticky reservation, original error
and successful fresh separate capture. This is not an ENOSPC reproduction.
The exact source registrations were refreshed and included in full qualification.

## Qualification

Independent source review and
[run 42372873439](https://github.com/whole-machine-works/RamenOS/actions/runs/42372873439),
attempt 1, qualify code revision `dbbb8e0b3ebe9df58d80ce539b1af96cefe844fe`.
All nine checks passed. The independent audit verifies all 57 canonical stages,
eight preservation stages, six Linux prerequisite controls, all 57 new trace
controls and 55 runtime probes, with 244 recording runs and three Cargo-bound
archived binaries. The audit is
`evidence/run0-c1-c2-next-20261107/hosted-pr76-diagnostic-candidate-audit-001/disposition.json`,
SHA256 `3f3a9a3c6ed66a3e0de35dbf1cdbf0e22de19b822e9cae9029998a8357ffedd4`.

Both earlier failed runs and all sixteen prior ZIPs remain unchanged. No
unchanged retry, deadline increase, skipped assertion, reduced recording or
duplicate full local campaign supplied this result. It does not establish either
original cause. PR76 is open and ready for separate A3 review, not merged; main
remains `2688f245`. This documentation closeout records the tested code and does
not claim a new execution on its prose successor. The included queue update is
an executable CI input and requires a separate complete hosted Foundry run under
the unchanged classification; no validation exception is introduced.

## Separate agent-runner failure

[Changed-candidate run42370785508](https://github.com/whole-machine-works/RamenOS/actions/runs/42370785508)
failed the existing agent-backend request7 success assertion after Docker create
timed out without a confirmed container ID. The backend's IO/poisoning and
reconciliation requirement are correct. Earlier Linux controls had already run
real validators in that same job, so daemon cold start is not established.
Disk pressure, scheduling and daemon storage/locking are also unproved. This
failure is separate from the editor-runner storage observation. Native worker,
backend, sandbox, test semantics and original 2,500ms budget remain unchanged.

The narrow follow-up adds `agent_runner_diagnostics.py` before the unchanged
canonical agent lane: it records the actual UTC/monotonic interval and fixed
bounded OS resource observations, with no Docker warm-up or subprocess.
Only after a failed lane does it collect two finite read-only queries: recent
Docker/containerd journal entries and container events within the recorded UTC
interval. The unchanged owned-command runner supervises five seconds of work
per query; fixed `prlimit` bounds each stdout/stderr file to262144 bytes. Missing
tools, permissions, clock reversal, truncation and timeouts are observations,
never acceptance or evidence that no late event occurred. Diagnostics cannot
replace the original failed lane status. Raw Linux-control records are uploaded
alongside the new observations and existing timing artifacts.

These stage-wide observations can reveal a named daemon error or retained event;
they do not locate an event inside the request's actual create interval.
No source fix for the underlying stall, extra budget, reused container, weakened
success assertion or stale-image accommodation is claimed. The original failed
run remains retained. The observation packet has independent source review and
the complete hosted qualification above. Its begin record and raw Linux-control
records were retained. Because the agent lane passed, the failure-only step was
skipped: no live journal/event queries, query-history completeness, absence proof
or cause finding is claimed. Full same-VM C0/C1/C2 capture and live I1 remain
separate unfinished work. Independent boot preparation retains its existing
priority; the pending recovery-benefit criterion choice holds further live I1,
update and performance experiments without blocking that boot work.
