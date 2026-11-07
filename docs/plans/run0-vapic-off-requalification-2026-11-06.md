# RUN0 SATA/VAPIC-disabled profile requalification

The user-approved successor disables VAPIC as well as SATA. Its exact invocation
is `q35-8.2-tcg-qemu64-virtio-ro-esp-debugcon-sata-vapic-off-v0`: the machine
remains `pc-q35-8.2,accel=tcg,sata=off`, with the single added pair
`-global apic.vapic=off`. Firmware, EFI and ESP pins are unchanged. The original
and SATA-only profiles remain supported with their original exact pins and argv.
This packet qualifies the successor's prior entry hint and reset prerequisites;
it does not establish live C0 or global device/work quiescence.

The nine source/test changes were prepared against
`6342f233d4cbbb9d6e56fe4b00ec94f850e5ea3b`. Independent source review, exact
plan review and coordinator authorization preceded one diagnostic, one CAP1
reset and one separate host reset witness. After independent diagnostic review,
the reviewed evidence-only assembly helper ran once. The source, plans, raw
artifacts, failed controls and reviews are retained in the Whole Machine Works
workspace under `evidence/run0-vapic-off-20261106`; the remote originals are
under `bigman:/tmp/wmw-vapic-TFoLSBig`.

## Accepted behavior and evidence

All 217 trace controls passed on Linux CPython 3.14.6. macOS CPython 3.14.8 ran
the same 217 controls, passing 215 with the two existing Linux-only skips.
The non-author source reviewer separately passed 39 affected CAP1/C0 controls.
The retained RED/green controls include rejection of AHCI or `kvmvapic` in either
current C0 memory view, as well as the prior CAP1 view. Full selected argv binds
the distinct profile during replay. Host runtime checks retain the existing
static exclusions and check module-bundle absence at the actual launch root.
The exact-source manifest covers all 22 trace source/test dependencies. These
focused checks do not substitute for integration qualification of changed source.

| Actual run | Accepted evidence |
| --- | --- |
| `probe-001` — 8 files | The complete 10,113-byte diagnostic contains one matching loader record on line 146. Exact EFI bytes reproduce loaded base `508690432`, entry `508698768` and the expected 32 entry bytes. All nine QMP operations bind to raw traffic. One permitted boot resume is followed by acknowledged quit, actual zero exit without signals and five EOFs. |
| `cap1-001` — 85 files | Ten QMP and twenty RSP operations bind to complete raw frames. One realized CPU has 40 physical address bits; the register payload and HMP view agree. Physical-mode replies are `0`, `OK`, `1`. Both status observations remain `prelaunch`; no resume or guest-memory read occurs. Actual zero exit and six EOFs are retained. |
| `witness-001` — 42 files | Independent offline host replay passes with the unchanged 14-read/104-byte budget. Both maps snapshots are identical: 74,689 bytes and 701 rows. Reset `hflags=64`, `hflags2=257`, CPL 0, CS64/LMA false and no NPT/SVM-guest/SMM satisfy the retained witness. All four actual waits exit zero and all eleven streams reach EOF; there is no RSP connection or resume. |

The diagnostic and CAP1 reset FlatViews contain neither AHCI nor `kvmvapic`.
All 135 run files match their remote originals byte for byte. The host replay
binds the exact native ABI, source dossier, observer, inputs, argv, metadata,
field wire and cleanup; reset evidence is not a witness at a future entry stop.

The five admission files also match the actual remote originals. Independent
read-only execution of the existing `boot_profile_inputs.admit` reproduces the
retained `ADMIT` result exactly. The pure C0 `_profile_binding` join passes over
35 verified blobs; `_capability_binding` independently passes over 86 verified
blobs in its prior-CAP1 namespace. These are prior-input joins, not full C0 replay.
The candidate remains `prior-run-hint-only`; all seven guest/hardware claims,
`capture_complete`, `profile_preconditions_met`, `fresh_c0_verified`, opaque
profile-semantics, symbols-match and admission ESP/EFI-binding flags remain false.

## Exact identities

All digests below are SHA-256. Paths are relative to the retained evidence root
unless identified as the unchanged ABI/source dossier.

| Identity | Digest |
| --- | --- |
| Raw profile, `staging/profile.new.json` | `ab82f30ae31a03761b39088a4dd96c138203ed7d631909a953bc5224f7403da3` |
| Canonical probe profile | `0239711aa87643c43ac5a0dd251fb446b207c18975b94c40d36ab3618d69b423` |
| Canonical admission profile | `93f0f790656425aaf03c00e554239640bab6aa4e874aa17349efcc667c5164bb` |
| Exact-source manifest, `source.sha256` | `98aeb24c3e2a8a7d9a64f5f5da659b0ef753df10931be14dec1a2fd83b935ccc` |
| Unchanged HostABI | `db5be432574e2d8631059a8a69d421c1163eee60c51fb61d7c358e2bb271aa73` |
| Unchanged source dossier | `f2dbb099816cc1dfad09f2ea2a938c4127a63e7985f8c363070ecab590973db9` |
| `probe-plan.json` | `3788b8e9da254e2ffcc034db3ad29ae2a969824ae1690d409f5fcaae2a087097` |
| `cap-plan.json` | `c004fe5008a92a40964f9294de92a987f5f64482b604183fb73a2d2599658ce2` |
| `host-plan.json` | `666fe5418ac2d95874e602cb685ac76726dcf100db3d146ace04679c24452e7b` |
| `probe-001/report.json` | `5ad1725752c493c451d353dcfad57d38fb658e5a8ca2de5ac19652bda85db9f0` |
| `cap1-001/report.json` | `2898a3b833dcbeb2eb38df1cd59de05566d0c16164af946b444f831f4413e48e` |
| `witness-001/report.json` | `c2af59627800984cc148121b509dad0a309c3062ef1570e25dc5430ee5667752` |
| `staging/prepare_admission.py` | `6e999044fff94b4d6e6f70494164b3fae288dff263f4dc999dea3313dc6a0064` |
| `admission/packet.json` | `ff6ed6545c3c4a29d09802b6e78fd93b7a1b7fbc498f8642f8cff0caf3ccc557` |
| `admission/mapping.json` | `ba51f6d6d1fe523ab4fc5cd2e7485dc4e008afd5edf5b5cd4f8b291ed05f0923` |
| `admission/result.json` | `f05f0d23bd00b29a8bcbbcf8b580cabdac1f9402febd2675bcc2b2384a80ff12` |

The following independent reviews have no unresolved findings within their
named scopes. The runtime directory is `review/runtime-evidence-001/`.

| Review | Digest |
| --- | --- |
| `source-review.json` | `358a2268f33f357aefa2b9a07c1b45da091f3d0cc05af74bf8ee7254535ec763` |
| `review/plan-review-002/review.json` | `e130baf509798e65cc9d34102a22b41013b84c4d8fc8f51e5b3d9acc2cc7eccd` |
| Runtime `probe-review.json` | `8620d8a0874c3e2c57fe5ca4ca4c5e7aa871d4b071f9000498521efb6913d80e` |
| Runtime `review.json` — CAP1 and host | `493d7a81a74d947fe106c11cae964fab66ee2268361070362942703d8f7f2c66` |
| Runtime `remote-identity.json` | `80f1152b54d0ef519d2ef6a04ff1bd0365e491b89be604f503d2f8c0bea876cb` |
| Runtime `capability-binding.json` | `3940329f25237530649ee13d805e92bd6745a7fd108d09b79a97b6c8084e9dcb` |
| Runtime `admission-review.json` | `fcfb8777db697d685c635eeb6e8bd5219c6101db566b84ed2ebf4711c44ecc6f` |

## Next dependency

Keep [entry preparation](run0-relocated-entry-preparation-v0.md), the
[C0 inspection plan](run0-c0-inspection-v0.md) and their existing authority and
budget limits. Freeze the admitted-entry breakpoint and asynchronous stop
interface before parallel transport and RAM-acquisition implementation. The
successor also needs a source-derived, exact-profile RTC policy: its actual
diagnostic carries `/machine/unattached/device[1]/rtc`, while the existing
shared-C0 contract pins `device[2]`. Preserve the older profiles' policy and
derive the third profile's closed rule from pinned source and complete raw
events; the reset result does not silently change that contract.

Before a guest-memory request, the live collector needs a fresh host witness
within that same stop and reviewed source closure for ordinary-RAM persistence,
including remaining asynchronous/global work. Removing two devices and seeing
equal snapshots does not prove that closure. Qualify bounded C0 acquisition and
replay, then the same-call C1/C2 capture and subsequent guest-access work.
All prior failures and profiles remain retained. This packet neither explains
historical editor/IPC failures nor establishes firmware exit, retained-range
completion, allocator installation, target execution or physical acceptance.
