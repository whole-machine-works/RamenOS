# RUN0 host CPU witness result

The owned Linux reset capture passed independent runtime evidence review.
The collector verified the selected CPU's host state while QEMU reported
`prelaunch` in both QMP brackets. It used the exact pinned DEBUG inputs and
reviewed HostABI dossier. The guest stayed paused throughout the capture.

| Evidence | Result |
| --- | --- |
| Run and finalized report | `reset-002`, SHA-256 `ac8219829a40636fd5bf3b189f84624bca4728e59cf747880c53e407e72295fd` |
| HostABI | `db5be432574e2d8631059a8a69d421c1163eee60c51fb61d7c358e2bb271aa73` |
| Authorized plan | `c376805032a174de32e853045e305fd3b0de743ce6be1b1b7efd2d86f836bf80` |
| Observed fields | 14 reads and 104 bytes, all complete and repeated as required |
| Reset state | CPL 0, CS64 and LMA clear, NPT, SVM guest and SMM inactive |
| Lifecycle | QEMU and three helpers exited zero and were reaped. All 11 required streams reached EOF without errors. |
| Raw review | 42 retained files verified and the production validator replayed the report as `PASS / retained_runtime`. |

The first run stopped when proc maps reached 65,536 bytes before EOF. The
metadata helper and QEMU were both reaped. The collector never opened the
process-memory descriptor in that attempt. The reviewed
[maps bound amendment](../contracts/run0-host-cpu-metadata-bound-v0.json) raised
the maps byte cap to 131,072 and kept the 1,024-row and aggregate limits. The
second run captured 74,881 bytes across 704 rows in each maps snapshot.
The complete first and second run artifacts are retained separately in the
Whole Machine Works workspace under `evidence/run0-cpu-witness-20261106`.

The [host witness plan](run0-host-cpu-witness-v0.md) defines the read and
process boundaries. The [offline decoder contract](../contracts/run0-c0-decoder-v0.json)
and [shared control amendment](../contracts/run0-shared-c0-control-v0.json)
govern future same-stop C0 evidence. All 16 decoder controls passed on Linux
and macOS, including a complete synthetic report with real replay through the
production validator. The final Linux reset candidate passed all 109 RUN0
controls.

The next executable packet is the fresh C0 collector. It needs a reviewed
typed RSP session, admission before each guest physical-memory read and the
host witness inside that same stop. Reuse the exact profile, firmware, prior
entry hint and decoder. This reset evidence supplies the owned reader proof.
Fresh C0 and same-call C1/C2 still require separate live qualification.
