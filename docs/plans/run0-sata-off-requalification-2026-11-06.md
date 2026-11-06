# RUN0 SATA-disabled profile requalification

The previous C0 persistence review identified queued AHCI work as an open
condition. The selected profile changes the QEMU machine argument to
`pc-q35-8.2,accel=tcg,sata=off`. The firmware, EFI and ESP bytes retain their
existing pins. The exact original profile remains supported for replay.

| Identity | Value |
| --- | --- |
| Invocation | `q35-8.2-tcg-qemu64-virtio-ro-esp-debugcon-sata-off-v0` |
| Raw profile SHA-256 | `b3c4bd6caa30641a0f1859f4fbc88cad64254f602c7190108cb223ff0c32feef` |
| Entry-input profile SHA-256 | `5ec9eee368903aad508d686d0aa21a2b3ca322f5434f7427c228cbd2484878e9` |
| DEBUG probe report SHA-256 | `24ca66ee8514b902d75fa7f06d297ef7743bd033db5267e23f0a59c41e728d4c` |
| Entry admission SHA-256 | `2cc84be26d150545c898e8190faf6bb7cfe8e6ef861df40e3b9062fd9a21c90c` |
| CAP1 reset report SHA-256 | `043e3baa58e04efcaf4c2ddd7af5b0c2a9ea0752de81b91ed574f8211394d623` |
| Host reset witness report SHA-256 | `eb82fd524cad83b432b4103b7bc831d1b78270145fa43ac71b1991e725b7179d` |

The DEBUG probe and CAP1 reset FlatViews contain no AHCI region. The DEBUG probe
produced a single matching loader record on line 146 of the complete 10,113-byte
diagnostic. The input helper admitted its prior entry candidate `508698768`
with loaded base `508690432`. The original profile had a different candidate.
The probe reached five stream EOFs and QEMU exited zero without signals.

CAP1 and the host CPU witness ran on separate owned VMs held at reset. CAP1
passed its existing debugger controls. The host witness passed with 14 reads
totaling 104 bytes and a retained clean exit. The first host preflight denied
the old module-bundle absence receipt because it named the original input
directory. The new path checks the actual launch input directory and requires
that exact absence in replay. The original absence rules remain in effect for
the original profile.

The full trace suite passed 166 tests on Linux and 164 on macOS with two
Linux-only skips. Saved DEBUG and CAP1 argv are now checked against the full
selected invocation during offline replay. The cross-profile tests cover old
argv substitution at both joins. Evidence, launch plans and review records are
retained under `evidence/run0-sata-off-20261106` in the Whole Machine Works
workspace.

The next packet needs a fresh same-stop C0 host witness and bounded live
transport and RAM acquisition. The event policy needs to account for the two
`RTC_CHANGE` events observed during the diagnostic boot. Live C0, firmware exit
and target guest-access evidence remain pending.
