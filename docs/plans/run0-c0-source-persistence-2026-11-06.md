# C0 source persistence condition — SATA/VAPIC-disabled profile

The source follow-up conditionally accepts mapping and architectural-state
persistence for the exact authenticated Ubuntu QEMU `1:8.2.2+ds-0ubuntu1.18`
profile `q35-8.2-tcg-qemu64-virtio-ro-esp-debugcon-sata-vapic-off-v0`.
Its canonical probe digest is
`0239711aa87643c43ac5a0dd251fb446b207c18975b94c40d36ab3618d69b423`.
The [requalification record](run0-vapic-off-requalification-2026-11-06.md)
retains the prior diagnostic, admission, CAP1 and reset evidence separately.

The accepted earlier controller and stop/drain reviews excluded ordinary
virtio completion/DMA after the stop routine returns and proved that admitted
in-band monitor/GDB commands cannot run inside its nested block drain. AHCI
and VAPIC construction are excluded by the new profile and their absence is
observed in its actual reset memory views. This follow-up closes the remaining
queued/in-flight CPU callback question using a finite source inventory.

Remaining TCG callbacks flush implementation TLB/TB caches, perform empty
synchronization callbacks or throttle. A real deferred callback,
`tcg_commit_cpu`, updates `CPUAddressSpace.memory_dispatch` to the already
published current dispatch and flushes TLBs. It does not publish another
FlatView or change architectural page-walk inputs. Physical RSP reads use
global `address_space_memory`; the manual page walk uses captured architectural
state and those physical reads. Neither consumes the CPU implementation cache.
The inventory also reviews direct A20/interrupt/reset paths and excludes
VAPIC, other accelerators, Hyper-V, plugins and injected-MCE history under the
exact fresh launch and frozen observer commands.

This is a profile-specific source condition. Queued work may still run.
It establishes neither global quiescence nor an atomic RAM-content snapshot.

## Conditions that the collector must still prove

- Bind this exact executable/profile and fresh owned launch. Add no device,
  plugin, migration/replay, config writer, reset/load or extra resume.
- Bind the actual permitted breakpoint stop and completed stop/drain interval,
  then fresh current C0 CPU/host state, including the required architectural
  paging inputs and absence of SMM/SVM/nested translation.
- Admit each entire typed physical request as ordinary `pc.ram` from the
  current C0 global FlatView. Preserve physical mode, budgets and all before/after
  identity, state and event checks. Prior reset values cannot supply this proof.
- Fail closed if the profile, stop, current state/view or command history
  differs. No source conclusion by itself releases a live read.

## Retained source and independent review

The Whole Machine Works workspace retains the exact full callback search,
numbered source excerpts and hashes for 24 inspected files under
`evidence/run0-vapic-off-20261106/persistence-followup.*`. The authenticated
patched tree is retained at
`bigman:/tmp/wmw-rsp-ipc-pB6u3SJF/qemu-source/patched`.

| Record | SHA-256 |
| --- | --- |
| Source analysis, `persistence-followup.md` | `021374b1bccfe724785540cca86fb9448ba6eba729ce0e27e742ef4da495345e` |
| Conditional disposition, `persistence-followup.json` | `d2b1bcd4e5f7318b587a02c15576fb54097fe379a00fed6be53cff61c3962ad9` |
| Full inventory/excerpts, `persistence-followup.sources.txt` | `4faaca2267dfeb46e50b785271e5b07cce345d6e3bccb76b5e1feba6e11ddd2a` |
| Source hashes, `persistence-followup.source-hashes.json` | `17c3b61b76cb97f86450312f2b2ef5e3716ed7b3ecab288629b832087a9d4149` |

The non-author coordinator checked the real deferred-dispatch counterexample,
stopped execution gating and direct A20 writers against the retained sources,
and rehashed the supporting input/review records. Its acceptance is retained
in `persistence-coordinator-review.json`. No VM, live fields or guest-memory
acquisition ran for either source review. Actual C0 and C1/C2 remain open.
