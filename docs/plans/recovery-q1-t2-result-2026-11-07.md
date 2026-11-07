# Recovery T2 — accepted Linux fault and fresh-instance result

Independent review accepted one Linux x86_64 run of the frozen T2 module
admission, fuel, stack, trap, nonzero-return and output-fault recipes. The
receiving adapter retained the actual constructor and call outcomes, and every
recipe ended with a separately fresh canonical instance returning the expected
result. This adds bounded technical evidence toward the
[registered recovery comparison](../contracts/recovery-comparison-v1.json).

The 32 recipes produced all 107 ordered phases:

| Observation | Actual result |
| --- | --- |
| Admission rejections | 21: 17 module-shape, two artifact-identity and two locked-engine translation errors (A10 and A21) |
| Fault raw calls | 11, including one fuel trap, one stack trap and one other trap |
| Fault public receiving decisions | 11: fuel, stack, trap and guest return `7` once each; five invalid-output errors; two disagreements |
| Fresh canonical raw calls | 32, each returning `0` with the exact canonical output and guards |
| Fresh public receiving decisions | 32, each `Ok(Committed)` |

The independent audit derived and compared every byte of 43 full before/after
page pairs: **86 pages / 5,636,096 bytes**. It reconstructed the 336-byte input
projections and expected pages from frozen recipe, actor and R0 inputs without
using the observed output as an oracle. The two disagreements retain their
actual candidate/expected dispositions. Admission failures have no fabricated
raw observation. The source and sealed executable support **86 actual recovery
invocations**: 43 raw calls and 43 separate public receiving calls, each using
a fresh Store/Instance. This count is execution evidence, not a performance or
physical resource guarantee.

The [fixture contract](../contracts/recovery-q1-t2-fixture-contract-v1.json),
[result schema](../contracts/recovery-q1-t2-schema-v1.json) and
[manifest](../contracts/recovery-q1-t2-manifest-v1.json) retain the exact recipe,
phase, error, memory and provenance rules. Existing production adapter limits
and earlier R0/C1/T1 receipts remain unchanged.

## Exact execution and review

| Identity | Value |
| --- | --- |
| Executed RamenOS source | `3e30005b9e8d52b9dced2a920d209698fb6f0285` |
| Executed Newcomputer source | `15a3cad1f8dc3962a35a7ee7b5cf29d2b3f58547` |
| Actual Linux executable, 48,158,144 bytes | `8ee0d0654727b450cfd20a36c6c02a84387df3ca2be3b4b1d546fb222945818d` |
| T2 manifest, 1,118 bytes | `9eb988c2a85180db3bf7068270694730fe785960d2aa2413502da46010cc663b` |
| Reviewed external execution plan | `4f962315bcf4a129faab66bcfec3882b6eb504476abf92e15d0891c73cdaa0c7` |
| Execution driver | `1c0fcb8610233f93b9830a87c7edaff2ae2edeb186ed3367c929a7eb0bbc6d68` |
| Raw engine result, 11,328,593 bytes | `2b092b42a0daadb606df9abf276ba63f4ecb9b62ae40ed53db18880da20d3834` |
| Retained verifier verdict | `442e000c5950fe8f531d3c404179fcae3bc62f5fd2070f7bc0425b22b54b63d2` |
| Independent source/static review | `bd07ca378a624ca9e8ae41afdc485d26b2ea85ffbfa3c1ae33bb6de01f0a0fd2` |
| Independent registration-delta review | `4e0b2f90928328fd25e116dd3293b2bc4189b2265709296cb3eac2696cdb180a` |
| Independent pre-execution review | `8ff1260c441294cc1a18cb5879b559facdddf67d2f74e2f263a811f2933ae624` |
| Independent actual-result review | `facf1db350e317976229bd4ed5582e4e67f8000f3296ba9e752fa764f807faf3` |

Evidence is retained outside this repository under the Whole Machine Works
workspace at `evidence/recovery-q1-t2-preparation-20261107/`.
`root-execution-007/actual-output/` contains the raw result, verifier verdict,
commands, pre/post checks and execution summary.
`linux-actual-review-001/disposition.json` records non-author review by
`vapic_off_persistence`, with decision
`ACCEPT_T2_LINUX_ACTUAL_TECHNICAL_EVIDENCE` and no findings. Its independent
retained-byte audit and unchanged-verifier replay did not rerun the campaign.

Pre/post checks and a separate reviewer remote rehash agreed on all **12,584
sealed paths**, including source, generated inputs, tools, private inputs and
the executable. Both execution heads were clean; the six generated RamenOS
files were sealed, with no Newcomputer generated or cache files. The native
command, verifier and outer SSH command each exited zero, completed process
group cleanup and were reaped. The canonical entry was selected once; its
separate start receipt and actual process/result records establish execution.
The immutable attempt marker remains its original reservation snapshot.

Preparation included 24 ordinary Linux T2 controls. The root's selected-control
run covered 44 controls in total: 20 preserved and 24 new substantive controls;
strict Clippy also passed. These source checks and the one reviewed actual run
are separate from **full hosted CI on the final documentation head, which is
pending**. Ordinary CI leaves the ignored canonical campaign unselected.

## Scope and next receiving work

All six retained claims remain false: `full_q1_qualified`,
`full_18_receiving_acceptance`, `owner_lifecycle_exercised`,
`live_parent_authority_exercised`, `measured_benefit` and
`activation_accepted`. Fresh computational instances establish only the recorded
fault and successor behavior. Genuine Store-owner retention, unrelated-session
progress and authority remain receiving work.

The [sequential closeout](recovery-q1-runtime-preparation-2026-11-06.md#sequential-closeout)
keeps full Q1, complete acceptance of all 18 obligations, I1 live integration
and the registered update/rollback/benefit/activation decisions open. Legacy
627-case corpus and T1 Linux confirmation, and independent review of the fresh
original C1 compiler build, remain separate work in progress. This T2 result
does not graduate those earlier platform scopes. The earlier
[corpus result](recovery-q1-technical-result-2026-11-06.md) and
[T1 result](recovery-q1-abi-result-2026-11-07.md) retain their original receipts.
