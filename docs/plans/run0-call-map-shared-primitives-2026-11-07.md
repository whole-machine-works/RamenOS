# RUN0 call/map shared primitives

This packet provides source-reviewed parent lifetime, retained-read and accounting
primitives for the next same-VM C0/C1/C2 capture. It builds on PR74's completed
[standalone C0 inspection](run0-c0-result-2026-11-07.md), at base
`d4bc3c50f761070bc447134a73cf7f6ec14f15b6`. That prior result remains separate;
these private fixture controls do not establish another capture or complete boot.

## Accepted source scope

`run0_call_owner.py` selects the fixed launch-origin work/hard deadlines:
85/90 seconds before the first held, journaled transition admission and
175/180 seconds afterward. Later transitions cannot renew them. Admission and
one-use consumption do not claim a sent continue packet, ACK or observed stop.
Actual clock checks reject stale caller timestamps. Interrupted activation and
cleanup retain their committed state, attempted signals and remaining bounded
waits. Helper work keeps its original lease while cleanup uses the effective
parent hard deadline; repeated polling retains bounded aggregate wait evidence.

`run0_call_read.py` and `run0_call_budget.py` bind retained packet/data/assembly
identities and debit bounded copies before their effects. Review repairs require
one physical base across a frame's halves and rereads, the exact seventeen-part
C2 map ceiling, every successful same-target prefix, and an authenticated next
failed retention attempt. They also account for codec, decoding, comparison,
serialization and file copies. Original failures and counterexamples remain
retained. The common 32 MiB allowance, cumulative 1 MiB report/128 KiB failure
reserves, original read credit and operation/time caps are unchanged. Shape
maxima do not promise that a capture fits; logical copy accounting is not a
Python heap or RSS bound.

An allocated accounting row is **not protocol admission**. `allocated_operations`
and its compatibility alias `actual_operations` do not prove sent bytes. The
future exclusive wire must install the exact held attempt at admission before
any first-byte send, including zero-byte and partial-send failures. Its ACK and
final receipt must join that same identity. Private completed-exchange fixtures
do not establish this production chronology.

## Evidence

Workspace records are under `evidence/run0-c1-c2-next-20261107/`:

- Owner review `owner-source-review-001/disposition.json`, SHA256
  `2fb4c08d3e9687473998db16c49fdd268fbc1e6e457e5b0089b499167bc16001`,
  accepts thirteen author controls plus six distinct independent controls.
- Read/budget review `read-budget-source-review-001/repair-003/disposition.json`,
  SHA256 `731f4ee8c9649cb3f433c541ab20ef09ce47d0d45658074095d8bd336795c492`,
  accepts 44 new controls and 47 unchanged regressions, with four repair
  controls and an explicit zero-byte admission check.
- The coordinator's separate `root-{owner,budget,read}-integration-001.log`
  records pass **57 tests: 13 owner, 16 budget and 28 read**. The earlier gate
  review counted 56 before the final read clarification.

The tooling gate adds only the three direct `python3 -B` test commands; existing
commands remain unchanged. Gate SHA256 is
`373424422325a0d7319dab19febb5d51a19e36e60d8357a1399a183c1fcbd1a9`;
`gate-source-review-001/disposition.json` is
`f3020112086714b4ec25715c60de36a4d65f9d92d948d88f7c8c3503fc388a18`.
Final integrated Linux hosted qualification remains pending.

The branch also reuses PR75's exact reviewed original-task timeout hook and
four source registrations, applied to byte-identical predecessors. This retains
same-iteration failure state if the existing capacity case fails during final
qualification; it does not change the deadline or establish a cause/fix. Source
review is `0e761f81072f14fd831564e4bafd4e0c4fee24f95e785682f8503daddba1f4ea`;
registration review is `80e99b30962e4a3d487ff8ccdb02857af6f9150385b80aabb7618c8c10a9c6f5`.
The exact reuse record is `native-task-diagnostics-reuse-001.json` under the
same workspace evidence root.

## Remaining receiving joins

No runtime registration factory, actual producer/current-stop/RAM/wire join,
final measured `OperationRow`, complete inventory or parent validator is accepted
here. There is no public registration or test-override flag, VM execution or
full C1/C2 acceptance. Freeze the pure-map and wire interfaces, then provide the
closed owning collector and independently review its genuine issuers before
dependent live use. The next capture still requires fresh C0, C1 and C2 in one
VM, with new authority at each stop and the existing conditional
[source-persistence proof](run0-c0-source-persistence-2026-11-06.md).
