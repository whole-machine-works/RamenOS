# Default-off recovery owner and fault controls

This successor to the [first shadow consumer](recovery-i1-first-shadow-2026-11-08.md)
adds real-owner assertions while Rust retains effects and receipt publication.
It does not change the recovery ABI, select another module or activate recovery.

The new Store assertion feature is separately default-off. A one-use token binds
an actual original, query, reply and current Store Core. Its fixed pause occurs
after the real receipt snapshot and all Store locks are released, before C1.
Release, token Drop and the two-second watchdog do not extend any Save/query
lease or imply producer completion. The actual worker and producer joins remain
separate obligations. A late release cannot bypass the watchdog.

Six real Store controls exercise unrelated authorized Save progress while paused,
query expiry followed by Rust publication refusal, token Drop and watchdog abort
before C1, actual revocation with retained original-scope recovery, and fenced
reopen under both committed and noncommit journal faults. The reopen case checks
distinct selected document bytes and revisions, the original receipt's old epoch,
and another successful Save on the new epoch. Each failure path retains actual
owners and proves a fresh authorized operation. Revoking ordinary editor access
does not retroactively cancel an already-issued original Save.

Two Linux process cases retire and reap the actual child while a genuine writer
is held before or after its Commit permit. The before-permit case proves zero
permit/effect, unchanged document and zero C1 calls on its excluded closure.
The after-permit case proves original ownership, actual C1 Committed recovery,
no Saved publication to the retired child, durable bytes, fenced reopen and a
new child completing a fresh Save. Their recording names are distinct from the
original required lost-reply case.

Development evidence passes the six Store cases, two boundary controls, ordinary
shadow-feature compilation and strict Clippy on macOS. Linux focused development
runs pass the two process paths and strict Clippy on earlier test snapshots;
the final exact namespace successor and combined unfiltered supplement still
require fresh hosted qualification. The required existing supplement adds both
unfiltered targets and boundary controls, preserves the original owner suites
and archives the actual child plus four owner harnesses. Its assertion reader
requires every named new fault case, not just a successful remaining subset.
All four source inventories add the two test files and remove no paths.

Independent review found and corrected a fixture watchdog race, missing current
admission at arm, a shared recording-name collision and insufficient reopened
byte/revision assertions. Failed development checks remain retained. Complete
successor CI and execution review are pending. These cases advance portions of
the live owner obligations; they do not close all eighteen, process live-flight
Pending, an admitted adapter-error artifact, updates/rollback, practical benefit,
activation, target persistence or physical durability.

## First hosted failure and diagnostic successor

[PR81 run42527957627, attempt1](https://github.com/whole-machine-works/RamenOS/actions/runs/42527957627)
on `16227de` passed every canonical lane stage but failed the expanded supplement:
five Store fault cases passed, and the watchdog case's fresh sibling Commit
returned `Unknown` (10) where the unchanged assertion requires success (0).
The watchdog abort and fresh original query had already passed. The later new
process-fault target was not reached. All ten provider artifacts and the failure
are retained. No causal timeout, IO failure or runtime repair is established.

The diagnostic successor preserves that assertion and every lease/deadline. Only
on failure it reports bounded actual intent/call entry and deadline observations,
wire status, operation/permit/transition state, IO/exchange rows and real producer
join observations. These are sequential observations rather than an atomic
snapshot or cleanup proof; diagnostic panics and stderr errors cannot replace
the original failure. Focused and unfiltered six-case Linux development runs pass,
but did not emit this diagnostic, and do not explain the earlier failure.

The supplement now retains each actual Cargo-selected harness before discovery
and execution through an optional runner argument, so a failed owner case keeps
its binary identity and bytes. Successor gates reuse that verified copy, preserve
normal default behavior and still fail on every missing/ignored/failed case.
Failure also retains a final source snapshot without replacing its first error.
Independent Python controls cover an actual owned failing harness, exclusive-path
refusal and missing-target refusal. Complete successor qualification remains open.
