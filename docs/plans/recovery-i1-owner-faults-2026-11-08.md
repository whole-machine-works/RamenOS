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
