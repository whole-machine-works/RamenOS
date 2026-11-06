# Linux editor process diagnostic amendments

This document supplements the reviewed P0 assertion handoff without changing its
retained hash or the frozen production protocol. Its scope is diagnostics and
actual fixture setup for the implemented P1–P3 owners. Source review is recorded
in the delivery plan; runtime acceptance still requires the complete gate.

The original P0 thirty-family inventory and negative/positive obligations stay
required. Corrections below replace impossible or conflated diagnostic recipes
with actual owner operations and additional independently checked facts.

* D23 consumed preview replay calls the existing Core Confirm owner operation
  with its retained actual Confirm envelope, genuine Chrome peer, and a new real
  request lifetime. The actual returned status and exact88-byte Core envelope
  are recorded as `owner_confirm_request/status`. Native preview's raw wire
  dispatcher continues to return Unsupported for this operation; no diagnostic
  exchange represents that wire response as Stale. The owner operation must
  return Stale without reviving the consumed preview or adopting new state.
* D27 overflow produces65 ordinary events by alternating supported key4 presses
  and releases. Core accepts fewer than65 distinct simultaneously pressed
  supported usages, so a distinct-press recipe cannot reach the queue boundary.
  The predicate retains64 actual queued ordinary events before the65th actual
  accepted producer event, followed by Core's reserved Reset and no adoption.
* D27 old Surface uses the otherwise valid, same owned offered and returned
  descriptor pair. Its old frame's actual surface ID/generation/creation epoch
  joins the actual Core surface. A genuine compositor restart advances Core's
  service epoch and retires the surface, clearing the old frame. The predicate compares Surface.epoch
  with service_epoch, which share the same counter domain, and requires a real
  Stale owner result and unchanged state. Comparing the offer ID to another
  pending offer would instead test the separate D12 descriptor lineage denial.
* D16 Drop physically releases accepted transport descriptors/maps; Reseed
  performs a genuine selected-object reread and attempts ordinary object
  admission; CounterReset changes only the finite fixture's actual offer cursor
  to0. Each then exercises the unchanged lifetime quota, requiring refusal
  before new native object allocation. The actual cursor is diagnostic only;
  lifetime counters and authority never reset or receive credit from these acts.
* Parent input ownership is separate from Core input ownership. Snapshot parent
  queue64 ordinary plus1 Reset, child pending1, and Core overflow counters are
  recorded separately. Counters derive from their real current owners.

Snapshots pin immutable pixel Arcs at the actual decision boundary. After real
native wait and Rust join, the recorder copies and hashes their exact bytes off
enforcing locks, then rechecks the pinned version and zero live ownership before
moving evidence. This removes diagnostic work from the input deadline without
changing that deadline or dropping raw observations.

The reader accepts diagnostic `RECORDING_COMPLETE` only. Referenced sibling,
retired bootstrap source, and fork-only assertion helper each have separate
provenance scopes. Native fork/birth/wait, authentic held image where executed,
actual received credentials, successful endpoint close, and real supervisor
join must be joined to the appropriate scope. A fork-only helper never claims
an editor exec. Synthetic adversarial reader tests prove parser rejection
properties, not Linux behavior.

D16 intermediate publications still invoke real Core composition and current
chrome observation on every accepted pair, with actor/document/generation/
sequence/focus/extent checks. The parent recorder exports full frames at the
first and final boundary; redundant intermediate parent frame exports are
omitted. All native controls, descriptors, captured object bytes and final Core
exchanges remain recorded. This avoids the unrelated128-frame export cap and
diagnostic copy/hash cost without changing the child deadline or quota proof.
