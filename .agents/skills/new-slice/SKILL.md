---
name: new-slice
description: Define and scaffold a new RamenOS behavior slice with a consumer, Foundry assertions and only the required interfaces.
---

Read the status/task pair, `AGENTS.md`, the relevant `SLICES.md` entry and
`docs/research/SLICE_NAMESPACING.md`. Extend an allocated slice when appropriate;
do not create a new slice or queue merely to divide work among authors.

For solo work, own the coordination and integration steps below; in a team, use
the assigned owners. This skill does not require a separate team for a small edit.

1. Name the bounded behavior, real consumer and acceptance assertion. A Store
   consumer is useful when relevant, but is not mandatory for every slice.
2. Select the OS/research/governance namespace without reusing allocated IDs.
   Separate code dependencies from evidence needed for a later claim.
3. Freeze shared contracts with the coordinator before dependent authors begin.
   Write behavior, denial and failure assertions first; unimplemented behavior
   must fail explicitly instead of passing an empty scaffold.
4. Send `justfile`, registry and generated-output edits to their assigned owner.
   Use `new-idl` for a new native interface. Keep the implementation within its
   kernel/service/Store boundary and host development features default-off.
5. Run the scoped assertions and report expected failures honestly. A compiling
   stub is not completion of the behavior.

Return the patch, checks and remaining work. The integration owner updates slice
definitions and status/queue/history for the outcome actually accepted. Missing
contract requirements or authority block that packet, not independent ready work.
