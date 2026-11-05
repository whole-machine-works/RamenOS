---
name: coordinate-work
description: Coordinate a RamenOS implementation batch with parallel authors, independent review and one integration owner. Use when selecting, assigning or integrating separable packets.
---

Read `AGENTS.md`, `CURRENT_STATUS.md`, `NEXT_TASKS.md` and
`docs/AGENTIC_WORKFLOW.md`. The workflow owns dispatch fields, shared-resource
reservations, handoffs and replanning; the queue owns ready dependencies.

Choose packets that shorten the named consumer's path. Freeze shared contracts
and acceptance assertions before dependent authors start. Assign disjoint files,
a non-author reviewer and one owner for generated outputs, registries and final
checks. Separate checkouts do not reserve ports, output paths or hardware.

Keep one compact batch record linking each packet to its owner, dependencies,
reserved resources, patch/evidence and review result. Integrate reviewed work as
it finishes. If reviews queue up, spend the next available slot on review rather
than another implementation. A blocked packet does not stop independent ready work.

Report the accepted behavior, tested source, remaining prerequisites and next ready
packet. Delegation supplies no additional merge, spending, release or hardware authority.
