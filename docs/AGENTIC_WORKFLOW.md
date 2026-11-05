# Agentic Workflow

**Last Updated:** 2026-11-04
**Status:** Contributor coordination contract; tooling is not an OS security boundary

Use a coordinator, parallel authors and independent review for work with separable
packets. Optimize the path to an integrated consumer. [AGENTS.md](../AGENTS.md)
owns invariants, [Current Status](../CURRENT_STATUS.md) owns landed behavior, and
[Next Tasks](../NEXT_TASKS.md) owns dispatch dependencies. This workflow does not
create a second queue or establish an advantage for the Agent Task Proof.

## Select and prepare a batch

The coordinator selects ready packets for the named product checkpoint, reads
their contracts and checks the current source. Separate implementation dependencies
from evidence or authority needed for a later claim: a blocked physical run need
not stop ready host/QEMU preparation. Research needs a concrete decision to resolve.

Freeze shared interfaces, protocol IDs and behavior/denial/failure assertions
before dependent authors start. An unimplemented behavior must fail explicitly.
Lifecycle assertions cover ownership during failure and the next usable operation;
preserve uncertainty after possible admission or mutation. A prerequisite author
can establish a contract while other authors work on unrelated ready packets.

Reserve review capacity. With four slots, a useful starting arrangement is one
coordinator, two authors and one reviewer. Adapt to disjoint work and available
review capacity; more authors do not help when completed patches await review.
Integrate accepted packets as they finish, without a barrier for unrelated work.

## Dispatch packet

An ordinary assignment can carry the following fields directly. RamenOrg execution
uses its existing [WorkOrderV0](org/WORK_ORDER_V0.md) and
[HandoffPacketV0](org/HANDOFF_PACKET_V0.md); no new schema is required.

| Field | Required content |
|-------|------------------|
| Outcome | Queue/slice reference, consumer-visible behavior and exclusions |
| Baseline | Checkout, base revision and relevant existing edits |
| Dependencies | Frozen contract, ready prerequisites and assumptions to recheck |
| Ownership | Exact writable files, shared-file owner, reviewer and integration owner |
| Context | Only the source, contract and evidence needed for this outcome |
| Acceptance | Assertions, expected initial result, fast iteration command and affected integration checks |
| Resources | Reserved output paths, Cargo targets, sockets, QEMU images or devices |
| Return | Patch identity, evidence and conditions requiring replanning |

An explicit [ContextGrantV0](org/CONTEXT_GRANT_V0.md) remains binding. A summary
cannot expand it or the user's authorization. Do not dispatch two competing
versions of the same interface.

## Ownership and workspace rules

- **Coordinator:** resolves dependencies and ownership, keeps the batch record,
  assigns reviews and accepts integration. It may author a prerequisite but
  cannot independently review its own patch.
- **Author:** edits its assigned paths, runs reserved focused checks and returns
  evidence. Send cross-owner changes to the coordinator.
- **Reviewer:** inspects the actual contract, patch and evidence; checks consumers,
  denied operations, recovery and claim scope. Return actionable findings or an
  explicit no-findings result. Technical review is not A3 approval or merge authority.
- **Integration owner:** normally the coordinator, owns shared registries,
  `justfile`, IDL/codegen outputs, `Cargo.lock` and status/history. It may explicitly
  delegate a shared file to one author while other writers are excluded.

In a shared checkout, only the integration owner switches branches, commits or
runs repository-wide formatting/codegen. Authors may format their assigned files.
Preserve existing edits; do not reset, restore, clean or stash away another
author's work. Use worktrees when source overlap or baseline differences require
them, not for read-only review or as a substitute for ownership.

Reserve gate resources as well as source files. Separate worktrees do not isolate
fixed ports, `/tmp` paths or hardware. Serialize gates sharing `out/`, images or
compiler targets unless the script supports genuinely isolated resources. Retain
logs before their output paths are reused.

## Review and integrate

Each author returns the delivered behavior, changed paths, base/head or retained
diff digest, commands/environment/results, evidence locations and remaining
limits. Identify concurrent edits included in the tested state. Do not send
credentials or whole-repository context dumps.

An independent reviewer checks the submitted patch before the integration commit
or milestone acceptance, even when edits are already visible in a shared tree.
Resolve material findings and rerun checks whose inputs changed. Review the
coordinator's code by the same rule; rotate a non-author into review if needed.

The integration owner assembles accepted changes, runs codegen once if required,
and executes affected producer/consumer gates on that candidate. Reuse a focused
result only when all relevant source, transitive dependencies, fixtures, features,
command and environment remain unchanged. Compiler caching never substitutes for
fresh assertions. Use the [developer loop and CI profile](FOUNDRY_CI_OPTIMIZATION_V0.md)
to avoid per-edit full preflight or duplicate complete local/hosted runs.

Update the authoritative status, queue, changelog and decisions only where the
accepted outcome changes them. Keep one compact batch record linking packet,
owner, dependencies, reserved resources, evidence, review result and next check.
An author report, empty scaffold or green hook is not completed behavior.

## Stop and replan conditions

Stop the affected packet when its contract must change, ownership overlaps, a
prerequisite is false, or required environment/evidence is missing. Report the
specific blocker and retain partial work; keep independent packets moving. The
coordinator narrows or resequences the work rather than retrying the same missing
inputs with new authors. A missing prerequisite remains `INCOMPLETE`.

Routine design choices stay within the Constitution and task. New spending,
physical actuation, release and merge require the applicable authority; delegation
does not supply it. Follow [the separate PR identities](org/RAMEN_IMPLEMENTER_BOT.md).

## Client hooks and skills

[`.claude/settings.json`](../.claude/settings.json) guards lockfiles, generated
Rust and Constitution edits through its `Edit`/`Write` hooks. It does not cover
arbitrary shell writes or other clients. Per-edit automatic formatting/Clippy is
disabled to avoid unreserved shared mutations; use explicit scoped checks.
[`.codex/hooks.json`](../.codex/hooks.json) records the convention but this repository
does not establish native support for that schema. Neither file is a sandbox.

Canonical skills live in [`.agents/skills/`](../.agents/skills/); client aliases
link there. Load the skill for the actual task: `coordinate-work` for a batch,
`new-slice` for a new behavior slice, `new-idl` for a native interface,
`foundry-gate` for validation, and `ramen-conventions` for code-boundary decisions.
Keep task mechanics in these skills and shared coordination rules here.
