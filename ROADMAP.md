# Roadmap

**Last Updated:** 2026-11-04
**Status:** Product checkpoints and dependencies; no completion-date or readiness claim

[Vision](VISION.md) owns the destination: an everyday post-Unix OS for humans and
AI agents. [Current Status](CURRENT_STATUS.md) owns landed behavior and limits;
[Next Tasks](NEXT_TASKS.md) owns the ready frontier and exact acceptance. Slice
definitions live in [SLICES.md](SLICES.md), history in [Changelog](CHANGELOG.md),
and rationale in [Decisions](DECISIONS.md).

The priority is a person completing useful work and recovering when something
goes wrong. First make one editing task dependable, then carry it onto RamenOS
with persistent storage and one qualified machine. Evaluate a small Newcomputer
replacement alongside that path. Expand the platform when a demonstrated task
needs it. This ordering advances the vision of
[Whole Machine Works](https://github.com/whole-machine-works) without making the
human experience depend on a compiler speedup or a model study.

<a id="deliver-the-first-integrated-human-task"></a>
<a id="human-input-and-desktop-scope"></a>

## Shortest path to a useful, dependable computer

Keep one keyboard-first human task unchanged across stronger boundaries: launch
through a permission preview, read/edit/save an artifact and recover after failure.
Core interaction must work without a model. The default-off trusted in-process
host consumer and reviewed reliability repairs are implemented and qualified.
The next process work starts with executable assertions and genuine owner staging.
Target persistence needs
actual storage IO/readback, not a host journal or embedded vector.

| Priority / checkpoint | What it makes possible | Concrete completion and boundary |
|-----------------------|------------------------|----------------------------------|
| Foundation — reliable host control | Preserve work through the known ownership, focus, timeout and staging failures | Accepted in trusted in-process host scope: Original18/Reader93, thirteen transition regressions, affected consumers and hosted lanes pass on their recorded sources. |
| 1 — real application process | An editor can fail without losing track of an admitted Save | Existing editor core runs in an actual Linux child through authenticated typed channels, immutable publications and retained original Save owners. Complete reviewed process assertions and lifecycle checks; preserve the in-process control. This remains host process evidence. |
| 2 — same task on RamenOS/QEMU | A person can type, see the result and use the permissions and recovery flow on RamenOS | Actual target loader/runtime, device-backed input, compositor/display and named required services execute the task with grants, denial and crash/restart. Join runtime+input+display branches; name any host services. Saving across restart additionally joins device-backed storage. |
| 3 — persistent target task | Saved work is available after restart, with failures reported honestly | Actual block read/write/flush and Store IO produce verified save/reopen and failure recovery for a concrete device profile and ordering contract. Vector or firmware-detection success is insufficient. |
| 4 — qualified reference machine | Repeat the useful task on one real computer | Live provenance, required input/display/storage qualification and reboot/readback/recovery. Requires H0→H1 observation/actuation and relevant S12/S13/controller evidence. One machine does not establish broad everyday readiness. |

At the first interactive checkpoint, include a recorded walkthrough by someone
who did not implement the interaction. They should be able to identify which
document is open, explain the access they are granting, edit with the keyboard,
and distinguish saved, pending/unknown, denied and failed outcomes using the UI.
After a deliberately injected failure, they should understand the offered recovery
action and complete a fresh authorized Save. Record confusion and intervention
alongside the technical result, and use them to choose the next usability repair.
Freeze the walkthrough and its expected outcomes before evaluation; it complements
the executable process/storage assertions and establishes no general usability claim.

Use one application, one input controller and a basic display path. Accelerated
GPU, pointer input, more apps, distributed transport and a generic deployment
resolver follow demonstrated needs. Do not turn the first checkpoint into a
platform-wide rewrite or wait for unrelated studies/hardware runs.

## Parallel execution with explicit joins

Use one coordinator, two implementers and one independent reviewer by default.
The coordinator freezes shared contracts/assertions, assigns disjoint files and
resources, integrates one reviewed packet at a time and owns final validation.
A successor starts when its own prerequisites clear; unrelated packets need not
finish together. Reserve review capacity rather than accumulating completed
patches. [Agentic Workflow](docs/AGENTIC_WORKFLOW.md) owns the mechanics.

```mermaid
flowchart LR
    E[Evidence admission] --> H[Reliable host control]
    F[Host transition repairs] --> H
    H --> P[Real editor process]
    C[Process assertions and owner staging] --> P
    R[RUN0 firmware ownership] --> L[Target loader/runtime]
    I[Input Vault and Oracle] --> K[Device keyboard]
    P --> D[Target display and service ports]
    L --> Q[Same QEMU human task]
    K --> Q
    D --> Q
    S[Device block IO and Store adapter] --> T[Persistent target task]
    Q --> T
    T --> M[Reference-machine repeat]
    H0[H0 serial] --> H1[H1 AMT]
    H1 --> H2[H2 S12 SATA]
    H2 --> H3[H3 S13 recovery]
    H1 --> M
    H3 --> M
```

RUN0 memory ownership, input Vault/Oracle preparation and device-backed storage
can advance while process assertions and implementation proceed. A worker needs the selected
device's Reference Vault and Oracle protocol_trace before device implementation.
Do not require physical H0–H3 for host/QEMU work or SW0. Physical execution keeps
its own explicit authorization and prerequisites. Target compositor/service ports
can prepare against frozen host contracts before process completion; their final
acceptance joins the real target task.

Split process work at assertions/owner staging, authenticated carrier, child
edit/raster and Save/recovery integration. After interface freeze, carrier and
child implementation can overlap in separately assigned files; acceptance requires
real combined execution. When two repairs touch the same host or Store lifecycle,
serialize that scope and backfill with independent work. Exact ready packets and
regression obligations live only in [Next Tasks](NEXT_TASKS.md#ready-work-front).

## Demonstrate independent evolution

The combined OS Core/Foundry/Store proposition is to reduce the cost of safe change:
versioned contracts bound behavior, authority, resources and recovery; Foundry
qualifies actual implementations; Store helps discover, authorize and activate
suitable artifacts. Fault containment and compatibility remain properties to
measure, not consequences inferred from modular code or typed messages.

Use the Newcomputer Save-recovery decision as the first proposed responsibility
transfer after the genuine process task. It asks a question a person cares about:
did this Save finish, and what can I safely do next? The component consumes
authorized observations of the original operation; the existing Rust owner keeps
all write authority and independently validates the result. Preserve uncertainty
when the evidence cannot justify a definite answer, and never retry a mutation
merely because its reply was lost.

Language/compiler and adapter preparation can proceed against the shared frozen
contract while the real process sequence advances. Integration joins accepted
P0–P3 behavior. Adoption requires independent review, shadow comparison, a measured
engineering benefit with acceptable overhead, and demonstrated rollback with a Save in flight.
Retain Rust if the replacement does not earn adoption. This experiment proceeds
alongside target preparation and does not gate the base human task; the arithmetic
compiler experiment has its own comparison and decision.

Keep the consumer unchanged; qualify a second implementation, activate it, inject
failure and recover while an unrelated human task progresses. Define logical
identity, implementation generation, unresolved operations, state compatibility
and permitted service interruption first.
Boot-time activation or bounded service interruption is acceptable when that is
the evidenced recovery mode; uninterrupted hot swapping is not a universal promise.

Measure changes outside the component, implementation/qualification effort, reused
versus fresh evidence, resource cost, disruption and recovery success. Hardware
variants must additionally establish actual DMA mappings, reset scope and buffer
retirement before memory reuse. A driver process crash alone cannot establish a
hardware failure boundary. Use device dossiers and existing contracts rather than
opening a new generic framework before a real consumer needs it.

## Keep independent lanes bounded

| Lane | Useful work now | Acceptance boundary |
|------|-----------------|---------------------|
| Newcomputer cooperation | Callable recovery decision and bounded adapter preparation against the shared contract | Accepted real process task before integration; independent comparison, useful benefit, authority checks and rollback before adoption. No speedup prerequisite on the human task. |
| SW0 Agent Task Proof | Remaining named authority/lifetime and offline provider-supervision controls | Complete deterministic A2 plus independently frozen bank/study releases before opt-in funded model collection. Host evidence is not target enforcement. |
| Recovery / S13 | Slot publication/readback, revisioned selection and interrupted-phase verifier | Fresh new-slot and rollback boots with provenance for physical graduation; metadata scaffold is insufficient. |
| H0–H3 | Lab setup, serial observer, AMT, SATA and NVMe qualification in order | Software preparation proceeds independently; physical acts require explicit authority and per-device evidence. |
| G0 Org Kernel / Research Office | Concrete research/coordination inputs that unblock a named packet | G0.8.1 A2-local boundaries remain; no autonomous approval, merge, release, spending or hardware authority. |

The agent study tests one part of the product. Preserve interface/substrate/total
contrasts, unknown authority, failures in the denominator and predeclared funded
ceilings. A tie, regression or exploratory report is valid; no positive study is
a prerequisite for human interaction. See [the study plan](docs/plans/2026-09-16-agent-task-proof.md).

## Fast feedback, complete acceptance

Choose validation before implementation: pure contracts/tooling first, focused
feature-correct developer checks during edits, affected producer/consumer gates at
handoff, and canonical CI lanes on a fixed assembled candidate. Reserve shared
outputs and compiler targets. Reuse compilation, not PASS results; unchanged-input
focused evidence may be referenced only for its original scope. Do not duplicate
complete preflight locally after the equivalent complete lanes passed on the same
candidate. Host/QEMU/physical claims retain their separate evidence requirements.

CI currently has five isolated execution lanes and one complete canonical stage
inventory. Measure actual stage/setup/cache/queue costs before splitting gates,
batching feature graphs or adding runner complexity. Preserve every behavior,
denial and failure assertion, fresh evidence and fail-closed aggregate. Smaller
reviewed PRs and fewer repeated builds improve throughput without widening real
timeouts or using retries to hide failures. [The execution profile](docs/FOUNDRY_CI_OPTIMIZATION_V0.md)
owns commands and measurements.

## Expansion after the checkpoint

Useful software, compatibility-to-native ports, live Semantic State, broader
hardware, native networking and sustained usability/reliability extend the product.
Choose the next application or device from a task the reference-machine user
cannot yet complete, or a failure they cannot recover from. Broader hardware,
GPU acceleration, general deployment machinery and paid model comparisons stay
off the first human task's critical path unless a named dependency requires them.
Execution-fabric transport, generalized wizard/deployment orchestration and new
research interfaces need a bounded consumer and evidence plan. Admit them when
they unblock the next task or address a measured risk. Everyday readiness requires
broader useful workloads and sustained evidence; completing a host/QEMU checkpoint
does not establish it. No delivery date or development-speed advantage is claimed.
