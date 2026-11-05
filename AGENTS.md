# RamenOS — Agent Instructions

Build a reliability-first, Rust-first, post-Unix OS for **humans and AI agents**,
with everyday use as the destination. The three pillars are **OS Core** (kernel,
services, runtimes), **Foundry** (tooling and evidence gates), and **Store**
(discovery, permission previews, execution, and native ports).

This is the stable agent contract; `CLAUDE.md` links here. Start with
[CURRENT_STATUS.md](CURRENT_STATUS.md) for landed behavior and
[NEXT_TASKS.md](NEXT_TASKS.md) for ready work and dependencies, then read only the
maintained contracts needed for the task. [VISION.md](VISION.md) owns product
direction, [ROADMAP.md](ROADMAP.md) milestone dependencies, and
[SLICES.md](SLICES.md) slice definitions. Use [docs/INDEX.md](docs/INDEX.md) to
find references. Do not copy the queue or milestone history into instructions.

## Product and evidence

- Keep human interaction, hardware support, and developer workflows visible
  alongside agent interfaces. SW0 Agent Task Proof evaluates one part of the OS.
- Core human interactions must work without an AI model. Models may translate
  intent; explicit policy and enforcement decide authority.
- Describe speed, safety, hardware adaptability, isolation, and everyday
  readiness as goals until matching evidence exists. The project is public
  pre-alpha; host services, replay, simulation, QEMU, and metal have different scopes.
- Isolation contains faults and typed contracts reduce coupling. Test affected
  consumers and shared-resource behavior when changing a component.
- Use [EVIDENCE_LEVELS.md](EVIDENCE_LEVELS.md) for hardware claims and
  [SECURITY_STATUS.md](SECURITY_STATUS.md) for current security limits. Never infer
  metal graduation, hidden-affordance noninterference, or release readiness.

## Non-negotiables

1. Rust-first kernel and core services.
2. Native interfaces are typed **Harnesses/Portals** defined in IDL; no ioctl escape hatches.
3. **POSIX is compatibility-only** and must not define native APIs.
4. The kernel validates capabilities for fast-path operations; user-space brokers decide grants.
5. **Control plane: typed messages. Data plane: zero-copy shared memory.**
6. Preserve **kernel ≠ services ≠ store**.

[CONSTITUTION.md](CONSTITUTION.md) holds the full invariants. Changing it requires
a `DECISIONS.md` entry. No temporary exception may silently violate it.

## Deliver a bounded outcome

Choose a ready packet from the status/task pair. Each implementation has a real
consumer, a bounded behavior or contract, and a Foundry assertion. Documentation
and governance work should remove a named obstacle to those outcomes.

- **Gate-first:** write behavior, denial and failure assertions before implementation.
  A lifecycle check includes the next successful operation after cancellation,
  rejection or recovery; an error alone does not prove continued usability.
- Define native interfaces in `idl/harness/`, `idl/portals/` or `idl/services/`.
  Run `just codegen`; never hand-edit `*.generated.rs` or `generated/` content.
- Use [Agentic Workflow](docs/AGENTIC_WORKFLOW.md) for coordinator, parallel
  author, reviewer and integration ownership. It owns dispatch and handoff rules;
  the queue owns dependencies. Independent review precedes integration.
- The integration owner updates status/history for achieved behavior and the
  queue for changed dependencies. Design rationale belongs in `DECISIONS.md`.

Choose routine defaults within the Constitution. Missing authority, frozen-contract
changes or absent evidence require the affected packet to be replanned.

## Code guardrails

- No heap allocation in `kernel/`: no `alloc`, `Vec`, `String`, or `Box`.
- Architecture-specific code belongs in `kernel/src/arch/`.
- `kernel_api/` is `#![no_std]` with no external dependencies. `kernel/` permits
  the recorded `spin` dependency; new dependencies require an explicit decision.
- Services may use `kernel_api` contracts, never kernel internals. Service-facing
  artifact types come from `artifact_store_schema`; keep Store IO ownership in
  `artifact_store_core` / `store_service`, not schema consumers.
- Keep IPC formats typed, versioned, bounded, and fail closed on invalid wire data.
- Keep trace, capability, and accounting state scoped by domain. Avoid ambient globals.
- Host development scaffolds require explicit, default-off features and visible
  limits; helper sandbox controls do not establish default runtime containment.
- For agent-facing or cross-domain boundaries, define request authority (`Lang`)
  separately from observable authority (`ObsContract`).

## Driver and application work

- Before hardware interactions, obtain the **Reference Vault** and Oracle
  `protocol_trace` artifacts. Derive registers and behavior from that evidence,
  not pre-training. See [Reference Vaults](drivers/reference_vaults/README.md).
- For application ports, derive the capability manifest from `observed_caps_v0`
  and validate it against scenarios. Observation of one run is not all possible authority.

## Validation

Use the pinned toolchain in `rust-toolchain.toml` and recipes in [justfile](justfile).
Select the fast iteration command, packet acceptance and affected integration
checks before implementation. For roadmap, org, and research planning changes, keep
`just s11`, `just s12`, `just s13`, and `just foundry-org-governance-g0` green;
run `just hil-appliance` for appliance docs/contracts. Serialize gates that share
fixed output paths or hardware; the coordinator runs the final integrated checks.
Use [the CI execution profile](docs/FOUNDRY_CI_OPTIMIZATION_V0.md) for focused
iteration and complete acceptance. Run complete CI lanes or their serial preflight
equivalent on the fixed candidate, without duplicating both. Reuse focused evidence
only for unchanged transitive inputs and environment; compiler reuse still requires
fresh assertions. A prose extension does not make a gate-consumed file non-executable.

Full preflight requires Linux, Python `jsonschema`, Docker with builtin seccomp,
and the already installed pinned image. Missing prerequisites produce `INCOMPLETE`.
Use focused host/QEMU gates on macOS and report limitations. Setup, gate coverage,
and S2 inputs are in [Getting Started](docs/GETTING_STARTED.md) and
[Development Reference](docs/DEVELOPMENT_REFERENCE.md).

## PR and authority boundaries

- The path-scoped **`merge-gate`** requires `org-governance` for docs/org-only PRs
  and successful `foundry` for OS-code PRs. Resolve executable classification from
  `tools/ci/change_policy.py`; a documentation suffix does not establish that a
  file is prose. Executable contracts, tooling, workflows and `justfile` need
  affected Foundry evidence. Classification errors fail closed.
- Open PRs as **`ramen-implementer[bot]` (A2)**. A **different identity (A3)**
  approves and merges. Drop `GH_TOKEN` and `GITHUB_TOKEN`, then verify the authorized
  A3 identity before switching to human review.
  Follow [the implementer-bot guide](docs/org/RAMEN_IMPLEMENTER_BOT.md) for credentials
  and exact commands; this file grants no approval, merge, or release authority.
- RamenOrg work uses bounded `WorkOrderV0`, `HandoffPacketV0`, and `BoardVoteV0`
  artifacts. A2-local and agent delegation grant no merge, release, self-approval,
  HIL actuation, spending, or public-support authority. Preserve separation of duties.
- Research must connect a product risk, claim boundary, evidence plan, and landing
  path. Use [the research index](docs/research/INDEX.md); RamenOS is research-backed.
