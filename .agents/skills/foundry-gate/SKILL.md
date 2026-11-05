---
name: foundry-gate
description: Select and run scoped RamenOS Foundry validation, retain evidence and distinguish failure from missing prerequisites.
---

Resolve the requested recipe from `just --list` and `justfile`, then inspect its
script for inputs, prerequisites and output paths. `CURRENT_STATUS.md` maps
implemented behavior to gates; `AGENTS.md` names required integration checks.
Do not maintain another gate inventory here.

- Select the changed behavior and affected consumers. Use
  `docs/FOUNDRY_CI_OPTIMIZATION_V0.md` to distinguish fast iteration, packet
  acceptance and complete integration; full preflight is not a per-edit check.
- Reserve shared `out/`, Cargo targets, sockets, images and devices through the
  coordinator. Run conflicting gates serially unless their outputs are isolated.
  An ordinary gate request does not authorize physical actuation or paid work.
- Inspect assertions and retained logs, not only the exit code. Distinguish PASS,
  failure, expected unimplemented failure and INCOMPLETE. Missing inputs or skipped
  assertions do not satisfy acceptance.
- Return the exact tested revision/diff, command/environment, exit result,
  evidence paths, failing assertion and untested scope. Preserve logs before reuse.
- Apply `EVIDENCE_LEVELS.md`: host fixtures, replay, QEMU and physical devices
  support different claims. Reuse a focused report only for unchanged transitive
  inputs and environment; compiler reuse still runs fresh assertions.
