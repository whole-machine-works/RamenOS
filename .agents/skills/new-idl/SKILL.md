---
name: new-idl
description: Create or evolve a RamenOS native IDL contract, regenerate bindings and check affected producers and consumers.
---

Read `AGENTS.md`, `idl/tools/README.md` and a relevant existing IDL for current
syntax. Generated bindings do not prove runtime enforcement.

For solo work, own the coordination and integration steps below; in a team, use
the assigned owners. This skill does not require a separate team for a small edit.

1. Choose `idl/harness/`, `idl/portals/` or `idl/services/` from the interface's
   purpose. Check existing IDs and `tools/ci/idl_lint.py`; the coordinator allocates
   shared protocol/message IDs and freezes the producer/consumer contract.
2. Specify bounded fields, error results, request and observable authority, and
   referenced-object lifetime/range checks. Check initialized padding and supported
   wire types. Version incompatible layouts or meanings and identify consumers.
3. Write behavior, denial and malformed-message assertions before handlers.
   An interface scaffold cannot claim implemented consumer behavior.
4. Give the assigned owner output-registration changes for
   `tools/ci/run_codegen.sh` and handwritten inclusion points such as
   `kernel_api/src/lib.rs`. That owner runs codegen after the shared IDLs settle;
   never hand-edit generated output.
5. Run `just codegen`, `just idl-lint`, `cargo build -p kernel_api` and affected
   wire/consumer checks under the reserved ownership. Inspect generated diffs.

Return the contract/output paths, compatibility decision, checks and remaining
implementation scope through the workflow's handoff.
