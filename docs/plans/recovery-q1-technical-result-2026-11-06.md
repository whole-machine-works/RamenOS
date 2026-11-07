# Recovery Q1 technical correspondence — 2026-11-06

Independent review accepted one fixed-corpus replay on Darwin arm64. All 627
ordered case IDs matched their frozen input hashes, zero guest return and all
16 observed output bytes. There are 623 distinct input byte strings; the
evaluator preserved every named row. No error, refusal or mismatch occurred.

This establishes correspondence for the recorded host run. It does not
complete the 18 frozen resource/fault/owner obligations, independent Linux
reproduction, live recovery integration, measured benefit or activation.

## Exact execution identities

| Input | Identity |
| --- | --- |
| RamenOS evaluator source | `34924deaaf14bf0cf83202151814918b17f84088` |
| Newcomputer evaluator source | `f7a41d070fb0fa4e832e3362a093aedd811d0eb2` |
| Candidate compiler source | `192715a77b497d370e4f956b38751aa310c9c1c3` |
| Wasm candidate, 1,349 bytes | `6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079` |
| Frozen corpus | `84eece3246d9b4521a5b8ac48fa6324cb4be4e98889277ab46837f6764aeda49` |
| Accepted registration | `185957fc5f45900995de9c4705c7936ac834cffea3006c67b6596e7e33e656e2` |
| Actual test executable, 47,113,152 bytes | `ac344e3c389f9447e64089eb41d6083d94df84f5128902aaa8c8a2035eae6c79` |
| Raw engine result, 129,945 bytes | `a90aa903ac99a365e4ce5867472e0a0f69f0e35767f48bf9eaf6b6c131c8b019` |
| Technical summary | `5d3b49450b4125e37f57a8ce6f0da520698067a97c084923bfa362bfdf01c392` |
| Final 50-file inventory | `0e9af1a73fe496de021bd20c71c8f274b925d502ffa2bdb08cf25c3cd31e46f0` |
| Independent result review | `c9d3e926ab6ababa36fe707c43b379902f7d91372e9b58d2fdf62b68650bb9df` |

The engine is locked Wasmtime 27.0.0 with Cranelift, 100,000 fuel units,
32,768-byte configured Wasm stack and exactly one memory page. Each call uses
a fresh Store/Instance. These are configured engine limits, not physical
resource guarantees. The exact ignored test was explicitly selected once:
`recovery_decision::q1_tests::run_registered_recovery_corpus`, with
`--ignored --nocapture --test-threads=1`. Ordinary CI retains the synthetic
controls and does not select this replay.

## Retained evidence and review

Evidence is retained under the Whole Machine Works workspace, outside this
repository:

- `evidence/recovery-q1-release-20261106/technical-YIqHr8zM/` contains private
  staged inputs, actual executable, source/tool/lock inventories, commands,
  engine output, verifier result and successful exit/reap observations.
- `evidence/recovery-q1-release-20261106/technical-review.PErIlyKo/review.json`
  records independent inspection of all rows, tracked/generated source,
  executable/configuration and lifecycle evidence without rerunning the candidate.
- `registration-review.json` and `source-release-review.json` in the same
  evidence root record acceptance before execution.

The original inventory's self-sealing stdout timing issue remains preserved.
`manifest-disposition.json` explains the final successor inventory, generated
after writers stopped. The evaluator did not rerun or alter source/results.

## Remaining decisions

The owner approved testing independent decision updates and rollback while
editor and Store executable bytes stay unchanged. The registered comparator
charges Rust only for its actual required changes. A no-change Rust release
records no demonstrated deployment benefit. Adoption budgets are 10 ms added
warm p95 latency, 250 ms cold p95 setup, 25 ms end-to-end p95 recovery and
64 MiB extra peak RSS, with the per-class uncertainty and fixed-sample rules
in [the registration](../contracts/recovery-comparison-v1.json).

Before adoption, complete the named fault/owner obligations, independent
reproduction and real host shadow/update/rollback/reopen/fresh-Save checks.
Rust retains effects and receipt/epoch/authority validation. A cost failure
retains Rust and allows correctness work to continue. Separate authorized
review and merge remain required.
