# First default-off recovery shadow consumer

The first Store and Linux process consumers now compare the independently
reviewed C1 recovery module with Rust on actual Save-recovery observations.
Rust retains all authority and publication decisions. The Store development
case passes on macOS; the Linux process development case passes with actual
child cleanup, a committed comparison and a fresh Save. Complete successor
gate/CI qualification and independent execution review remain open.

## Reference and scope

The shared recovery v0 contract names Rust `958a6f1713129930b217c16b1a21140e8fab9ed0`
and requires a reviewed update for later source. The independent reference/seam
review binds the first implementation baseline
`82561cde4dfa0680a3cf9a1d8a90c24aea45f9e9`: schema, Store API contract and receipt
validator are unchanged; process-owned query/join behavior is mapped explicitly.
This accepts the named later reference and first consumer scope, not equivalence
of every changed owner path. Final implementation and execution need their own
source and candidate bindings. The original Q1/T1/T2 results retain their original
source and executable identities.

The fixture is the independently reproduced 1,349-byte C1 module, SHA-256
`6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079`.
Its checked-in provenance is beside
`services/store_service/tests/fixtures/recovery-c1.wasm`. Preparation admits its
exact bytes and ABI before opening the Save scenario. No C2 artifact is selected.

The new feature is default-off. Store receives actual original/query/reply and
joined owners, authenticates their private origin, claims the reply once, copies
a bounded observation without receipt publication, releases locks, and calls
the existing adapter. After return, current Rust checks independently control
native publication. The module result never supplies permission or Saved state.
Ordinary copy and non-shadow paths preserve their existing predicates.

Each editor retains at most 16 bounded diagnostic records. Consuming records
frees diagnostic capacity without resetting reply claims. Exhaustion refuses
before snapshot, module invocation or publication while retaining the lookup.
Typed publication phases prevent a spent reply from taking the ordinary copy
path after an error. Error text is bounded without turning an actual error into
success. These are trusted host development controls, not production isolation.

## First development evidence

The genuine Store case holds the writer before its permit, observes authorized
Pending through q7, rejects wrong-origin and replayed replies, fills and drains
record capacity, and obtains a terminal result only through a fresh query.
Canonical NotReady zero reply fields qualify only with actual authenticated
query/target/Returned-join provenance. Unknown and terminal replies retain their
strict operation and receipt checks. ReceiptCopy observations establish the
scoped capture path, not physical device-write counts.

The Linux editor case uses the existing lost-reply terminal recovery path and
requires exactly one actual Committed C1 result with a retained receipt. It then
composes Saved under existing protection, edits and saves again, joins the actual
child, and completes recorder/root cleanup with no held producers. Three imported
cleanup controls also pass. An existing live Commit flight prevents process q7;
process Pending observation remains a separate unimplemented packet. Existing
progress and reconciliation ordering is unchanged.

Earlier missing-prerequisite, compile, fixture and cleanup failures remain
retained separately. Diagnostic copies that expose hidden errors do not qualify
the candidate. The successful Linux development run uses private umask 077 and
fresh recording context. It is not a complete resealed execution qualification.

## Qualification and next work

`just foundry-editor-recovery-shadow-i1-first` runs a required Linux supplement
with a separate compiler target and evidence/timing directory. It binds the
actual child Cargo package, source, features and digest before parent compilation,
runs the owner suites without filtering or ignored tests, checks bounded error
recording and strict Clippy, and compares source snapshots. CI retains its raw
recordings and command/binary identities. Canonical stage and preservation inventories,
original18, Reader93, and the existing binary-archival checks are preserved.

The existing source collector follows the new optional dependency. Its reviewed
registries are extended without removing old paths. One cfg(test) T1 include is
rewritten as an equivalent literal path to the same manifest; collector algorithms,
manifest bytes and assertions are unchanged.

Full I1 still requires the remaining live owner/fault families, including child
death, revocation, unrelated progress, reopen and in-flight version selection.
A real adapter-error fallback needs a separately reviewed admitted fault artifact.
Independent artifact update/rollback work is authorized and proceeds separately
from superiority. The semantics-preserving C1-to-C2 change cannot demonstrate
fewer Rust releases when competent Rust needs no release. No benefit, all-18
acceptance, adoption or activation follows from this first integration.

Private reviews and development receipts are retained in the workspace under
`evidence/recovery-i1-shadow-preparation-20261107/`, including
`reference-seam-review-002`, `i1-store-review-003`, `registry-review-003`,
`i1-store-author-resume-003`, `i1-editor-author-resume-003` and
`i1-coordinator-resume-003`. Public CI supplies the final candidate's execution
record when that qualification is complete.
