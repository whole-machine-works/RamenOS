# C2 independent build and technical correspondence

The semantics-preserving C2 compiler change now has a separate clean rebuild and
one recorded Darwin arm64 correspondence run. Both builds produce exactly the
same 1,347-byte module. The run matches all 627 ordered R0 raw observations,
13 independently specified public-API observations and 13 fresh Committed
followups. Independent actual-result review accepts this named scope; it does not
select C2 in Store or establish operational update/rollback or benefit.

## Fixed identities and recorded execution

Newcomputer source is `45060d06c644afa7be0023a91c763915c32c6e2a`; the module
SHA-256 is `fbcceae4411b17f2e517a8539991bfb41b097b2aa2b037ca58a828972a3b3ce4`.
A separate clean, detached, cache-free checkout reproduced the original build
with the pinned CPython3.14.8 and uv0.12.23. Source, environment, tool and original
checkout snapshots matched before and after the successful owned/reaped build.
Only paths differ in the two build receipts; no existing source or result was
rewritten. The [fixture provenance](../../services/native_runner/tests/fixtures/recovery-c2.md)
records the rebuild receipt and corpus identities.

The ABI remains recovery v0, SHA-256
`49daf52dd669411376770b3bc2a007d7c6a8b346843bcd123a45da8139b0da60`.
[The new registration](../../tools/recovery_c2/registration-v1.json) pins the
unchanged R0 corpus: 627 ordered cases with 623 distinct inputs, preserving
all duplicate rows. Its historical Rust reference remains `958a6f`; the later
live-owner reference/seam review is separate. The
[independent typed matrix](../../tools/recovery_c2/typed-expectations-v1.json)
fixes all thirteen observations before candidate execution and requires a fresh
Committed followup after every one.

The recorded executable is a Cargo-selected, retained native_runner unit harness,
49,451,504 bytes, SHA-256
`36daf172cfa716708a62ffc8235bca06d36419c66b853a006b5ba7b290bf8517`.
Its source snapshot is based on RamenOS `b97f096`, with 948 content-bound entries,
manifest SHA-256 `bce23715fb011107bd80e6ed202afd63f517c24e7ee4e92ffa9daaa093bc87fd`.
Adding the one test-only module declaration is the only enclosing adapter diff;
removing it recovers the exact accepted production adapter bytes. Q1/T1/T2,
Store's C1 preparation, Cargo and ABI are unchanged in that execution snapshot.

One reviewed driver invocation staged the fixed inputs, ran exactly the explicit
registered test and independently verified its result. Each command exited zero,
was reaped and had no remaining group members. All sixteen input references,
the full source snapshot and host platform match before/after; the original
failed synthetic/build checks remain retained without relabeling. The actual
result SHA-256 is
`b50573fc3779c5a43d922401efbc49d0af7e44695c2685508d018adc6299497e`.
Independent review authenticated every row and all nineteen retained attempt
files, the three exact owned commands, source/input preservation and the actual
executable. The accepted disposition SHA-256 is
`888171c826af2b1200a701a857587a58c45f8082117d3889d9f8f8df6ca7ad75`.
It contains 653 observations corresponding to 649 guest calls: nine of thirteen
typed rows reach the guest; four refuse before guest execution, and all thirteen
fresh followups actually run. No candidate retry or warmup was performed.

## Raw and public-API scope

The raw leg uses the unchanged adapter's private `invoke` from a test-only child,
as the original Q1 bridge does. It captures each actual return, all sixteen
output bytes when available, input digest and bounded error in corpus order.
It does not describe malformed raw records as public `decide` calls. Nonzero
returns and traps retain unavailable output as null, never fabricated zeros.

The separate public leg calls the real constructor/`decide` for Pending, Denied,
Invalid, valid committed/noncommit receipts, foreign operation/epoch/binding,
malformed receipt, zero epoch/operation and wrong artifact/ABI identities. Every
row is followed by a real fresh Committed result. Each guest call uses the same
unchanged fresh-instance, one-page, no-import, 100000-fuel, 32768-byte-stack adapter.
System dylib paths and platform are retained, but dylib bytes are not individually
pinned; this is technical evidence on that trusted host, not host isolation or
an OS-image reproduction claim.

## Maintained controls and next consumer

Five synthetic Rust controls exercise real traps/returns, fresh calls, identity
and duplicate-input refusal, typed correspondence and interrupted result output.
Five Python controls exercise comparison/refusal and private file rules; a sixth
checks the packaged registration, typed matrix and module bytes. Existing Native
Runner and quality gates add these controls without removing prior assertions.
The registered candidate test remains explicit; ordinary CI does not repeat the
recorded experiment. Successor integration CI remains pending.

Store still prepares only C1; its lookup, publication and update APIs are unchanged.
The next separately reviewed consumer is independent C1/C2 selection and rollback
while a genuine recovery call is in flight, with unchanged trusted executable
identities, owners and deadlines. That operational test is authorized separately
from superiority. The C1-to-C2 change preserves semantics, so competent Rust needs
zero trusted executable replacements for it; the original strict replacement
benefit criterion remains infeasible. No threshold or reference is retuned.
Full live owner/all-18 qualification, admitted adapter-error fallback, operational
updates, measured benefit, activation, target execution and persistence remain open.
