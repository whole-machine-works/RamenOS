# C0 acquisition driver — pure and typed preparation

The acquisition driver implements the suspended paging consumer needed after
the [entry-stop prefix](run0-c0-entry-prefix-2026-11-06.md). It uses the existing
PageWalk and ordinary-RAM admission helpers, translates each complete object
before requesting its data, validates the fixed eight PE/EFI objects, freezes
the discovered graph and physical splits, and rereads every frame and object
without walking or chasing pointers again. A completed changed reread fails
immediately. The existing retained-byte decoder independently checks the
assembled synthetic records.

Immutable bindings and one-use pending grants retain exact session, stop,
epoch, deadlines, raw identities and observed receipts. Shared reservations
precede lookup, growth and dispatch; the control tail reserves its actual
33 required operations. The completion verifier rechecks the exact singleton
and current session before after-state queries. Failure latches its first cause
and never refunds an uncertain consumed grant or retries it.

This packet supplies no production binding issuer, socket or live-read adapter.
Explicit synthetic bindings exercise the state machine and cannot establish
an owned current C0 join. Structural references or an origin string alone do
not establish runtime provenance.

## Validation and identities

Eighteen new controls and 39 unchanged decoder/paging/prior-token controls pass.
An independent non-author separately ran the eighteen controls, six paging and
21 decoder regressions, plus ancestor-NX, valid-CRC/null-BootServices and stale
receipt counterexamples. Complete synthetic receipts replay through the
unchanged object decoder and shared `decode_c0` envelope.

The Whole Machine Works workspace retains evidence under
`evidence/run0-c0-acquire-20261106/`. Source was transferred unchanged from the
author worktree to the integration and host-consumer worktrees.

| Artifact | SHA-256 |
| --- | --- |
| `tools/trace/run0_c0_acquire.py` | `1b8e02a1bc3bef735b33c6f18faf248f986d76315b56e9629589042ebf1ba673` |
| Original author test | `0811aa18bb7f886ef0cdfaf88bc8131f01961aa8ffd251f01dc92ee2a6791d36` |
| Portable integration test, `tools/trace/test_run0_c0_acquire.py` | `a59474ecd7a8cb820e0f52d4d5242e90b97c36d94765db6799883ee7547ad35a` |
| Retained two-file author patch | `7bfdfba88a99b2ccb672eebf343054bf90f9ddfa9e89ed3335aa8887cd3fa1a8` |
| Independent disposition, `review.disposition.json` | `3b91e33ef1e5c52c589b262ac4428aa8f56396a0ccc7f80238ddc7a1ae387f4b` |

The initial missing-implementation RED and intermediate failures remain in the
author's tool history. This record does not manufacture a separate replay log.

Integration review caught a user-specific fixture directory that would fail on
hosted Linux. The portable test uses the OS private temporary directory; its
assertions and production implementation are unchanged. Non-author delta review
accepted it, and all eighteen controls pass on a fresh Linux snapshot with
source hashes checked before and after. `linux-portable-controls.log` and
`linux-source.sha256` retain that separate validation.

## Receiving work

The owned collector must issue current and after bindings from actual launch,
profile, stopped state, same-stop host witness and current layout evidence.
The shared wire must reconcile its actual prefix/helper/physical/tail charges
with the reserved envelope, perform the final consume/revocation check at the
send boundary and propagate aborts. The reviewed runtime plan/source branch,
after-state checks, breakpoint removal, teardown and final retained report are
still required. No VM, guest-memory acquisition or complete C0 is claimed.
