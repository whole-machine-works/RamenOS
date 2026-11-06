# Editor-process Linux prerequisite packet

2026-11-04. Preparation only; the editor carrier/child and complete P0 thirty-family
assertions remain unimplemented. This packet advances real kernel prerequisites
without releasing P1/P2. The frozen process ABI and existing four missing-API
consumers are unchanged.

## Assignment and independent review

The clean baseline is `e541f9f`. One coordinator owns integration, Cargo/lock,
gates, source registries and status. Worker `p0_assertions` owns only
`apps/artifact_editor/tests/process_support/linux_controls.rs`; `reviewer` is
the independent non-author. The other author slot independently prepared
Newcomputer recovery cases; it did not author this packet or its review.

Native test source SHA-256:
`0acf6a04391a089c136a3fb89a17fee3fbe54fd0bc178276e85e7147d29544f9`.
The reviewer inspected mapping/seal behavior, CMSG alignment and FD lifetimes,
actual kernel credentials, preprepared async-safe helper syscalls and genuine
helper wait cleanup. A descriptor-reuse race finding was resolved by forcing
serial harness execution and restoring the caller's test-thread environment.
No unresolved technical review finding remains in this primitive-only scope.

## Executable outcome

The default-off `process_linux_prerequisites` harness has six exact tests:

- A real writable mapping, including after `mprotect`, prevents WRITE sealing.
- FUTURE_WRITE does not freeze an already writable shared mapping.
- Both offered objects become immutable only after every writable alias closes;
  all four required seals block writes, growth and shrinkage.
- Ancillary truncation distinguishes the aliases actually received from those
  discarded by the kernel; received aliases have CLOEXEC and close on denial.
- An unprivileged forged SCM_CREDENTIALS send is rejected by the actual kernel.
- An inherited endpoint reports the owned helper's actual credential PID,
  rather than the socket creator or a payload PID; parent observes birth and
  obtains the helper's genuine terminal wait outcome.

These tests exercise kernel primitives and a test-only helper. They do not
exercise an editor carrier, adopt a publication, execute a registered held ELF,
or prove parent-death recovery. No full D-family coverage follows from them.

`just foundry-editor-process-linux-prerequisites-ui1-1d` refuses non-Linux
execution as `INCOMPLETE`, verifies all six selected and executed names, runs
locked strict Clippy, retains actual command exits/reaps and compares full source
manifests before/after. The hosted editor job invokes this supplemental gate
separately and retains its output. Canonical stage/assertion inventories remain
unchanged. Four affected source registries add exactly the new Rust file, with
reviewed successor pins; existing consumer assertions are preserved.

## Evidence and retained failures

Fresh Linux work uses `bigman`, unprivileged UID 1000, kernel
`6.8.0-142-generic`, x86_64, and pinned `nightly-2026-02-08` rustc
`1.95.0-nightly (c7f5f3e0d)`. Source, Cargo target and outputs are isolated under
`/tmp/ramen-team-p0-akiw4GVk`; no historical campaign location is reused.
Local retained evidence lives under `out/team-next-p0-*`.

- `native-001`: six actual kernel tests and strict Clippy pass. Its original
  identical before/after source manifest SHA-256 is
  `c6311ff4c1561064c42c177adbbe6c42ab6d5df8d671418512f5817f1e8bd90e`.
  A later preparation-driver change requires fresh final-source execution.
- `preparation-001`: initial setup failure at recording finalization is retained.
  The shared assertion helper discards the concrete RecordingError, so the
  original receipt does not establish its exact cause.
- `preparation-002`: the unchanged source passes with an explicit owner-only
  umask: thirteen setup controls, strict Clippy and actual expected missing-API
  compile exit 101 for the four public consumers. This remains preparation only.
- `macos-incomplete-001`: the native gate exits 2 with `INCOMPLETE`, demonstrating
  that an unsupported host cannot produce a zero-test native pass.

The preparation driver now sets umask077 around its private fixture command and
restores the caller's umask even on failure. Final-source native, preparation and
affected-editor receipts are retained separately; their source manifests, rather
than the earlier run's status, bind their tested inputs. Final caller-umask022
execution passes in `out/team-next-p0-native-final-002` (six actual tests, strict
Clippy; identical source manifest SHA-256
`8ea689787f77006aeb70dc14821591ed72d6311e53752b892bb43544a142f05a`)
and `out/team-next-p0-preparation-final-003` (thirteen controls, strict Clippy,
four missing-API consumers; identical source manifest SHA-256
`fd1cbce7516dc51871ff366b7de84608d41885f31cf25001bedbdabff09b063f`).
The direct diagnostic launcher reports umask002; the same pinned Rust tempfile
call produces mode0775, consistent with the recorder's rejection of writable
group/world bits. The diagnostic did not modify repository source.

Local `s11`, `s12`, `s13` and `foundry-org-governance-g0` pass serially, with logs
and hashes under `out/team-next-planning-checks-001`. These are default
QEMU/docs/scaffold checks. Appliance execution is skipped; vector-backed IO is
not device IO. Hosted, full Linux, target and physical qualification remain
separate from these local results.

### Complete strict Linux qualification

The complete `just preflight` run passes all **56 canonical stages**, including
original18/Reader93, every affected editor consumer, S11/S12/S13, governance and
final editor reliability. The exact stage inventory, exit 0 results, actual reaps
and `cleanup_uncertain=false` records are retained in
`out/team-next-p0-full-final-004-receipts/canonical-stages.json`; the main receipt,
raw command logs, environment audit and source/lock identity records are adjacent.
The full runtime outputs and earlier failed attempts are retained separately.

The immutable qualification snapshot is
`5db7e8b8586d2bfeef3bea6bffb1523d068fa906`, a disposable source-copy commit,
not a shared-branch commit or merge. Its unchanged preflight source fingerprint
is `e0cef491e29b5d1f4e121b2ddcb7fd813c67a6c3b2200deb959b7f26e93927a5`;
Cargo.lock remains
`44a1bccc5d6c602500e3b3b91dcab928fd37e46aca3f55c86ed09ccfe4c5d7b4`.
`out/team-next-p0-qualification-snapshot.bundle` retains that exact source, with
SHA-256 `0841fcb8e916c0789f77740687e19e260452eaec91de3d038b0ae98ea07d5f85`.
Only this plan's evidence prose was updated after that source freeze; executable
sources, gates, registries, contracts and locks match the tested snapshot.

The environment uses the pinned toolchain, builtin Docker seccomp and exact
proof image, matching OVMF 4M templates, two Cargo jobs, serial tests, umask022,
`RAMEN_CI_STRICT=1` and `LINT_ALLOW_WARNINGS=0`. The existing CI/stage-selected
`SKIP_E2E_ASSERTIONS=1` profile is preserved. The CI-pinned readable kernel
package was copied from retained bytes into fresh output and verified/extracted
by the existing helper; no historical input was overwritten.

Retained earlier failures identify setup limits: absent proof image, missing
HEAD in the isolated source copy, a boot script expecting canonical `target/`
instead of the initial external Cargo output, and an unreadable host `/boot`
kernel. The final run uses the normal repository bootstrap/profile and canonical
output layout; no product code, assertion or budget was changed to clear these
failures. This is local strict Linux host/Docker/QEMU qualification, separate
from hosted PR execution, editor-process acceptance and physical evidence.

## Remaining acceptance join

P0 still needs reviewed private fault/barrier ownership and executable assertions
for all thirty families: registered held-ELF preexec identity, authenticated
malformed carrier/FD enforcement, genuine map/offer/cap faults, native child
fault/stall, sole-supervisor uncertainty and uncertain parent death with real
parent SaveChains. Primitive fixtures cannot supply these runtime observations.
After complete P0 assertion review, dispatch disjoint P1 carrier and P2 child
writers; P3 still waits for their combined acceptance.
