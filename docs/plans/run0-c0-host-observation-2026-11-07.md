# C0 host-observation receiving adapter

The receiving adapter now connects the shared C0 wire to the existing owned
host-observation body. It preserves the reset wrapper and unchanged reader's
14-read/104-byte inventory. The new closed port supplies fresh selected-register,
peer, mode, host-bracket and layout receipts with actual operation identities.
No arbitrary command, register, address or caller completion flag is introduced.

One aggregate five-second lease covers peer observation, both fresh host
brackets, three helper processes and their closure. Both host brackets precede
the first physical read. The common selector continues monitoring while helpers
run and while an exited-pipe helper is still awaiting actual process completion.
Failure cleanup remains independent of a failed pump. Helper raw/derived
retention uses the original wire budget and original VM/stop deadlines.

The after-state path requires the exact held acquisition completion receipt,
actual registered binding, transport identity, epoch and deadline. It rejects
absent registration and explicitly synthetic bindings. Selected after-registers,
final HMP and final layout remain separate ordered operations. This packet adds
no production registration setter or current/after issuer.

## Validation and scope

All 25 new controls pass, including a shared-body flow with three actual owned
helpers reading private synthetic files, exactly 14 reads/104 bytes, real waits,
EOFs and closure. The protocol metadata remains synthetic. A sealed Linux run
passes all 296 trace controls with source hashes unchanged before and after;
194 focused macOS controls pass with one existing Linux-only skip. All three
historical reset witnesses replay unchanged. The non-author coordinator
inspected all six files and separately ran the 25 new controls.

Evidence is retained in the Whole Machine Works workspace under
`evidence/run0-c0-host-join-20261106/`:

| Record | SHA-256 |
| --- | --- |
| Six-file author patch, `host-001.patch` | `65698cb21859623ff36cd2a1e18b2294ba53bb4540cefb8122a47092f6ad426f` |
| Author handoff, `host-handoff-001.json` | `70d9384be0a16518b019c8d7832fff76bdfe61dabb44003a5d449fe06845d14b` |
| Sealed source manifest | `82747965eb4b7158e9050e3563636ef072267c11f97e038ceb160987fcba195b` |

`owned-source-001.sha256` binds all six source/test files;
`coordinator-source-review.json` records independent source acceptance.
The accepted acquisition pair and portable test were transferred unchanged
onto this integration baseline. Failed controls and successful evidence remain
retained separately.

The real collector still must bind its prepared owned launch and issue current
and after RAM bindings, reconcile shared wire/accounting and final-send checks,
retain the complete report and prove actual teardown. The retained-runtime C0
provenance guard remains closed until a separate reviewed C0 plan/observer/source
branch is integrated. No VM, live QEMU field read, guest-memory acquisition or
complete C0 is claimed here.
