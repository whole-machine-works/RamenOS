# Checked C0 entry-stop prefix

Two parallel authors implemented the prior-entry token and asynchronous
transport prefix against `331a7fa4209a945d88847d7e7a9203d014c91299`.
Independent source review accepted both before integration. This is executable
host socket preparation; no new VM, actual entry stop or guest-memory read ran.

The pure token factory reuses the complete profile/admission/diagnostic proof.
It accepts exact native references and bytes, recomputes the sole candidate and
returns an immutable prior-run hint. Missing referenced bytes remain incomplete;
contradictory saved-admission evidence is denied. It has no raw address
constructor, acquiring callback or live-read authority.

After reset setup, the wire accepts that token, installs one candidate-derived
hardware breakpoint and sends one continue. It records the actual request ACK,
waits silently for the exact asynchronous stop and sends one separate stop ACK.
A separate confirmation requires a fresh QMP debug reply and the complete
same-QMP RESUME/STOP bracket. Cross-socket events retain actual recognition
order, including equal-clock observations. The original continue-start deadline,
shared operation/event/ACK/storage caps, actual raw prefixes and first failure
survive faults. Extra or partial stop tails are rejected before acknowledgment.

The closed RTC policy follows the exact invocation: VAPIC-off uses
`device[1]/rtc`; both older profiles retain `device[2]/rtc`. The policy is
source-derived and bound to actual prior streams. Host and C0 replay pass the
verified invocation through the same policy and reject the other profile's path.

## Validation and retained identities

All 253 trace controls pass on the exact Linux snapshot. macOS passes 251 with
the two existing Linux-only skips. This includes twelve token controls and
twenty-two new entry-stop/RTC controls. The coordinator separately ran those
new controls. All three historical reset witnesses replay unchanged. The complete
tooling gate passes, including its Rust content-stability controls.

The Whole Machine Works workspace retains the packet under
`evidence/run0-c0-entry-20261106/`:

- `token.handoff.json` and `token.coordinator-review.json` bind both token files
  and their RED/GREEN controls.
- `wire.handoff.json`, digest
  `12c627dc1c63f8574996e550a6470b17e9cd29a6a42f4101fa00bb75133713ec`,
  binds six author files, the exact private Linux snapshot, commands and logs.
- `wire.patch`, digest
  `24b60792996a157a650da50a11bd6bdea33b68018bc446929cd2c906b3f15d39`,
  is the frozen wire/replay change. `wire.coordinator-review.json` records
  non-author acceptance and `wire.historical-reset-replay.json` the three replays.
- `tooling-integrated.log` retains the complete tooling result. Failed setup,
  fixture and propagation controls remain alongside successful evidence.

## Next consumer

Use the separately accepted
[source persistence condition](run0-c0-source-persistence-2026-11-06.md).
The collector must bind actual owned launch/profile identity before using the
prefix on a VM. Then obtain current stopped registers, physical mode, same-stop
host witness and current FlatView before admitting RAM reads. The acquisition
driver and typed read hook, final after-state checks, breakpoint removal, owned
teardown and whole-run replay remain unfinished. A socket prefix or prior hint
cannot complete C0. C1/C2 and target execution remain subsequent work.
