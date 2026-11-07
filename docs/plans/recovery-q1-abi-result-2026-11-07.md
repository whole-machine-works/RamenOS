# Recovery T1 — accepted technical ABI result

Independent final review accepted one Darwin arm64 run of the six frozen
malformed ABI calls. Each returned `1` without trapping and left its entire
65,536-byte memory page unchanged. Each was followed by a separate fresh
canonical instance returning `0`, with exact output
`00000000100000000100000000000000` and unchanged surrounding memory.
All 24 full before/after pages were independently derived and checked.

This closes the technical call-refusal and fresh-instance portion for the
recorded platform and candidate. It does not establish retained Store owners,
authority, unrelated-session progress, full Q1, measured benefit or activation.
The [closeout sequence](recovery-q1-runtime-preparation-2026-11-06.md)
retains those receiving obligations.

## Exact execution and evidence

| Identity | Value |
| --- | --- |
| Executed RamenOS source | `51c71bfdd8af7c4451b260d242c0e9329fcc7d8d` |
| Executed Newcomputer source | `b24ecbccc7ac3fb656f88d6feeb6c3b82fe953c5` |
| Unchanged candidate, 1,349 bytes | `6458a173cd09e73fe0be59b1a2d339c2070c33ac05628b3d2dd5fb264cb2e079` |
| T1 manifest, 3,538 bytes | `0f486a30510462344d21c80cbab60c9904e286727e28e31a6f38dec58b62313c` |
| Actual executable, 47,486,576 bytes | `d769743d7990e05ca9123362e7413f967200338d64fbd16cc7dead44cd14f9be` |
| Reviewed execution plan v2 | `6132f05dedec1b37898cac58e94f63b006db5ee01534dea7548a35c030deb971` |
| Raw engine result, 3,147,564 bytes | `d8399f5ae0e5e8e10fd5284b1916dba0e8338de060233fa7fdf2c475c5f20f1c` |
| Execution summary | `663b6a6f29ba3c92fcf8c3a3544d6ea16c3d118f600d38bc650c61c04fc4c9d2` |
| Post-execution checks | `ed7dc7bf665f745f7ade0e68bffce141ab74b0ee547fb30b9a03dc167e9debd2` |
| Final 72-file inventory | `399989bdb3618ee91022345b53a2ea8f82064072dd83a6c7d7c824842472cb88` |
| Pre-execution independent review | `b936a79282b07529b859db73f6d64ba9d7e61f7b5a4d6f71967c961521ac8172` |
| Final independent review | `60029e590aaa39e218ec5597f69d823906779cf220c3a38c6fdf1d582c1d4f52` |

Evidence remains under the Whole Machine Works workspace at
`evidence/recovery-q1-t1-20261106/evaluator-preparation.7hIt1ICj/`.
The final review is in `actual-review.v6ungzsl/review.json` in the same packet
root. The inventory was written after all writers stopped and excludes itself.
Earlier plans and manifest wording were retained with explicit successors.
The immutable attempt marker is a reservation; actual process records and raw
results establish execution.

The locked Wasmtime 27.0.0/Cranelift adapter used 100,000 fuel, a configured
32,768-byte Wasm stack and one fixed page, with a fresh Store/Instance per call.
The fixed 16-byte ABI output span was zeroed where legal before each snapshot;
capacity-15 still zeroed 16 bytes, while its sixteenth byte remained an
outside-capacity guard compared with that baseline.

The actual ignored test and planned verifier each ran once. Both and their
outer driver exited zero, completed group cleanup and were reaped. Postchecks
verified 12,339 tracked regular files, five generated inputs, exact tools,
locks, private inputs and executable, and both clean execution commits.
No retry or failed result was excluded. Ordinary CI selects synthetic controls
and does not invoke the ignored experiment.

Next, freeze and independently evaluate admission/fuel/stack/trap/output fixtures,
then complete independent Linux reproduction and genuine live-owner integration. The
registered update/rollback comparison and receiving activation remain separate.
