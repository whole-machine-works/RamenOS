# C2 recovery correspondence fixture

`recovery-c2.wasm` is the 1,347-byte Newcomputer C2 artifact, SHA-256
`fbcceae4411b17f2e517a8539991bfb41b097b2aa2b037ca58a828972a3b3ce4`.
It was built from Newcomputer `45060d06c644afa7be0023a91c763915c32c6e2a`
and reproduced from a separate clean, cache-free checkout using the same pinned
CPython3.14.8 and uv0.12.23. Both builds produced identical bytes. The independent
rebuild receipt has SHA-256
`06d6496f60a2c987e5bff90525cb2cf212a770157be71416621121afd04b19b7`.

The fixed registration and independently specified typed observations are in
`tools/recovery_c2/registration-v1.json` and `typed-expectations-v1.json`.
The original R0 corpus remains in Newcomputer `recovery/r0-v1/cases.json`:
611,903 bytes, SHA-256
`84eece3246d9b4521a5b8ac48fa6324cb4be4e98889277ab46837f6764aeda49`.
The ABI digest is
`49daf52dd669411376770b3bc2a007d7c6a8b346843bcd123a45da8139b0da60`.

This is a test/staging fixture. Store's preparation allowlist still admits only
C1; no runtime selection or update/rollback is enabled by adding this file.
See [the technical record](../../../../docs/plans/recovery-c2-correspondence-2026-11-08.md)
for the exact recorded execution and its limits. Ordinary CI checks the fixture
bytes and synthetic harness controls; the registered candidate run stays explicit.
