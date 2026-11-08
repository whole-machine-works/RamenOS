# UI2 fixed compositor placement prerequisite

`desktop_compositor_core` is a dependency-free, allocation-free `no_std` crate
for the current fixed BGRA profile. It places a 640×480 app image at rows 48–527
in an already owned 640×568 output, preserving both chrome regions and every
source alpha byte. An absent frame makes only the app region opaque white.
Short or oversized source/output slices fail before any write; a subsequent
valid operation remains usable. The caller retains allocation, authentication,
trusted chrome and publication ownership.

All three actual `HostDesktop` composition paths call the core: general,
Store-current preview and native Save. Their existing reservations, immutable
source capture, unavailable handling, pre/post authority checks, focus and
settlement ordering are unchanged. The dependency is optional behind the
existing default-off Desktop development feature. It is absent from the
standalone editor-child normal dependency graph.

Gate-first tests failed on the missing API before implementation. Three focused
pixel/refusal tests, strict core and host Clippy, the exact
`x86_64-unknown-none` check and all 13 existing host-editor assertions pass on
macOS. The same pure checks and all 13 host assertions pass on Linux, as do
the real Store-current preview and two native Save golden/unavailable cases.
The Linux host report initially failed because the staged source lacked Git
metadata; the failure is retained. Adding the actual baseline commit/tree
objects let the report validate the unchanged test output. Complete successor
CI qualification is pending. The existing
host-editor gate adds the core check, strict lint and tests; every prior command
and assertion remains. All four reviewed editor source inventories add the new
crate without dropping previous paths, and their fast admission controls pass.

This is a target-compatible pure computation prerequisite with real host
consumers. It does not establish target execution, scanout, hardware support,
framebuffer mapping or authority. RUN0 and the trusted framebuffer address,
length, stride, format and lifetime handoff remain prerequisites to a target
compositor and the unchanged human editing task in QEMU. No hardware values are
invented by this extraction.
