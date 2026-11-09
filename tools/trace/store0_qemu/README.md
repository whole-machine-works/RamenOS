# Instrumented QEMU for the STORE0 Linux Oracle

Apply these three patches in order to a private copy of the upstream QEMU 8.2.2
release. The verified source tarball has SHA-256
`847346c1b82c1a54b2c38f6edbd85549edeb17430b7d4d3da12620e2962bc4f3`.
Verify the release signature with the published QEMU release key and the patch
hashes in [SHA256SUMS](SHA256SUMS) before applying. The patches preserve the
existing device and guest-memory operations and add observations at those
operations.

- `01-device.patch` records negotiated block features, FLUSH submission, and
  the actual backend callback result.
- `02-marker.patch` records the guest's synchronous markers at the ISA debug
  console's byte-write callback.
- `03-used-ring.patch` records the existing split-ring element write result
  and direct writable guest RAM readbacks of the element and published index.
  The receiver rejects absent, indirect, or mismatched readbacks.

Build in an empty directory beside the patched source. Supply the checked
compiler, build dependencies, and `libfdt` headers and library in the build
environment. The development build used a private sysroot for `libfdt`.

```sh
PIP_NO_INDEX=1 ../qemu-8.2.2/configure --target-list=x86_64-softmmu \
  --disable-download --disable-docs --disable-tools --disable-gtk \
  --disable-sdl --disable-vnc --disable-slirp --disable-pixman \
  --disable-plugins --disable-werror --enable-trace-backends=log
ninja -j3 qemu-system-x86_64
```

Freeze the resulting executable, its actual loader and library paths and hashes,
the selected firmware files, and the guest kernel and initrd. The launcher
verifies those inputs under an explicit plan digest. Retain one global log stream
in source order. The existing block completion trace records the status at entry
to the completion path. The used-ring witness and the actual guest syscall
return supply separate observations.
