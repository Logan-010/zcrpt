# zcrpt

`zcrpt` is a tripple-s (simple small speedy) zero configuration cli encryption
tool. It is designed to be very simple for users, along with being as small and
fast as possible.

`zcrpt` is written in pure zig and utilizes modern cryptography for 100% secure
en/decryption. All code is written entirely by a human and follows the `zig zen`
philosophy. Code is entirely open source, and in fact, public domain.

If this isn't enough for you it's also cross-platform (any posix target
supported by the zig compiler, and windows!), zero-dependancy, uses only 4.9MB
of memory when en/decrypting a file, and encrypts at a staggaring ~7.0667 Gbps
rate (tested on amd64 windows, ReleaseFast binary, encrypting a 15.9GB file).

# Building

_Currently_ built on zig version `v0.16.0-dev.2682+02142a54d`.

Build using the simple and amazing zig build system.

```sh
# Build the file with "ReleaseSafe" optimizations (also can build with "ReleaseSmall" or "ReleaseFast" build modes) and the "native" build mode (accepts any zig target, run "zig targets" to view supported targets)
zig build -Doptimize=ReleaseSafe -Dtarget=native
```
