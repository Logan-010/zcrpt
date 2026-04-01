# zcrpt

`zcrpt` is a triple-s (simple small speedy) zero configuration CLI encryption
tool. It is designed to be very simple for users, along with being as small and
fast as possible.

`zcrpt` is written in pure zig and utilizes modern cryptography for 100% secure
en/decryption. All code (and this readme :3) is written entirely by a human and
follows the `zig zen` philosophy. Code is entirely open source, and in fact,
public domain.

If this isn't enough for you it's also cross-platform (any posix target
supported by the zig compiler, and windows!), zero-dependancy, uses only ~4.9MB
of memory when en/decrypting a file, and encrypts at a staggering 13.658 Gb/s*
rate.

*`ReleaseFast` binary with `native` target (x86_64 Windows 11 with Intel 13900K
CPU), encrypting a 15.9GB file. Very isolated test, do your own!

# Get started

**For far superior performance, please compile from source. Its not hard I
promise!**

Download a precompiled binary from
[here](https://github.com/Logan-010/zcrpt/releases/latest).

For building from source see
[Building](https://github.com/Logan-010/zcrpt#Building).

# Building

_Currently_ built on `zig` version `v0.16.0-dev.2682+02142a54d`.

Requires `zig` compiler installed and added to path along with `git` (for
cloning project).

Build using the simple and amazing zig build system.

**Highly** recommended to build with `ReleaseSafe` optimizations and `native`
build target to provide a balance of safety and performance, however for
absolute maximum performance build with `ReleaseFast` optimizations and `native`
build target.

```sh
# Clone source
git clone https://github.com/Logan-010/zcrpt

# Open source directory
cd zcrpt

# Build the file with "ReleaseSafe" optimizations (also can build with "ReleaseSmall" or "ReleaseFast" build modes) and the "native" build mode (accepts any zig target, run "zig targets" to view supported targets)
zig build -Doptimize=ReleaseSafe -Dtarget=native
```
