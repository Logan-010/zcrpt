const std = @import("std");
const builtin = @import("builtin");
const aegis = std.crypto.aead.aegis;

const usage =
    \\zcrpt version 0.2.0
    \\
    \\zcrpt is a tripple-s (simple small speedy) zero configuration cli encryption
    \\tool. It is designed to be very simple for users, along with being as small and
    \\fast as possible.
    \\
    \\usage: zcrpt [flags]
    \\
    \\flags:
    \\  -e/d encrypt/decrypt mode
    \\  -i input path
    \\  -o output path (optional)
    \\
;

const salt_size = 32;
const key_size = 32;
const buf_size = 2 * 1024 * 1024;
const nonce_size = 32;
const u64_size = @sizeOf(u64);
const overhead = 32;
const capacity = (nonce_size - u64_size) + overhead + buf_size;

pub fn Cipher() @TypeOf(aegis.Aegis256_256) {
    const arch = builtin.target.cpu.arch;

    if (arch == .x86 or arch == .x86_64) {
        const has_avx512 = std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f) and std.Target.x86.featureSetHas(builtin.cpu.features, .vaes) and std.Target.x86.featureSetHas(builtin.cpu.features, .vpclmulqdq);

        const has_avx2 = std.Target.x86.featureSetHas(builtin.cpu.features, .avx2) and std.Target.x86.featureSetHas(builtin.cpu.features, .vaes) and std.Target.x86.featureSetHas(builtin.cpu.features, .vpclmulqdq);

        if (has_avx512) return aegis.Aegis256X4_256;
        if (has_avx2) return aegis.Aegis256X2_256;

        return aegis.Aegis256_256;
    }

    if (arch == .aarch64) {
        const has_crypto = std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes) and std.Target.aarch64.featureSetHas(builtin.cpu.features, .pmull);

        if (has_crypto) return aegis.Aegis256X2_256;

        return aegis.Aegis256_256;
    }

    if (arch == .powerpc64) {
        const has_altivec = std.Target.powerpc.featureSetHas(builtin.cpu.features, .altivec);

        if (has_altivec) return aegis.Aegis256X2_256;

        return aegis.Aegis256_256;
    }

    return aegis.Aegis256_256;
}

fn setEcho(io: std.Io, enable: bool) !void {
    switch (builtin.os.tag) {
        .windows => {
            const ENABLE_ECHO_MODE: u32 = 0x0004;

            var mode = std.os.windows.CONSOLE.USER_IO.GET_MODE;

            if (try mode.operate(io, std.Io.File.stdin()) != .SUCCESS) {
                return error.OperateFailed;
            }

            const newMode = if (enable) mode.Data | ENABLE_ECHO_MODE else mode.Data & ~ENABLE_ECHO_MODE;

            mode = std.os.windows.CONSOLE.USER_IO.SET_MODE(newMode);

            if (try mode.operate(io, std.Io.File.stdin()) != .SUCCESS) {
                return error.OperateFailed;
            }
        },
        .linux, .macos, .freebsd => {
            const fd = std.Io.File.stdin().handle;

            var termios = try std.posix.tcgetattr(fd);

            termios.lflag.ECHO = enable;

            try std.posix.tcsetattr(fd, .NOW, termios);
        },
        else => {},
    }
}

fn getPassword(io: std.Io, allocator: std.mem.Allocator, reprompt: bool) ![]u8 {
    try setEcho(io, false);
    defer setEcho(io, true) catch @panic("Failed to re-enable terminal echo");

    var stdin_buf: [1024]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &stdin_buf);

    try std.Io.File.stdout().writeStreamingAll(io, "Enter password: ");

    const p1 = (try stdin.interface.takeDelimiter('\n')) orelse return error.PasswordTooLong;

    try std.Io.File.stdout().writeStreamingAll(io, "\n");

    const p1out = try allocator.dupe(u8, p1);
    errdefer allocator.free(p1out);

    if (reprompt) {
        try std.Io.File.stdout().writeStreamingAll(io, "One more time: ");

        const p2 = (try stdin.interface.takeDelimiter('\n')) orelse return error.PasswordTooLong;

        try std.Io.File.stdout().writeStreamingAll(io, "\n");

        if (!std.mem.eql(u8, p1out, p2)) {
            return error.PasswordsDontMatch;
        }
    }

    return p1out;
}

const Cli = struct {
    mode: enum { Encrypt, Decrypt, Help } = .Help,
    input: ?[]const u8 = null,
    output: ?[]const u8 = null,

    const Self = @This();
    const Error = error{ MissingInput, MissingOutput };

    fn parse(args: []const [:0]const u8) Error!Self {
        var out: Self = .{};

        var nextIsInput = false;
        var nextIsOutput = false;
        for (args) |arg| {
            if (nextIsInput) {
                out.input = arg;
                nextIsInput = false;
                continue;
            }
            if (nextIsOutput) {
                out.output = arg;
                nextIsOutput = false;
                continue;
            }
            if (arg.len > 1 and arg[0] == '-') {
                for (arg[1..]) |code| {
                    switch (code) {
                        'e' => out.mode = .Encrypt,
                        'd' => out.mode = .Decrypt,
                        'i' => nextIsInput = true,
                        'o' => nextIsOutput = true,
                        'h' => out.mode = .Help,
                        else => {},
                    }
                }
            }
        }
        if (nextIsInput) {
            return Error.MissingInput;
        }
        if (nextIsOutput) {
            return Error.MissingOutput;
        }

        if (out.input == null and out.mode != .Help) {
            return Error.MissingInput;
        }

        return out;
    }
};

fn encrypt(io: std.Io, allocator: std.mem.Allocator, input: []const u8, output: ?[]const u8) !void {
    const password = try getPassword(io, allocator, true);
    defer allocator.free(password);

    var salt: [salt_size]u8 = undefined;
    io.random(&salt);

    var key: [key_size]u8 = undefined;
    try std.crypto.pwhash.argon2.kdf(allocator, &key, password, &salt, .owasp_2id, .argon2id, io);

    var inputFile = try std.Io.Dir.cwd().openFile(io, input, .{});
    defer inputFile.close(io);
    const total = try inputFile.length(io);

    var outputFile = if (output) |path| try std.Io.Dir.cwd().createFile(io, path, .{}) else blk: {
        const name = try std.fmt.allocPrint(allocator, "{s}.enc", .{input});
        defer allocator.free(name);
        break :blk try std.Io.Dir.cwd().createFile(io, name, .{});
    };
    defer outputFile.close(io);

    try outputFile.writeStreamingAll(io, &salt);

    var buf = try allocator.alloc(u8, capacity);
    defer allocator.free(buf);

    var counter: u64 = 0;
    var total_read: u64 = 0;

    const progress = std.Progress.start(io, .{ .root_name = "processing", .estimated_total_items = @as(usize, total) });
    defer progress.end();

    const cipher = Cipher();

    while (total_read < total) {
        const read = try inputFile.readStreaming(io, &[_][]u8{buf[(nonce_size - u64_size) + overhead ..]});

        if (read == 0) {
            break;
        }

        total_read += read;

        var nonce: [nonce_size]u8 = undefined;
        @memcpy(nonce[0..u64_size], std.mem.asBytes(&std.mem.nativeToBig(u64, counter)));
        io.random(nonce[u64_size..]);

        cipher.encrypt(buf[(nonce_size - u64_size) + overhead .. (nonce_size - u64_size) + overhead + read], buf[(nonce_size - u64_size) .. (nonce_size - u64_size) + overhead], buf[(nonce_size - u64_size) + overhead .. (nonce_size - u64_size) + overhead + read], &[_]u8{}, nonce, key);

        @memcpy(buf[0..(nonce_size - u64_size)], nonce[u64_size..]);

        try outputFile.writeStreamingAll(io, buf[0 .. (nonce_size - u64_size) + overhead + read]);

        counter += 1;

        progress.setCompletedItems(total_read);
    }
}

fn decrypt(io: std.Io, allocator: std.mem.Allocator, input: []const u8, output: ?[]const u8) !void {
    const password = try getPassword(io, allocator, false);
    defer allocator.free(password);

    var outputFile = if (output) |path| try std.Io.Dir.cwd().createFile(io, path, .{}) else blk: {
        const name = blk2: {
            if (std.mem.endsWith(u8, input, ".enc")) {
                break :blk2 try allocator.dupe(u8, input[0 .. input.len - 4]);
            }

            break :blk2 try std.fmt.allocPrint(allocator, "{s}.dec", .{input});
        };
        defer allocator.free(name);

        break :blk try std.Io.Dir.cwd().createFile(io, name, .{});
    };
    defer outputFile.close(io);

    var inputFile = try std.Io.Dir.cwd().openFile(io, input, .{});
    defer inputFile.close(io);
    const total = try inputFile.length(io);

    var salt: [salt_size]u8 = undefined;
    if (try inputFile.readStreaming(io, &[_][]u8{&salt}) != salt_size) {
        return error.FailedToReadSalt;
    }

    var key: [key_size]u8 = undefined;
    try std.crypto.pwhash.argon2.kdf(allocator, &key, password, &salt, .owasp_2id, .argon2id, io);

    const buf = try allocator.alloc(u8, capacity);
    defer allocator.free(buf);

    var counter: u64 = 0;
    var total_read: u64 = 32;

    const progress = std.Progress.start(io, .{ .root_name = "processing", .estimated_total_items = @as(usize, total) });
    defer progress.end();

    const cipher = Cipher();

    while (total_read < total) {
        const read = try inputFile.readStreaming(io, &[_][]u8{buf});

        if (read == 0) {
            break;
        }

        if (read < (nonce_size - u64_size) + overhead) {
            return error.ReadTooSmall;
        }

        total_read += read;

        var nonce: [nonce_size]u8 = undefined;

        @memcpy(nonce[0..u64_size], std.mem.asBytes(&std.mem.nativeToBig(u64, counter)));
        @memcpy(nonce[u64_size..], buf[0..(nonce_size - u64_size)]);

        var tag: [overhead]u8 = undefined;

        @memcpy(&tag, buf[(nonce_size - u64_size) .. (nonce_size - u64_size) + overhead]);

        try cipher.decrypt(buf[(nonce_size - u64_size) + overhead .. read], buf[(nonce_size - u64_size) + overhead .. read], tag, &[_]u8{}, nonce, key);

        try outputFile.writeStreamingAll(io, buf[(nonce_size - u64_size) + overhead .. read]);

        counter += 1;

        progress.setCompletedItems(total_read);
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    var runtime = std.Io.Threaded.init_single_threaded;
    defer runtime.deinit();

    const args = try init.args.toSlice(arena.allocator());
    const cli = try Cli.parse(args);

    switch (cli.mode) {
        .Help => {
            try std.Io.File.stdout().writeStreamingAll(runtime.io(), usage);
        },
        .Encrypt => {
            try encrypt(runtime.io(), gpa.allocator(), cli.input.?, cli.output);
        },
        .Decrypt => {
            try decrypt(runtime.io(), gpa.allocator(), cli.input.?, cli.output);
        },
    }
}
