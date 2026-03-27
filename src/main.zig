const std = @import("std");
const Cipher = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;
const builtin = @import("builtin");

const usage =
    \\zcrpt version 0.1.0
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

const heap_size = 3 * 1024 * 1024;
const salt_size = 32;
const key_size = Cipher.key_length;
const buf_size = 2 * 1024 * 1024;
const nonce_size = Cipher.nonce_length;
const overhead = Cipher.tag_length;
const capacity = nonce_size + overhead + buf_size;

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
        else => {
            const fd = std.Io.File.stdin().handle;

            var termios = try std.posix.tcgetattr(fd);

            termios.lflag.ECHO = enable;

            try std.posix.tcsetattr(fd, .NOW, termios);
        },
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

    const progress = std.Progress.start(io, .{ .root_name = "processing", .estimated_total_items = 1 });
    const cipher = progress.startFmt(@as(usize, total), "encrypting {s}", .{input});
    defer cipher.end();

    while (total_read < total) {
        const read = try inputFile.readStreaming(io, &[_][]u8{buf[nonce_size + overhead ..]});

        if (read == 0) {
            break;
        }

        total_read += read;

        var nonce: [nonce_size]u8 = undefined;
        io.random(&nonce);

        Cipher.encrypt(buf[nonce_size + overhead .. nonce_size + overhead + read], buf[nonce_size .. nonce_size + overhead], buf[nonce_size + overhead .. nonce_size + overhead + read], std.mem.asBytes(&counter), nonce, key);

        @memcpy(buf[0..nonce_size], &nonce);

        try outputFile.writeStreamingAll(io, buf[0 .. nonce_size + overhead + read]);

        counter += 1;

        cipher.setCompletedItems(total_read);
    }
}

fn decrypt(io: std.Io, allocator: std.mem.Allocator, input: []const u8, output: ?[]const u8) !void {
    const password = try getPassword(io, allocator, false);
    defer allocator.free(password);

    var outputFile = if (output) |path| try std.Io.Dir.cwd().createFile(io, path, .{}) else blk: {
        var iter = std.mem.splitSequence(u8, input, ".enc");

        var name: ?[]u8 = null;
        defer if (name) |n| allocator.free(n);

        var n = iter.next();
        while (n) |next| {
            n = iter.next();

            if (n == null) {
                break;
            }

            const oldN = name;
            name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ name orelse "", next });
            if (oldN) |oN| {
                allocator.free(oN);
            }
        }

        break :blk try std.Io.Dir.cwd().createFile(io, name orelse return error.InvalidFilename, .{});
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

    const progress = std.Progress.start(io, .{ .root_name = "processing", .estimated_total_items = 1 });
    const cipher = progress.startFmt(@as(usize, total), "decrypting {s}", .{input});
    defer cipher.end();

    while (total_read < total) {
        const read = try inputFile.readStreaming(io, &[_][]u8{buf});

        if (read == 0) {
            break;
        }

        if (read < nonce_size + overhead) {
            return error.ReadTooSmall;
        }

        total_read += read;

        var nonce: [nonce_size]u8 = undefined;

        @memcpy(&nonce, buf[0..nonce_size]);

        var tag: [overhead]u8 = undefined;

        @memcpy(&tag, buf[nonce_size .. nonce_size + overhead]);

        try Cipher.decrypt(buf[nonce_size + overhead .. read], buf[nonce_size + overhead .. read], tag, std.mem.asBytes(&counter), nonce, key);

        try outputFile.writeStreamingAll(io, buf[nonce_size + overhead .. read]);

        counter += 1;

        cipher.setCompletedItems(total_read);
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var stf = std.heap.stackFallback(heap_size, gpa.allocator());
    const allocator = stf.get();
    var arena = std.heap.ArenaAllocator.init(allocator);
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
            try encrypt(runtime.io(), allocator, cli.input.?, cli.output);
        },
        .Decrypt => {
            try decrypt(runtime.io(), allocator, cli.input.?, cli.output);
        },
    }
}
