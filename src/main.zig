const std = @import("std");
const builtin = @import("builtin");

const Cipher = std.crypto.aead.aes_gcm_siv.Aes256GcmSiv;

const usage =
    \\zcrpt: secure & fast encryption in your command line
    \\
    \\usage:
    \\  zcrpt MODE INPUT ?OUTPUT
    \\
    \\  MODE: encrypt, decrypt
    \\  INPUT: input file path
    \\  OUTPUT (optional): output file path
    \\
;

const capacity = 2 * 1024 * 1024;

fn setEchoW(enable: bool) !void {
    const windows = std.os.windows;
    const kernel32 = windows.kernel32;

    const stdout_handle = kernel32.GetStdHandle(windows.STD_INPUT_HANDLE) orelse return error.StdHandleFailed;

    var mode: windows.DWORD = undefined;
    _ = kernel32.GetConsoleMode(stdout_handle, &mode);

    const ENABLE_ECHO_MODE: u32 = 0x0004;
    const new_mode = if (enable) mode | ENABLE_ECHO_MODE else mode & ~ENABLE_ECHO_MODE;
    _ = kernel32.SetConsoleMode(stdout_handle, new_mode);
}

fn setEchoL(enable: bool) !void {
    const fd = std.Io.File.stdin().handle;
    var termios: std.posix.termios = try std.posix.tcgetattr(fd);
    termios.lflag.ECHO = enable;
    try std.posix.tcsetattr(fd, .NOW, termios);
}

fn setEcho(enable: bool) !void {
    switch (builtin.os.tag) {
        .windows => setEchoW(enable) catch {},
        else => setEchoL(enable) catch {},
    }
}

fn getPassword(io: std.Io, allocator: std.mem.Allocator, reprompt: bool) ![]u8 {
    try setEcho(false);
    defer setEcho(true) catch |e| @panic(e);

    var stdin_buf: [1024]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &stdin_buf);

    try std.Io.File.stdout().writeStreamingAll(io, "Enter password: ");

    const p1Slice = (try stdin.interface.takeDelimiter('\n')).?;

    try std.Io.File.stdout().writeStreamingAll(io, "\n");

    const p1 = try allocator.alloc(u8, p1Slice.len);
    std.mem.copyForwards(u8, p1, p1Slice);

    if (reprompt) {
        try std.Io.File.stdout().writeStreamingAll(io, "(Re)enter password: ");

        const p2 = (try stdin.interface.takeDelimiter('\n')).?;

        try std.Io.File.stdout().writeStreamingAll(io, "\n");

        if (!std.mem.eql(u8, p1, p2)) {
            return error.PasswordsDontMatch;
        }
    }

    return p1;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    var runtime = std.Io.Threaded.init_single_threaded;

    const args = try init.args.toSlice(arena.allocator());

    if (args.len < 3) {
        try std.Io.File.stdout().writeStreamingAll(runtime.io(), usage);
        return;
    }

    const mode = args[1];
    const inputPath = args[2];
    var outputPath: ?[:0]const u8 = null;
    if (args.len > 3) {
        outputPath = args[3];
    }

    if (std.mem.eql(u8, mode, "encrypt")) {
        try encrypt(runtime.io(), gpa.allocator(), inputPath, outputPath);
    } else if (std.mem.eql(u8, mode, "decrypt")) {
        try decrypt(runtime.io(), gpa.allocator(), inputPath, outputPath);
    } else {
        try std.Io.File.stdout().writeStreamingAll(runtime.io(), "invalid mode, expected encrypt or decrypt");
        return;
    }
}

fn encrypt(io: std.Io, allocator: std.mem.Allocator, input: []const u8, output: ?[]const u8) !void {
    const password = try getPassword(io, allocator, true);
    defer allocator.free(password);

    var salt: [32]u8 = undefined;
    io.random(&salt);

    var key: [32]u8 = undefined;
    try std.crypto.pwhash.argon2.kdf(allocator, &key, password, &salt, .owasp_2id, .argon2id, io);

    var outputFile: std.Io.File = undefined;
    if (output) |outPath| {
        outputFile = try std.Io.Dir.cwd().createFile(io, outPath, .{});
    } else {
        const baseName = std.fs.path.basename(input);
        var name = std.Io.Writer.Allocating.init(allocator);
        defer name.deinit();

        try name.writer.print("{s}.enc", .{baseName});

        outputFile = try std.Io.Dir.cwd().createFile(io, name.written(), .{});
    }
    defer outputFile.close(io);

    try outputFile.writeStreamingAll(io, &salt);

    var inputFile = try std.Io.Dir.cwd().openFile(io, input, .{});
    defer inputFile.close(io);
    const total = try inputFile.length(io);

    var dataBuf = try allocator.alloc(u8, capacity + Cipher.nonce_length + Cipher.tag_length);
    defer allocator.free(dataBuf);

    const buf = try allocator.alloc(u8, capacity);
    defer allocator.free(buf);
    var reader = inputFile.readerStreaming(io, buf);

    var counter: u64 = 0;
    var total_read: u64 = 0;

    var stdout_buf: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buf);

    const startTime = @as(f32, @floatFromInt(std.Io.Timestamp.now(io, .awake).toMilliseconds()));

    while (total_read < total) {
        const read = try reader.interface.readSliceShort(dataBuf[Cipher.nonce_length + Cipher.tag_length ..]);

        if (read == 0) {
            break;
        }

        total_read += read;

        var nonce: [Cipher.nonce_length]u8 = undefined;
        io.random(&nonce);

        Cipher.encrypt(dataBuf[Cipher.nonce_length + Cipher.tag_length .. Cipher.nonce_length + Cipher.tag_length + read], dataBuf[Cipher.nonce_length .. Cipher.nonce_length + Cipher.tag_length], dataBuf[Cipher.nonce_length + Cipher.tag_length .. Cipher.nonce_length + Cipher.tag_length + read], std.mem.asBytes(&counter), nonce, key);

        std.mem.copyForwards(u8, dataBuf[0..Cipher.nonce_length], &nonce);

        counter += 1;

        try outputFile.writeStreamingAll(io, dataBuf[0 .. Cipher.nonce_length + Cipher.tag_length + read]);

        try stdout.interface.print("\r%{d:.2} complete", .{(@as(f32, @floatFromInt(total_read)) / @as(f32, @floatFromInt(total))) * 100});
    }

    const endTime = @as(f32, @floatFromInt(std.Io.Timestamp.now(io, .awake).toMilliseconds()));

    try stdout.interface.print("\nfinished in {d:.2} seconds.\n", .{(endTime - startTime) / 1000});
    try stdout.interface.flush();
}

fn decrypt(io: std.Io, allocator: std.mem.Allocator, input: []const u8, output: ?[]const u8) !void {
    const password = try getPassword(io, allocator, false);
    defer allocator.free(password);

    var outputFile: std.Io.File = undefined;
    if (output) |outPath| {
        outputFile = try std.Io.Dir.cwd().createFile(io, outPath, .{});
    } else {
        const baseName = std.fs.path.basename(input);
        var iter = std.mem.splitAny(u8, baseName, ".enc");
        const name = iter.next() orelse "out";

        outputFile = try std.Io.Dir.cwd().createFile(io, name, .{});
    }
    defer outputFile.close(io);

    var inputFile = try std.Io.Dir.cwd().openFile(io, input, .{});
    defer inputFile.close(io);
    const total = try inputFile.length(io);

    var dataBuf = try allocator.alloc(u8, capacity + Cipher.nonce_length + Cipher.tag_length);
    defer allocator.free(dataBuf);

    const buf = try allocator.alloc(u8, capacity);
    defer allocator.free(buf);
    var reader = inputFile.readerStreaming(io, buf);

    var salt: [32]u8 = undefined;
    try reader.interface.readSliceAll(&salt);

    var key: [32]u8 = undefined;
    try std.crypto.pwhash.argon2.kdf(allocator, &key, password, &salt, .owasp_2id, .argon2id, io);

    var counter: u64 = 0;
    var total_read: u64 = 32;

    var stdout_buf: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buf);

    const startTime = @as(f32, @floatFromInt(std.Io.Timestamp.now(io, .awake).toMilliseconds()));

    while (total_read < total) {
        const read = try reader.interface.readSliceShort(dataBuf);

        if (read == 0) {
            break;
        }

        if (read < Cipher.nonce_length + Cipher.tag_length) {
            return error.ReadTooSmall;
        }

        total_read += read;

        var nonce: [Cipher.nonce_length]u8 = undefined;

        std.mem.copyForwards(u8, &nonce, dataBuf[0..Cipher.nonce_length]);

        var tag: [Cipher.tag_length]u8 = undefined;

        std.mem.copyForwards(u8, &tag, dataBuf[Cipher.nonce_length .. Cipher.nonce_length + Cipher.tag_length]);

        try Cipher.decrypt(dataBuf[Cipher.nonce_length + Cipher.tag_length .. read], dataBuf[Cipher.nonce_length + Cipher.tag_length .. read], tag, std.mem.asBytes(&counter), nonce, key);

        counter += 1;

        try outputFile.writeStreamingAll(io, dataBuf[Cipher.nonce_length + Cipher.tag_length .. read]);

        try stdout.interface.print("\r%{d:.2} complete", .{(@as(f32, @floatFromInt(total_read)) / @as(f32, @floatFromInt(total))) * 100});
    }

    const endTime = @as(f32, @floatFromInt(std.Io.Timestamp.now(io, .awake).toMilliseconds()));

    try stdout.interface.print("\nfinished in {d:.2} seconds.", .{(endTime - startTime) / 1000});
    try stdout.interface.flush();
}
