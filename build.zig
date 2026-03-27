const std = @import("std");

const targets = [_]std.Target.Query{ .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc }, .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu }, .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu }, .{ .cpu_arch = .aarch64, .os_tag = .macos, .abi = .none } };
const release_modes = [_]std.builtin.OptimizeMode{ .ReleaseSafe, .ReleaseFast, .ReleaseSmall };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zcrpt",
        .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .single_threaded = true, .strip = if (optimize == .Debug) false else true, .target = target, .optimize = optimize, .link_libc = false, .link_libcpp = false }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const release = b.step("release", "Build for all chosen targets and archetectures with all build types.");
    for (targets) |targetQuery| {
        const targetStr = targetQuery.zigTriple(b.allocator) catch @panic("out of memory :( get a better computer");
        const buildTarget = b.resolveTargetQuery(targetQuery);

        const name = std.fmt.allocPrint(b.allocator, "zcrpt-{s}", .{targetStr}) catch @panic("out of memory :( get a better computer");
        defer b.allocator.free(name);

        const buildExe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .single_threaded = true, .strip = true, .target = buildTarget, .optimize = .ReleaseSafe, .link_libc = false, .link_libcpp = false }),
        });

        const install = b.addInstallArtifact(buildExe, .{});

        release.dependOn(&install.step);
    }
}
