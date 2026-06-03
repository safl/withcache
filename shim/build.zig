const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const want_static = b.option(
        bool,
        "static",
        "Link statically (use with -Dtarget=x86_64-linux-musl / aarch64-linux-musl)",
    ) orelse false;

    const mod = b.createModule(.{
        .root_source_file = b.path("shim.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = optimize != .Debug,
    });
    const exe = b.addExecutable(.{ .name = "fromcache-shim", .root_module = mod });
    if (want_static) exe.linkage = .static;
    b.installArtifact(exe);
}
