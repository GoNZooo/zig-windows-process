const std = @import("std");
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const Abi = std.Target.Abi;

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{ .default_target = CrossTarget{ .abi = Abi.gnu } });

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("find-processes", "src/main.zig");
    exe.linkLibC();
    exe.linkSystemLibrary("kernel32");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    // const lib = b.addSharedLibrary("injected", "src/injected.zig", .{ .major = 0, .minor = 1 });
    // lib.linkLibC();
    // lib.linkSystemLibrary("msvcrt");
    // lib.addPackagePath("win32", "./dependencies/zig-win32/src/main.zig");
    // lib.setTarget(target);
    // lib.setBuildMode(mode);
    // lib.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
