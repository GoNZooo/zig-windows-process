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

    const find_process_exe = b.addExecutable("find-process", "src/find_process.zig");
    find_process_exe.linkLibC();
    find_process_exe.linkSystemLibrary("kernel32");
    find_process_exe.setTarget(target);
    find_process_exe.setBuildMode(mode);
    find_process_exe.install();

    const inject_dll_exe = b.addExecutable("inject-dll", "src/inject_dll.zig");
    inject_dll_exe.linkLibC();
    inject_dll_exe.linkSystemLibrary("kernel32");
    inject_dll_exe.setTarget(target);
    inject_dll_exe.setBuildMode(mode);
    inject_dll_exe.install();

    const tests = b.addTest("src/main.zig");

    const run_find_process_cmd = find_process_exe.run();
    run_find_process_cmd.step.dependOn(b.getInstallStep());

    const run_find_process_step = b.step("run-find-process", "Run the `find-process` app");
    run_find_process_step.dependOn(&run_find_process_cmd.step);

    const run_inject_dll_cmd = inject_dll_exe.run();
    run_inject_dll_cmd.step.dependOn(b.getInstallStep());

    const run_inject_dll_step = b.step("run-inject-dll", "Run the `inject-dll` app");
    run_inject_dll_step.dependOn(&run_inject_dll_cmd.step);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&tests.step);
}
