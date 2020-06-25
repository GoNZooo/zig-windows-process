const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const process = std.process;

const winprocess = @import("./main.zig");

const ProcessId = winprocess.ProcessId;

const max_processes = 2048;

pub fn main() anyerror!void {
    const args = try process.argsAlloc(heap.page_allocator);
    if (args.len != 3) {
        debug.warn("Usage: {} <dll-to-inject> <process-name>", .{args[0]});

        process.exit(1);
    }

    const dll_name = args[1];
    const process_name = args[2];

    var process_buffer: [max_processes]ProcessId = undefined;
    const processes = try winprocess.enumerateProcesses(process_buffer[0..]);
    var target_process_buffer: [max_processes]ProcessId = undefined;
    const target_processes = try winprocess.getProcessesByName(
        processes,
        process_name,
        target_process_buffer[0..],
    );

    for (target_processes) |pid| {
        const exit_code = try winprocess.injectDll(pid, dll_name);
        debug.warn("{} executed with exit code: {}\n", .{ pid, exit_code });
    }
}
