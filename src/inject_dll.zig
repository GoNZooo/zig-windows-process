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
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.skip();

    var process_buffer: [max_processes]ProcessId = undefined;
    const processes = try winprocess.enumerateProcesses(process_buffer[0..]);
    var chrome_process_buffer: [max_processes]ProcessId = undefined;
    const chrome_processes = try winprocess.getProcessesByName(
        processes,
        "chrome.exe",
        chrome_process_buffer[0..],
    );

    for (chrome_processes) |pid| {
        const exit_code = try winprocess.injectDll(pid, ".\\injected.dll");
        debug.warn("{} executed with exit code: {}\n", .{ pid, exit_code });
    }
}
