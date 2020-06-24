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

    while (arg_iterator.next(heap.page_allocator)) |process_name| {
        const process_id = try winprocess.getProcessByName(processes, try process_name);
        if (process_id) |pid| {
            debug.warn("{}: {}\n", .{ process_name, pid });
        } else {
            debug.warn("{}: N/A\n", .{process_name});
        }
    }
}
