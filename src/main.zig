const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;

const win32 = @import("win32").c;
const psapi = @import("./psapi.zig");

const max_processes = 2048;

// pub fn injectDll(process: []const u8, dll: []const u8) !void {}

pub fn enumerateProcessesAlloc(allocator: *mem.Allocator) ![]win32.DWORD {
    var process_id_buffer: [max_processes]win32.DWORD = undefined;
    var needed_bytes: c_uint = undefined;
    if (psapi.EnumProcesses(
        &process_id_buffer,
        @sizeOf(@TypeOf(process_id_buffer)),
        &needed_bytes,
    ) == 0) return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(win32.DWORD);

    var processes = try allocator.alloc(win32.DWORD, number_of_processes);
    mem.copy(win32.DWORD, processes, process_id_buffer[0..number_of_processes]);

    return processes;
}

pub fn enumerateProcesses(processes: []win32.DWORD) ![]win32.DWORD {
    var needed_bytes: c_uint = undefined;
    if (psapi.EnumProcesses(
        processes.ptr,
        @sizeOf(win32.DWORD) * @intCast(c_ulong, processes.len),
        &needed_bytes,
    ) == 0) return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(win32.DWORD);

    return processes[0..number_of_processes];
}

pub fn main() anyerror!void {
    const process_id = null;
    const access = win32.PROCESS_CREATE_THREAD | win32.PROCESS_QUERY_INFORMATION |
        win32.PROCESS_VM_READ | win32.PROCESS_VM_WRITE | win32.PROCESS_VM_OPERATION;
    var process_buffer: [max_processes]win32.DWORD = undefined;
    const processes = try enumerateProcessesAlloc(heap.page_allocator);
    const processes_on_stack = try enumerateProcesses(process_buffer[0..]);
    for (processes_on_stack) |p| {
        debug.warn("p={}\n", .{p});
    }
    debug.warn("processes.len={}\n", .{processes_on_stack.len});
    // var process = win32.OpenProcess(access, win32.FALSE, process_id);
}
