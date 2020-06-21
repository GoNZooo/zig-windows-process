const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const process = std.process;

// const win32 = @import("win32").c;
const psapi = @import("./psapi.zig");

const max_processes = 2048;

const ProcessId = win32.DWORD;

// pub fn injectDll(process: []const u8, dll: []const u8) !void {}

pub fn enumerateProcessesAlloc(allocator: *mem.Allocator) ![]ProcessId {
    var process_id_buffer: [max_processes]ProcessId = undefined;
    var needed_bytes: c_uint = undefined;
    if (psapi.EnumProcesses(
        &process_id_buffer,
        @sizeOf(@TypeOf(process_id_buffer)),
        &needed_bytes,
    ) == 0) return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(ProcessId);

    var processes = try allocator.alloc(ProcessId, number_of_processes);
    mem.copy(ProcessId, processes, process_id_buffer[0..number_of_processes]);

    return processes;
}

pub fn enumerateProcesses(processes: []ProcessId) ![]ProcessId {
    var needed_bytes: c_uint = undefined;
    if (psapi.EnumProcesses(
        processes.ptr,
        @sizeOf(ProcessId) * @intCast(c_ulong, processes.len),
        &needed_bytes,
    ) == 0) return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(ProcessId);

    return processes[0..number_of_processes];
}

pub fn getProcessByName(processes: []ProcessId, name: []const u8) !?ProcessId {
    var process_name: [psapi.MAX_PATH]psapi.TCHAR = undefined;
    var process_handle: psapi.HANDLE = undefined;

    for (processes) |process_id| {
        process_handle = psapi.OpenProcess(
            psapi.PROCESS_QUERY_INFORMATION | psapi.PROCESS_VM_READ,
            psapi.FALSE,
            process_id,
        );

        if (process_handle != null) {
            var module: psapi.HMODULE = undefined;
            var bytes_needed: psapi.DWORD = undefined;
            if (psapi.EnumProcessModules(
                process_handle,
                &module,
                @sizeOf(@TypeOf(module)),
                &bytes_needed,
            ) != 0) {
                const length_copied = psapi.GetModuleBaseNameA(
                    process_handle,
                    module,
                    &process_name[0],
                    @sizeOf(@TypeOf(process_name)) / @sizeOf(psapi.TCHAR),
                );
                const name_slice = process_name[0..length_copied];

                if (mem.eql(u8, name_slice, name)) return process_id;
            } else {
                return error.UnableToEnumerateModules;
            }
        }
    }

    return null;
}

const access = psapi.PROCESS_CREATE_THREAD | psapi.PROCESS_QUERY_INFORMATION |
    psapi.PROCESS_VM_READ | psapi.PROCESS_VM_WRITE | psapi.PROCESS_VM_OPERATION;

pub fn main() anyerror!void {
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.skip();

    var process_buffer: [max_processes]ProcessId = undefined;
    const processes = try enumerateProcesses(process_buffer[0..]);

    while (arg_iterator.next(heap.page_allocator)) |process_name| {
        const process_id = try getProcessByName(processes, try process_name);
        if (process_id) |pid| {
            debug.warn("{}: {}\n", .{ process_name, pid });
        } else {
            debug.warn("{}: N/A\n", .{process_name});
        }
    }
    // var process = psapi.OpenProcess(access, psapi.FALSE, process_id);
}

test "can enumerate processes with dynamic allocation" {
    const processes = try enumerateProcessesAlloc(heap.page_allocator);
    testing.expect(processes.len != 0);
}
