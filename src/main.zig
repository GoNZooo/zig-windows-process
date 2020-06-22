const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const process = std.process;

const ArrayList = std.ArrayList;

// const win32 = @import("win32").c;
const psapi = @import("./psapi.zig");

const max_processes = 2048;

const ProcessId = psapi.DWORD;

// @TODO: have this return null instead, maybe?
pub fn openProcess(access_rights: c_ulong, inherit_handle: bool, pid: ProcessId) !psapi.HANDLE {
    const win_bool: psapi.BOOL = if (inherit_handle) psapi.TRUE else psapi.FALSE;
    return if (psapi.OpenProcess(access_rights, win_bool, pid)) |handle|
        handle
    else
        error.UnableToOpenProcess;
}

// @TODO: have this return null instead, maybe?
pub fn getModuleHandle(name: []const u8) !psapi.HINSTANCE {
    return if (psapi.GetModuleHandleA("kernel32.dll")) |instance|
        instance
    else
        error.UnableToGetModuleHandle;
}

pub fn getProcAddress(module: psapi.HMODULE, name: []const u8) !fn (...) callconv(.C) c_longlong {
    return if (psapi.GetProcAddress(module, "LoadLibraryA")) |address|
        address
    else
        error.UnableToGetProcAddress;
}

pub fn virtualAllocEx(
    process_handle: psapi.HANDLE,
    starting_address: ?*c_ulong,
    size: usize,
    allocation_type: psapi.DWORD,
    protection: psapi.DWORD,
) !*c_ulong {
    return if (psapi.VirtualAllocEx(
        process_handle,
        starting_address,
        size,
        allocation_type,
        protection,
    )) |memory|
        @ptrCast(*c_ulong, @alignCast(@alignOf(*c_ulong), memory))
    else
        error.UnableToVirtualAllocEx;
}

pub fn writeProcessMemory(
    process_handle: psapi.HANDLE,
    starting_address: ?*c_ulong,
    buffer: [:0]const u8,
) !usize {
    var bytes_written: usize = undefined;
    return if (psapi.WriteProcessMemory(
        process_handle,
        starting_address,
        buffer.ptr,
        buffer.len,
        &bytes_written,
    ) != 0) bytes_written else error.UnableToWriteProcessMemory;
}

pub fn createRemoteThread(
    process_handle: psapi.HANDLE,
    thread_attributes: psapi.LPSECURITY_ATTRIBUTES,
    stack_size: ?usize,
    start_address: psapi.LPTHREAD_START_ROUTINE,
    parameter: psapi.LPVOID,
    flags: ?psapi.DWORD,
    thread_id: psapi.LPDWORD,
) !psapi.HANDLE {
    return if (psapi.CreateRemoteThread(
        process_handle,
        thread_attributes,
        if (stack_size) |size| size else 0,
        start_address,
        parameter,
        if (flags) |fs| fs else 0,
        thread_id,
    )) |thread_handle|
        thread_handle
    else
        error.UnableToCreateRemoteThread;
}

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
        process_handle = openProcess(
            psapi.PROCESS_QUERY_INFORMATION | psapi.PROCESS_VM_READ,
            false,
            process_id,
        ) catch |e| {
            switch (e) {
                error.UnableToOpenProcess => continue,
            }
        };

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

pub fn getProcessesByName(
    processes: []ProcessId,
    name: []const u8,
    buffer: []ProcessId,
) ![]ProcessId {
    var process_name: [psapi.MAX_PATH]psapi.TCHAR = undefined;
    var process_handle: psapi.HANDLE = undefined;

    var hits: usize = 0;
    for (processes) |process_id| {
        process_handle = openProcess(
            psapi.PROCESS_QUERY_INFORMATION | psapi.PROCESS_VM_READ,
            false,
            process_id,
        ) catch |e| {
            switch (e) {
                error.UnableToOpenProcess => continue,
            }
        };

        var module: psapi.HMODULE = undefined;
        var bytes_needed: psapi.DWORD = undefined;
        if (psapi.EnumProcessModulesEx(
            process_handle,
            &module,
            @sizeOf(@TypeOf(module)),
            &bytes_needed,
            psapi.LIST_MODULES_ALL,
        ) != 0) {
            const length_copied = psapi.GetModuleBaseNameA(
                process_handle,
                module,
                &process_name[0],
                @sizeOf(@TypeOf(process_name)) / @sizeOf(psapi.TCHAR),
            );
            const name_slice = process_name[0..length_copied];

            if (mem.eql(u8, name_slice, name)) {
                buffer[hits] = process_id;
                hits += 1;
            }
        } else {
            return error.UnableToEnumerateModules;
        }
    }

    return buffer[0..hits];
}

pub fn getProcessesByNameAlloc(
    allocator: *mem.Allocator,
    processes: []ProcessId,
    name: []const u8,
) !ArrayList(ProcessId) {
    var found_processes = ArrayList(ProcessId).init(allocator);
    var process_name: [psapi.MAX_PATH]psapi.TCHAR = undefined;
    var process_handle: psapi.HANDLE = undefined;

    for (processes) |process_id| {
        process_handle = openProcess(
            psapi.PROCESS_QUERY_INFORMATION | psapi.PROCESS_VM_READ,
            false,
            process_id,
        ) catch |e| {
            switch (e) {
                error.UnableToOpenProcess => continue,
            }
        };

        var module: psapi.HMODULE = undefined;
        var bytes_needed: psapi.DWORD = undefined;
        if (psapi.EnumProcessModulesEx(
            process_handle,
            &module,
            @sizeOf(@TypeOf(module)),
            &bytes_needed,
            psapi.LIST_MODULES_ALL,
        ) != 0) {
            const length_copied = psapi.GetModuleBaseNameA(
                process_handle,
                module,
                &process_name[0],
                @sizeOf(@TypeOf(process_name)) / @sizeOf(psapi.TCHAR),
            );
            const name_slice = process_name[0..length_copied];

            if (mem.eql(u8, name_slice, name)) try found_processes.append(process_id);
        } else {
            return error.UnableToEnumerateModules;
        }
    }

    return found_processes;
}

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
    var spotify_process_buffer: [max_processes]ProcessId = undefined;
    const spotify_processes = try getProcessesByName(
        processes,
        "Spotify.exe",
        spotify_process_buffer[0..],
    );
    for (spotify_processes) |pid| {
        debug.warn("spotify pid: {}\n", .{pid});
    }
}

test "can enumerate processes with dynamic allocation" {
    const processes = try enumerateProcessesAlloc(heap.page_allocator);
    testing.expect(processes.len != 0);
}
