const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const process = std.process;

const ArrayList = std.ArrayList;

const psapi = @import("./psapi.zig");

pub const ProcessId = psapi.DWORD;

const max_processes = 2048;

const inject_access = psapi.PROCESS_CREATE_THREAD | psapi.PROCESS_QUERY_INFORMATION |
    psapi.PROCESS_VM_READ | psapi.PROCESS_VM_WRITE | psapi.PROCESS_VM_OPERATION;

pub const AllocationType = packed struct {
    __padding1__: u12 = 0,
    commit: bool = false,
    reserve: bool = false,
    __padding2__: u5 = 0,
    reset: bool = false,
    // This should actually be there according to MSDN:
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    // but doesn't seem to exist in my headers
    // reset_undo: bool = false,
    top_down: bool = false,
    __padding3__: u1 = 0,
    physical: bool = false,
    __padding5__: u6 = 0,
    large_pages: bool = false,
    __padding6__: u2 = 0,

    pub fn toDWORD(self: AllocationType) psapi.DWORD {
        const bytes = mem.toBytes(self);

        return mem.bytesToValue(psapi.DWORD, &bytes);
    }
};

// @TODO: take in DLL byte data instead of path here?
/// Injects the DLL located at the path `dll_name` into the process with ID `pid`.
/// The path will be expanded as needed into an absolute path.
pub fn injectDll(pid: ProcessId, dll_name: []const u8) !psapi.DWORD {
    var zeroed_dll_name: [psapi.MAX_PATH:0]u8 = undefined;
    mem.copy(u8, zeroed_dll_name[0..dll_name.len], dll_name);
    zeroed_dll_name[dll_name.len] = 0;
    var full_dll_path: [psapi.MAX_PATH:0]u8 = undefined;
    const full_length = psapi.GetFullPathNameA(
        &zeroed_dll_name[0],
        psapi.MAX_PATH,
        &full_dll_path,
        null,
    );

    const process_handle = try openProcess(inject_access, false, pid);

    const kernel32_module = try getModuleHandle("kernel32.dll");

    const load_library_ptr = try getProcAddress(kernel32_module, "LoadLibraryA");

    const memory = try virtualAllocEx(
        process_handle,
        null,
        full_length + 1,
        AllocationType{ .reserve = true, .commit = true },
        psapi.PAGE_READWRITE,
    );

    _ = try writeProcessMemory(
        process_handle,
        memory,
        full_dll_path[0..(full_length + 1)],
    );

    const thread_handle = try createRemoteThread(
        process_handle,
        null,
        0,
        @ptrCast(psapi.LPTHREAD_START_ROUTINE, load_library_ptr),
        memory,
        0,
        null,
    );

    const wait_result = psapi.WaitForSingleObject(thread_handle, psapi.INFINITE);

    const exit_code = try getExitCodeThread(thread_handle);

    try closeHandle(thread_handle);
    try virtualFreeEx(process_handle, memory, 0, psapi.MEM_RELEASE);
    try closeHandle(process_handle);

    return exit_code;
}

/// Opens a process and returns a handle to it.
/// The caller is responsible for calling `closeHandle` on the returned handle.
pub fn openProcess(access_rights: c_ulong, inherit_handle: bool, pid: ProcessId) !psapi.HANDLE {
    const win_bool: psapi.BOOL = if (inherit_handle) psapi.TRUE else psapi.FALSE;
    return if (psapi.OpenProcess(access_rights, win_bool, pid)) |handle|
        handle
    else
        error.UnableToOpenProcess;
}

// @TODO: have this return null instead, maybe?
pub fn getModuleHandle(name: []const u8) !psapi.HINSTANCE {
    return if (psapi.GetModuleHandleA(name.ptr)) |instance|
        instance
    else
        error.UnableToGetModuleHandle;
}

/// Closes a handle, should be used after `openProcess`.
pub fn closeHandle(handle: psapi.HANDLE) !void {
    if (psapi.CloseHandle(handle) == 0) return error.UnableToCloseHandle;
}

/// Returns a function pointer to the function with `name` in `module`. A module
/// can be loaded via `getModuleHandle`.
pub fn getProcAddress(module: psapi.HMODULE, name: []const u8) !fn (...) callconv(.C) c_longlong {
    return if (psapi.GetProcAddress(module, name.ptr)) |address|
        address
    else
        error.UnableToGetProcAddress;
}

/// Allocates memory in the process corresponding to `process_handle`, which can
/// be used to allocate memory in other processes.
pub fn virtualAllocEx(
    process_handle: psapi.HANDLE,
    starting_address: ?*c_ulong,
    size: usize,
    allocation_type: AllocationType,
    // @TODO: add same thing as `AllocationType` but for protection flags
    protection: psapi.DWORD,
) !*c_ulong {
    return if (psapi.VirtualAllocEx(
        process_handle,
        starting_address,
        size,
        allocation_type.toDWORD(),
        protection,
    )) |memory|
        @ptrCast(*c_ulong, @alignCast(@alignOf(*c_ulong), memory))
    else
        error.UnableToVirtualAllocEx;
}

pub fn virtualFreeEx(
    process_handle: psapi.HANDLE,
    starting_address: ?*c_ulong,
    size: usize,
    free_type: psapi.DWORD,
) !void {
    if (psapi.VirtualFreeEx(process_handle, starting_address, size, free_type) == 0) {
        return error.UnableToVirtualFreeEx;
    }
}

pub fn writeProcessMemory(
    process_handle: psapi.HANDLE,
    starting_address: ?*c_ulong,
    buffer: []const u8,
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
    stack_size: usize,
    start_address: psapi.LPTHREAD_START_ROUTINE,
    parameter: psapi.LPVOID,
    flags: psapi.DWORD,
    thread_id: psapi.LPDWORD,
) !psapi.HANDLE {
    return if (psapi.CreateRemoteThreadEx(
        process_handle,
        thread_attributes,
        stack_size,
        start_address,
        parameter,
        flags,
        null,
        thread_id,
    )) |thread_handle|
        thread_handle
    else
        error.UnableToCreateRemoteThread;
}

pub fn getExitCodeThread(handle: psapi.HANDLE) !psapi.DWORD {
    var exit_code: psapi.DWORD = undefined;
    if (psapi.GetExitCodeThread(handle, &exit_code) == 0) {
        return error.UnableToGetExitCodeFromThread;
    }

    return exit_code;
}

pub fn enumerateProcessesAlloc(allocator: *mem.Allocator) ![]ProcessId {
    var process_id_buffer: [max_processes]ProcessId = undefined;
    const size_of_buffer = @sizeOf(@TypeOf(process_id_buffer));
    var needed_bytes: c_uint = undefined;
    const enum_result = psapi.EnumProcesses(&process_id_buffer, size_of_buffer, &needed_bytes);
    if (enum_result == 0)
        return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(ProcessId);

    var processes = try allocator.alloc(ProcessId, number_of_processes);
    mem.copy(ProcessId, processes, process_id_buffer[0..number_of_processes]);

    return processes;
}

/// Returns the IDs of all running processes. The passed in slice is filled in
/// with the result.
pub fn enumerateProcesses(processes: []ProcessId) ![]ProcessId {
    var needed_bytes: c_uint = undefined;
    const processes_size = @sizeOf(ProcessId) * @intCast(c_ulong, processes.len);
    const enum_result = psapi.EnumProcesses(processes.ptr, processes_size, &needed_bytes);
    if (enum_result == 0) return error.UnableToEnumerateProcesses;

    const number_of_processes = needed_bytes / @sizeOf(ProcessId);

    return processes[0..number_of_processes];
}

/// Returns one or no process IDs for a process matching a given name, biased
/// towards the first match in the process ID slice.
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

        if (process_handle) |handle| {
            var module: psapi.HMODULE = undefined;
            var bytes_needed: psapi.DWORD = undefined;
            const enum_result = psapi.EnumProcessModulesEx(
                handle,
                &module,
                @sizeOf(@TypeOf(module)),
                &bytes_needed,
                psapi.LIST_MODULES_ALL,
            );
            if (enum_result != 0) {
                const length_copied = psapi.GetModuleBaseNameA(
                    handle,
                    module,
                    &process_name[0],
                    @sizeOf(@TypeOf(process_name)) / @sizeOf(psapi.TCHAR),
                );
                const name_slice = process_name[0..length_copied];

                if (mem.eql(u8, name_slice, name)) return process_id;

                try closeHandle(handle);
            } else {
                return error.UnableToEnumerateModules;
            }
        }
    }

    return null;
}

/// Returns all (or no) process IDs matching a given name. The result slice to
/// fill is taken as a parameter, allowing one to slice into a stack allocated
/// array easily. This may or may not be removed in favor of only having the
/// allocator version and having the caller pass a stack allocator instead.
pub fn getProcessesByName(
    processes: []ProcessId,
    name: []const u8,
    result_buffer: []ProcessId,
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
        const enum_result = psapi.EnumProcessModulesEx(
            process_handle,
            &module,
            @sizeOf(@TypeOf(module)),
            &bytes_needed,
            psapi.LIST_MODULES_ALL,
        );
        if (enum_result != 0) {
            const length_copied = psapi.GetModuleBaseNameA(
                process_handle,
                module,
                &process_name[0],
                @sizeOf(@TypeOf(process_name)) / @sizeOf(psapi.TCHAR),
            );
            const name_slice = process_name[0..length_copied];

            if (mem.eql(u8, name_slice, name)) {
                result_buffer[hits] = process_id;
                hits += 1;
            }

            try closeHandle(process_handle);
        } else {
            return error.UnableToEnumerateModules;
        }
    }

    return result_buffer[0..hits];
}

/// Returns all (or no) process IDs matching a given name.
/// The caller is responsible for freeing the returned `ArrayList`.
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
        const enum_result = psapi.EnumProcessModulesEx(
            process_handle,
            &module,
            @sizeOf(@TypeOf(module)),
            &bytes_needed,
            psapi.LIST_MODULES_ALL,
        );
        if (enum_result != 0) {
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

test "`getProcessesByNameAlloc` finds zig processes" {
    var processes_buffer: [max_processes]ProcessId = undefined;
    const processes = try enumerateProcesses(processes_buffer[0..]);
    const zig_processes = try getProcessesByNameAlloc(heap.page_allocator, processes, "zig.exe");
    testing.expect(zig_processes.items.len != 0);
}

test "can enumerate processes with dynamic allocation" {
    const processes = try enumerateProcessesAlloc(heap.page_allocator);
    testing.expect(processes.len != 0);
}

test "`getProcessName` finds 'zig.exe'" {
    var process_buffer: [max_processes]ProcessId = undefined;
    const processes = try enumerateProcesses(process_buffer[0..]);
    const zig_process = try getProcessByName(processes, "zig.exe");
    testing.expect(zig_process != null);
}

test "`getProcessesByName` finds zig processes" {
    var process_buffer: [max_processes]ProcessId = undefined;
    const processes = try enumerateProcesses(process_buffer[0..]);
    var results_buffer: [max_processes]ProcessId = undefined;
    const zig_processes = try getProcessesByName(processes, "zig.exe", results_buffer[0..]);
    testing.expect(zig_processes.len > 0);
}

test "`AllocationType` works the same as C enum does" {
    testing.expectEqual((AllocationType{}).toDWORD(), 0);
    testing.expectEqual((AllocationType{ .reserve = true }).toDWORD(), psapi.MEM_RESERVE);
    testing.expectEqual((AllocationType{ .commit = true }).toDWORD(), psapi.MEM_COMMIT);
    testing.expectEqual((AllocationType{ .reset = true }).toDWORD(), psapi.MEM_RESET);
    // testing.expectEqual((AllocationType{ .reset_undo = true }).toDWORD(), psapi.MEM_RESET_UNDO);
    testing.expectEqual((AllocationType{ .top_down = true }).toDWORD(), psapi.MEM_TOP_DOWN);
    testing.expectEqual((AllocationType{ .physical = true }).toDWORD(), psapi.MEM_PHYSICAL);
    testing.expectEqual((AllocationType{ .large_pages = true }).toDWORD(), psapi.MEM_LARGE_PAGES);
    testing.expectEqual(
        (AllocationType{ .commit = true, .reserve = true }).toDWORD(),
        psapi.MEM_COMMIT | psapi.MEM_RESERVE,
    );
}
