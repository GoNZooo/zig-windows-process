const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const process = std.process;

const ArrayList = std.ArrayList;

const win32package = @import("win32");
const win32 = win32package.c;
const psapi = win32package.psapi;

pub const ProcessId = win32.DWORD;

const max_processes = 2048;

const inject_access = win32.PROCESS_CREATE_THREAD | win32.PROCESS_QUERY_INFORMATION |
    win32.PROCESS_VM_READ | win32.PROCESS_VM_WRITE | win32.PROCESS_VM_OPERATION;

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

    pub fn toDWORD(self: AllocationType) win32.DWORD {
        const bytes = mem.toBytes(self);

        return mem.bytesToValue(win32.DWORD, &bytes);
    }
};

// @TODO: take in DLL byte data instead of path here?
/// Injects the DLL located at the path `dll_name` into the process with ID `pid`.
/// The path will be expanded as needed into an absolute path.
pub fn injectDll(pid: ProcessId, dll_name: []const u8) !win32.DWORD {
    var zeroed_dll_name: [win32.MAX_PATH:0]u8 = undefined;
    mem.copy(u8, zeroed_dll_name[0..dll_name.len], dll_name);
    zeroed_dll_name[dll_name.len] = 0;
    var full_dll_path: [win32.MAX_PATH:0]u8 = undefined;
    const full_length = win32.GetFullPathNameA(
        &zeroed_dll_name[0],
        win32.MAX_PATH,
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
        win32.PAGE_READWRITE,
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
        @ptrCast(win32.LPTHREAD_START_ROUTINE, load_library_ptr),
        memory,
        0,
        null,
    );

    const wait_result = win32.WaitForSingleObject(thread_handle, win32.INFINITE);

    const exit_code = try getExitCodeThread(thread_handle);

    try closeHandle(thread_handle);
    try virtualFreeEx(process_handle, memory, 0, win32.MEM_RELEASE);
    try closeHandle(process_handle);

    return exit_code;
}

/// Opens a process and returns a handle to it.
/// The caller is responsible for calling `closeHandle` on the returned handle.
pub fn openProcess(access_rights: c_ulong, inherit_handle: bool, pid: ProcessId) !win32.HANDLE {
    const win_bool: win32.BOOL = if (inherit_handle) win32.TRUE else win32.FALSE;
    return if (win32.OpenProcess(access_rights, win_bool, pid)) |handle|
        handle
    else
        error.UnableToOpenProcess;
}

// @TODO: have this return null instead, maybe?
pub fn getModuleHandle(name: []const u8) !win32.HINSTANCE {
    return if (win32.GetModuleHandleA(name.ptr)) |instance|
        instance
    else
        error.UnableToGetModuleHandle;
}

/// Closes a handle, should be used after `openProcess`.
pub fn closeHandle(handle: win32.HANDLE) !void {
    if (win32.CloseHandle(handle) == 0) return error.UnableToCloseHandle;
}

/// Returns a function pointer to the function with `name` in `module`. A module
/// can be loaded via `getModuleHandle`.
pub fn getProcAddress(module: win32.HMODULE, name: []const u8) !fn (...) callconv(.C) c_longlong {
    return if (win32.GetProcAddress(module, name.ptr)) |address|
        address
    else
        error.UnableToGetProcAddress;
}

/// Allocates memory in the process corresponding to `process_handle`, which can
/// be used to allocate memory in other processes.
pub fn virtualAllocEx(
    process_handle: win32.HANDLE,
    starting_address: ?*c_ulong,
    size: usize,
    allocation_type: AllocationType,
    // @TODO: add same thing as `AllocationType` but for protection flags
    protection: win32.DWORD,
) !*c_ulong {
    return if (win32.VirtualAllocEx(
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
    process_handle: win32.HANDLE,
    starting_address: ?*c_ulong,
    size: usize,
    free_type: win32.DWORD,
) !void {
    if (win32.VirtualFreeEx(process_handle, starting_address, size, free_type) == 0) {
        return error.UnableToVirtualFreeEx;
    }
}

pub fn writeProcessMemory(
    process_handle: win32.HANDLE,
    starting_address: ?*c_ulong,
    buffer: []const u8,
) !usize {
    var bytes_written: usize = undefined;
    return if (win32.WriteProcessMemory(
        process_handle,
        starting_address,
        buffer.ptr,
        buffer.len,
        &bytes_written,
    ) != 0) bytes_written else error.UnableToWriteProcessMemory;
}

pub fn createRemoteThread(
    process_handle: win32.HANDLE,
    thread_attributes: win32.LPSECURITY_ATTRIBUTES,
    stack_size: usize,
    start_address: win32.LPTHREAD_START_ROUTINE,
    parameter: win32.LPVOID,
    flags: win32.DWORD,
    thread_id: win32.LPDWORD,
) !win32.HANDLE {
    return if (win32.CreateRemoteThreadEx(
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

pub fn getExitCodeThread(handle: win32.HANDLE) !win32.DWORD {
    var exit_code: win32.DWORD = undefined;
    if (win32.GetExitCodeThread(handle, &exit_code) == 0) {
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
    var process_name: [win32.MAX_PATH]win32.TCHAR = undefined;
    var process_handle: win32.HANDLE = undefined;

    for (processes) |process_id| {
        process_handle = openProcess(
            win32.PROCESS_QUERY_INFORMATION | win32.PROCESS_VM_READ,
            false,
            process_id,
        ) catch |e| {
            switch (e) {
                error.UnableToOpenProcess => continue,
            }
        };

        if (process_handle) |handle| {
            var module: win32.HMODULE = undefined;
            var bytes_needed: win32.DWORD = undefined;
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
                    @sizeOf(@TypeOf(process_name)) / @sizeOf(win32.TCHAR),
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
    var process_name: [win32.MAX_PATH]win32.TCHAR = undefined;
    var process_handle: win32.HANDLE = undefined;

    var hits: usize = 0;
    for (processes) |process_id| {
        process_handle = openProcess(
            win32.PROCESS_QUERY_INFORMATION | win32.PROCESS_VM_READ,
            false,
            process_id,
        ) catch |e| {
            switch (e) {
                error.UnableToOpenProcess => continue,
            }
        };

        var module: win32.HMODULE = undefined;
        var bytes_needed: win32.DWORD = undefined;
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
                @sizeOf(@TypeOf(process_name)) / @sizeOf(win32.TCHAR),
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
    var process_name: [win32.MAX_PATH]win32.TCHAR = undefined;
    var process_handle: win32.HANDLE = undefined;

    for (processes) |process_id| {
        process_handle = openProcess(
            win32.PROCESS_QUERY_INFORMATION | win32.PROCESS_VM_READ,
            false,
            process_id,
        ) catch |e| {
            switch (e) {
                error.UnableToOpenProcess => continue,
            }
        };

        var module: win32.HMODULE = undefined;
        var bytes_needed: win32.DWORD = undefined;
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
                @sizeOf(@TypeOf(process_name)) / @sizeOf(win32.TCHAR),
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
    var testing_allocator = testing.LeakCountAllocator.init(heap.page_allocator);
    var processes_buffer: [max_processes]ProcessId = undefined;
    const processes = try enumerateProcesses(processes_buffer[0..]);
    const zig_processes = try getProcessesByNameAlloc(
        &testing_allocator.allocator,
        processes,
        "zig.exe",
    );
    testing.expect(zig_processes.items.len != 0);
    zig_processes.deinit();
    try testing_allocator.validate();
}

test "can enumerate processes with dynamic allocation" {
    var testing_allocator = testing.LeakCountAllocator.init(heap.page_allocator);
    const processes = try enumerateProcessesAlloc(&testing_allocator.allocator);
    testing.expect(processes.len != 0);
    testing_allocator.allocator.free(processes);
    try testing_allocator.validate();
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
    testing.expectEqual((AllocationType{ .reserve = true }).toDWORD(), win32.MEM_RESERVE);
    testing.expectEqual((AllocationType{ .commit = true }).toDWORD(), win32.MEM_COMMIT);
    testing.expectEqual((AllocationType{ .reset = true }).toDWORD(), win32.MEM_RESET);
    // testing.expectEqual((AllocationType{ .reset_undo = true }).toDWORD(), win32.MEM_RESET_UNDO);
    testing.expectEqual((AllocationType{ .top_down = true }).toDWORD(), win32.MEM_TOP_DOWN);
    testing.expectEqual((AllocationType{ .physical = true }).toDWORD(), win32.MEM_PHYSICAL);
    testing.expectEqual((AllocationType{ .large_pages = true }).toDWORD(), win32.MEM_LARGE_PAGES);
    testing.expectEqual(
        (AllocationType{ .commit = true, .reserve = true }).toDWORD(),
        win32.MEM_COMMIT | win32.MEM_RESERVE,
    );
}
