const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const os = std.os;

const win32 = @import("win32").c;

pub export fn DllMain(
    instance: win32.HANDLE,
    reason: win32.DWORD,
    reserved: win32.LPVOID,
) callconv(.Stdcall) win32.BOOL {
    _ = win32.AttachConsole(@intCast(c_ulong, 0) -% 1);
    switch (reason) {
        win32.DLL_PROCESS_ATTACH => debug.warn("process attach\n", .{}),
        win32.DLL_PROCESS_DETACH => debug.warn("process detach\n", .{}),
        win32.DLL_THREAD_ATTACH => debug.warn("thread attach\n", .{}),
        win32.DLL_THREAD_DETACH => debug.warn("thread detach\n", .{}),
        else => {},
    }

    return 0;
}
