# zig-gnu-starter

By default Zig defaults to looking for vcruntime, which makes it so that one
cannot compile Zig code that relies on libc without installing MSVC.

Setting the target to `native-native-gnu` fixes this, as Zig falls back to the
MinGW code that it itself ships. This template repository sets that default
target automatically.
