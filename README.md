# zig-windows-process

This repo is meant to hold tools for tinkering with Windows processes
(though I might extend it in the future) to allow for a higher-level interface
for injecting DLLs and such.

The primary motivation is that I'd like to have a basic toolkit for dealing with
things that usually come up in game hacking and exploration.

## Example usage

### DLL injection

`inject_dll.zig` contains a main file for a program that will take a DLL path
and inject it into a given process. One needs to make sure that the process has
the same bitness as the DLL.

### Finding/enumerating processes

`find_process.zig` uses the process enumeration API to find processes matching
a given executable name.

## More stuff and more ways to do these things

I'm not an expert on any of these things and there are way more things to add
here. I'd love suggestions for tools to add, techniques to facilitate through
this package. Having a general module that allows interaction with Windows
processes in general is the point, after all.
