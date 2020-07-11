# Ideas

## Loading of memory in remote process

The idea of loading arbitrary memory inside a remote process is interesting
because it sidesteps the DLL path expansion and could possibly be more flexible.

### Issues?

#### Possible technical issues

I'm not aware of which functions we could use to execute the copied over memory.
Currently we're copying over the path to the DLL and it's mostly by coincidence
`LoadLibraryA` has the correct type signature to be used with
`createRemoteThread`. If we were to load the DLL into memory we'd have to figure
out what inside of it matches the `createRemoteThread` contract and execute that.

Beyond that, what mappings in the DLL data are actually set up with
`LoadLibraryA`?

### Possibly opportunity cost issues

It's entirely possible that an entirely different type of injection or process
manipulation technique is better to spend time and energy on.
