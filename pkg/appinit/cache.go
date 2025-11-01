package appinit

// Use a .cache dir to keep a copy of remote objects for disconnected operation.
// The cache will be used at startup and synchronized with the remote objects,
// not necessarily using a watcher (periodic or 'on demand' sync are possible
// and can be more reliable on large systems, avoid breaking all at once)

// For sync, 'last modified' is the minimum, object revision - the cache is
// read only, any chances should be tracked as diffs or on master.
