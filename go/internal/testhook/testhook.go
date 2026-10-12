// Package testhook lets this module's tests outside a package reach client
// internals that are not public API. The owning package installs each hook
// when it is initialised; nothing outside this module can import it.
package testhook

import "time"

// SetDiscoveryClock replaces the cache clock of a *discovery.Client, so a
// conformance runner can drive TTL expiry without waiting in real time. It is
// installed by package discovery and must be called before the client's first
// fetch.
var SetDiscoveryClock func(client any, now func() time.Time)
