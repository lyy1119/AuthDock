//go:build !unix

package main

// setSecureUmask is a no-op on platforms without POSIX file modes.
func setSecureUmask() {}
