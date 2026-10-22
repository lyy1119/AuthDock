//go:build unix

package main

import "syscall"

// setSecureUmask makes every file AuthDock creates (including the SQLite WAL and
// shared-memory sidecars, which hold database pages) readable only by the
// service user.
func setSecureUmask() {
	syscall.Umask(0o077)
}
