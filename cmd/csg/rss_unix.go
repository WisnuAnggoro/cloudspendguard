//go:build linux || darwin

package main

import (
	"runtime"
	"syscall"
)

// peakRSS returns the peak resident set size of this process in bytes.
func peakRSS() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	if runtime.GOOS == "darwin" {
		return uint64(ru.Maxrss), true // bytes
	}
	return uint64(ru.Maxrss) * 1024, true // kilobytes on Linux
}
