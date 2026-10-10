//go:build linux || darwin

package main

import (
	"math"
	"runtime"
	"syscall"
)

// peakRSS returns the peak resident set size of this process in bytes.
func peakRSS() (uint64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return rssBytes(ru.Maxrss, runtime.GOOS == "darwin")
}

// rssBytes converts Darwin's bytes or Linux's KiB to bytes without overflow.
func rssBytes(maxRSS int64, darwin bool) (uint64, bool) {
	if maxRSS < 0 {
		return 0, false
	}
	rss := uint64(maxRSS)
	if darwin {
		return rss, true
	}
	if rss > math.MaxUint64/1024 {
		return 0, false
	}
	return rss * 1024, true
}
