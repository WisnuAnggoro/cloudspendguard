//go:build !linux && !darwin

package main

// peakRSS is not available on this platform.
func peakRSS() (uint64, bool) { return 0, false }
