//go:build linux

package measurement

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// SystemClock reads the boot ID and CLOCK_MONOTONIC. Neither is namespaced,
// so both containers of the Pod read the same values.
func SystemClock() Clock {
	return Clock{BootID: bootID, Monotonic: monotonicNs}
}

func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("empty boot ID")
	}
	return id, nil
}

func monotonicNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return ts.Nano(), nil
}
