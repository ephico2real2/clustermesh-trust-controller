//go:build !linux

package measurement

import "errors"

var errNotLinux = errors.New("the measurement plane runs on Linux only")

// SystemClock fails on every read outside Linux, so the plane reports not ready.
func SystemClock() Clock {
	return Clock{
		BootID:    func() (string, error) { return "", errNotLinux },
		Monotonic: func() (int64, error) { return 0, errNotLinux },
	}
}
