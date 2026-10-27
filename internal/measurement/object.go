package measurement

import _ "embed"

// Object is bpf/measure.c compiled by scripts/measurement/build-bpf.sh. The loader loads only this object, so the
// object that the unit tests check (CheckSpec, CheckObserveOnly) is the object that runs.
//
//go:embed bpf/measure_bpfel.o
var Object []byte
