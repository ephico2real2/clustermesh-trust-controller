package measurement

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Linux capability numbers (include/uapi/linux/capability.h).
const (
	CapNetAdmin = 12
	CapSysAdmin = 21
	CapPerfmon  = 38
	CapBPF      = 39
)

// LoaderCapabilities is the whole capability set of the cgroup_skb loader; it refuses to start with any other
// (CheckCapabilitySets). ADR-005 names these two; the hooks need both and nothing else (Linux v6.8):
//   - CAP_BPF: map creation and program loading while unprivileged BPF is disabled (kernel/bpf/syscall.c:1187,
//     2628), and the LRU hash map (:1217-1221).
//   - CAP_NET_ADMIN: attaching a cgroup_skb program, also through a bpf_link: link_create calls
//     bpf_prog_attach_check_attach_type, which returns -EPERM without capable(CAP_NET_ADMIN) (syscall.c:3820-3824,
//     5013). Loading needs no CAP_NET_ADMIN (CGROUP_SKB is "always unpriv", syscall.c:2565-2566).
//   - not CAP_PERFMON: the programs call no tracing helper. CAP_PERFMON would let the verifier accept pointer leaks
//     and uninitialized stack reads and skip its Spectre v1 and v4 hardening (verifier.c:20804-20807,
//     include/linux/bpf.h:2205-2223). Without it the verifier keeps that hardening: bpf/measure.c is written for
//     it, and the kernel tests load the programs with this set only (asLoader in program_privileged_test.go).
const LoaderCapabilities uint64 = 1<<CapBPF | 1<<CapNetAdmin

var capabilityNames = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
	"CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT",
	"CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL",
	"CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
}

// CapabilityNames names the capabilities in mask, lowest number first.
func CapabilityNames(mask uint64) []string {
	var names []string
	for i := 0; i < 64; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		if i < len(capabilityNames) {
			names = append(names, capabilityNames[i])
		} else {
			names = append(names, "cap_"+strconv.Itoa(i))
		}
	}
	return names
}

// CapabilitySets are the five capability sets of /proc/self/status.
type CapabilitySets struct {
	Inheritable, Permitted, Effective, Bounding, Ambient uint64
}

// ParseCapabilitySets reads the CapInh, CapPrm, CapEff, CapBnd and CapAmb
// lines of a /proc/<pid>/status file. All five must be present.
func ParseCapabilitySets(status []byte) (CapabilitySets, error) {
	var c CapabilitySets
	fields := map[string]*uint64{"CapInh": &c.Inheritable, "CapPrm": &c.Permitted, "CapEff": &c.Effective,
		"CapBnd": &c.Bounding, "CapAmb": &c.Ambient}
	found := map[string]bool{}
	s := bufio.NewScanner(bytes.NewReader(status))
	for s.Scan() {
		key, value, ok := strings.Cut(s.Text(), ":")
		target, known := fields[key]
		if !ok || !known {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return CapabilitySets{}, fmt.Errorf("parse %s: %w", key, err)
		}
		*target = v
		found[key] = true
	}
	if err := s.Err(); err != nil {
		return CapabilitySets{}, err
	}
	for key := range fields {
		if !found[key] {
			return CapabilitySets{}, fmt.Errorf("status has no %s line", key)
		}
	}
	return c, nil
}

// CheckCapabilitySets refuses any capability outside allowed in any of the
// five sets, and requires every allowed capability in the effective set.
func CheckCapabilitySets(c CapabilitySets, allowed uint64) error {
	for _, set := range []struct {
		name string
		mask uint64
	}{{"effective", c.Effective}, {"permitted", c.Permitted}, {"inheritable", c.Inheritable},
		{"bounding", c.Bounding}, {"ambient", c.Ambient}} {
		if extra := set.mask &^ allowed; extra != 0 {
			return fmt.Errorf("refusing to start: the %s capability set holds %s beyond %s",
				set.name, strings.Join(CapabilityNames(extra), ","), strings.Join(CapabilityNames(allowed), ","))
		}
	}
	if missing := allowed &^ c.Effective; missing != 0 {
		return fmt.Errorf("refusing to start: the effective capability set lacks %s", strings.Join(CapabilityNames(missing), ","))
	}
	return nil
}
