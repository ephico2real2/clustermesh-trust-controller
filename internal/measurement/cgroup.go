package measurement

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxCgroupDepth bounds the walk: kubelet puts a Pod cgroup at most four
// levels below the root (kubelet.slice/kubelet-kubepods.slice/
// kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<UID>.slice).
const maxCgroupDepth = 5

var (
	// systemd driver: dashes of the Pod UID become underscores.
	systemdPodCgroup = regexp.MustCompile(`-pod([0-9a-f_]{32,36})\.slice$`)
	// cgroupfs driver.
	cgroupfsPodCgroup = regexp.MustCompile(`^pod([0-9a-f-]{32,36})$`)
)

// FindPodCgroups maps Pod UIDs to the kubelet Pod-level cgroup directories
// under root, the host cgroup v2 mount. It descends only into kubelet and
// kubepods directories. A UID with several candidates keeps all of them, so
// the caller can refuse the ambiguity.
func FindPodCgroups(root string) (map[string][]string, error) {
	found := map[string][]string{}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name, path := e.Name(), filepath.Join(dir, e.Name())
			if uid, ok := podCgroupUID(name); ok {
				found[uid] = append(found[uid], path)
				continue
			}
			if depth < maxCgroupDepth && descendInto(name) {
				// A cgroup removed during the walk is not an error.
				if err := walk(path, depth+1); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(root, 1); err != nil {
		return nil, err
	}
	return found, nil
}

func podCgroupUID(name string) (string, bool) {
	if m := systemdPodCgroup.FindStringSubmatch(name); m != nil {
		uid := strings.ReplaceAll(m[1], "_", "-")
		return uid, podUIDPattern.MatchString(uid)
	}
	if m := cgroupfsPodCgroup.FindStringSubmatch(name); m != nil {
		return m[1], podUIDPattern.MatchString(m[1])
	}
	return "", false
}

func descendInto(name string) bool {
	return strings.Contains(name, "kubepods") || strings.Contains(name, "kubelet") ||
		name == "besteffort" || name == "burstable"
}
