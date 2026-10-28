package measurement

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mkdirs(t *testing.T, root string, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func systemdPod(uid string) string {
	return "kubepods-besteffort-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice"
}

func TestFindPodCgroups(t *testing.T) {
	root := t.TempDir()
	guaranteed := "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + strings.ReplaceAll(uidA, "-", "_") + ".slice"
	besteffort := "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/" + systemdPod(uidB)
	mkdirs(t, root,
		// The lab's kubelet: systemd driver, cgroupRoot /kubelet. A container cgroup below a Pod is not a Pod.
		guaranteed+"/cri-containerd-0123.scope",
		besteffort,
		// Not kubelet's: never walked.
		"system.slice/kubepods-besteffort-pod"+strings.ReplaceAll(uidA, "-", "_")+".slice/x",
		"user.slice",
	)
	got, err := FindPodCgroups(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		uidA: {filepath.Join(root, guaranteed)},
		uidB: {filepath.Join(root, besteffort)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("found %v, want %v", got, want)
	}
}

func TestFindPodCgroupsWithTheCgroupfsDriver(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "kubepods/burstable/pod"+uidA, "kubepods/pod"+uidB)
	got, err := FindPodCgroups(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		uidA: {filepath.Join(root, "kubepods/burstable/pod"+uidA)},
		uidB: {filepath.Join(root, "kubepods/pod"+uidB)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("found %v, want %v", got, want)
	}
}

// A UID found twice keeps both paths, so the plane refuses the ambiguity instead of choosing one.
func TestFindPodCgroupsKeepsEveryCandidate(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, "kubepods.slice/kubepods-besteffort.slice/"+systemdPod(uidA),
		"kubepods.slice/kubepods-burstable.slice/"+strings.Replace(systemdPod(uidA), "besteffort", "burstable", 1))
	got, err := FindPodCgroups(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[uidA]) != 2 {
		t.Fatalf("found %v, want both cgroups of %s", got, uidA)
	}
}

func TestFindPodCgroupsStopsAtTheDepthBound(t *testing.T) {
	root := t.TempDir()
	deep := "kubepods/kubepods/kubepods/kubepods/kubepods/" + systemdPod(uidA)
	mkdirs(t, root, deep)
	got, err := FindPodCgroups(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("found %v %d levels down, beyond maxCgroupDepth %d", got, strings.Count(deep, "/")+1, maxCgroupDepth)
	}
}

func TestPodCgroupUIDRefusesWhatIsNoUID(t *testing.T) {
	for _, name := range []string{"kubepods-besteffort-podXYZ.slice", "pod" + strings.ToUpper(uidA), "kubepods.slice",
		"kubepods-besteffort-pod" + strings.ReplaceAll(uidA, "-", "_") + ".scope"} {
		if uid, ok := podCgroupUID(name); ok {
			t.Errorf("%s gave Pod UID %q", name, uid)
		}
	}
	if uid, ok := podCgroupUID(systemdPod(uidA)); !ok || uid != uidA {
		t.Errorf("systemd name gave %q, %v", uid, ok)
	}
}
