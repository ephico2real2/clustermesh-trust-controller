package charts

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// containers returns the node agent's containers by name.
func containers(t *testing.T, objects map[string]object) map[string]object {
	t.Helper()
	out := map[string]object{}
	for _, c := range dig(objects["DaemonSet/cmtc-node-agent"], "spec", "template", "spec", "containers").([]any) {
		out[c.(object)["name"].(string)] = c.(object)
	}
	return out
}

// names returns the container names, sorted.
func names(c map[string]object) []string {
	out := make([]string, 0, len(c))
	for name := range c {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// mounts returns a container's volume mounts as name -> "path ro|rw".
func mounts(c object) map[string]string {
	out := map[string]string{}
	list, _ := c["volumeMounts"].([]any)
	for _, m := range list {
		mode := "rw"
		if m.(object)["readOnly"] == true {
			mode = "ro"
		}
		out[m.(object)["name"].(string)] = m.(object)["mountPath"].(string) + " " + mode
	}
	return out
}

// The measurement loader holds exactly CAP_BPF and CAP_NET_ADMIN, no API token and a read-only view of the host's
// cgroups; the agent holds the token and no capability (ADR-005).
func TestMeasurementLoaderPrivileges(t *testing.T) {
	got := render(t, "clusterName=cmtc-a", "image.tag=x")
	pod := dig(got["DaemonSet/cmtc-node-agent"], "spec", "template", "spec").(object)
	if pod["automountServiceAccountToken"] != false {
		t.Fatalf("automountServiceAccountToken = %v, want false: kubelet would mount the token into the loader too",
			pod["automountServiceAccountToken"])
	}
	c := containers(t, got)
	loader, agent := c["measurement-loader"], c["agent"]
	if loader == nil || agent == nil || len(c) != 2 {
		t.Fatalf("containers %v, want agent and measurement-loader", names(c))
	}
	wantSecurity := object{"runAsUser": float64(0), "runAsNonRoot": false, "allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true, "capabilities": object{"drop": []any{"ALL"}, "add": []any{"BPF", "NET_ADMIN"}}}
	if !reflect.DeepEqual(loader["securityContext"], wantSecurity) {
		t.Errorf("loader securityContext %v, want %v", loader["securityContext"], wantSecurity)
	}
	if !reflect.DeepEqual(loader["command"], []any{"/cmtc-measure"}) || loader["ports"] != nil {
		t.Errorf("loader command %v ports %v, want /cmtc-measure and no port", loader["command"], loader["ports"])
	}
	if !reflect.DeepEqual(mounts(loader), map[string]string{"host-cgroup": "/host/cgroup ro",
		"measurement-desired": "/run/cmtc/desired ro", "measurement-snapshot": "/run/cmtc/snapshot rw"}) {
		t.Errorf("loader mounts %v", mounts(loader))
	}
	if !reflect.DeepEqual(mounts(agent), map[string]string{
		"api-token":            "/var/run/secrets/kubernetes.io/serviceaccount ro",
		"measurement-desired":  "/run/cmtc/desired rw",
		"measurement-snapshot": "/run/cmtc/snapshot ro"}) {
		t.Errorf("agent mounts %v", mounts(agent))
	}
	if caps := dig(agent, "securityContext", "capabilities"); !reflect.DeepEqual(caps, object{"drop": []any{"ALL"}}) {
		t.Errorf("agent capabilities %v, want drop ALL only", caps)
	}
	args := strings.Join(toStrings(agent["args"]), " ")
	if !strings.Contains(args, "--measurement-desired-dir=/run/cmtc/desired --measurement-snapshot-dir=/run/cmtc/snapshot") {
		t.Errorf("agent args %q lack the exchange directories", args)
	}
	if path := dig(volume(t, got, "host-cgroup"), "hostPath", "path"); path != "/sys/fs/cgroup" {
		t.Errorf("host-cgroup hostPath %v", path)
	}
	if !hasNamespaceRead(got) {
		t.Error("the node agent's ClusterRole lacks namespaces get/list/watch")
	}
}

// The securityContext value tunes the agent and the controller; it never reaches the loader.
func TestMeasurementLoaderSecurityIsFixed(t *testing.T) {
	got := render(t, "clusterName=cmtc-a", "image.tag=x", "securityContext.capabilities.add[0]=SYS_ADMIN",
		"securityContext.allowPrivilegeEscalation=true")
	loader := containers(t, got)["measurement-loader"]
	if add := dig(loader, "securityContext", "capabilities", "add"); !reflect.DeepEqual(add, []any{"BPF", "NET_ADMIN"}) {
		t.Errorf("loader capabilities add %v", add)
	}
	if dig(loader, "securityContext", "allowPrivilegeEscalation") != false {
		t.Error("the securityContext value changed the loader's allowPrivilegeEscalation")
	}
}

func TestMeasurementDisabled(t *testing.T) {
	got := render(t, "clusterName=cmtc-a", "image.tag=x", "nodeAgent.measurement.enabled=false")
	c := containers(t, got)
	if len(c) != 1 || c["agent"] == nil {
		t.Fatalf("containers %v, want the agent alone", names(c))
	}
	if args := strings.Join(toStrings(c["agent"]["args"]), " "); strings.Contains(args, "measurement") {
		t.Errorf("agent args %q name the measurement plane", args)
	}
	if !reflect.DeepEqual(mounts(c["agent"]), map[string]string{
		"api-token": "/var/run/secrets/kubernetes.io/serviceaccount ro"}) {
		t.Errorf("agent mounts %v, want the API token only", mounts(c["agent"]))
	}
	if volumes := dig(got["DaemonSet/cmtc-node-agent"], "spec", "template", "spec", "volumes").([]any); len(volumes) != 1 {
		t.Errorf("volumes %v, want api-token only", volumes)
	}
	if hasNamespaceRead(got) {
		t.Error("namespaces are readable without the measurement plane")
	}
}

// On OpenShift the plane is off unless enabled: the restricted-v2 SCC refuses the loader, and a refused Pod would stop
// the node agent too. Enabled explicitly, the loader is rendered as on Kubernetes.
func TestMeasurementIsOffByDefaultOnOpenShift(t *testing.T) {
	got := render(t, "clusterName=cmtc-a", "image.tag=x", "global.openshift=true")
	if c := containers(t, got); len(c) != 1 || c["agent"] == nil {
		t.Fatalf("containers %v on OpenShift, want the agent alone", names(c))
	}
	for name, spec := range podSpecs(got) {
		for _, c := range spec["containers"].([]any) {
			sc, _ := dig(c, "securityContext").(object)
			if user, ok := sc["runAsUser"]; ok {
				t.Errorf("%s container %s sets runAsUser %v on OpenShift", name, c.(object)["name"], user)
			}
		}
	}
	if hasNamespaceRead(got) {
		t.Error("namespaces are readable without the measurement plane")
	}
	enabled := render(t, "clusterName=cmtc-a", "image.tag=x", "global.openshift=true", "nodeAgent.measurement.enabled=true")
	if c := containers(t, enabled); c["measurement-loader"] == nil || !hasNamespaceRead(enabled) {
		t.Fatalf("containers %v with the plane enabled on OpenShift, want the loader too", names(c))
	}
}

func toStrings(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func volume(t *testing.T, objects map[string]object, name string) object {
	t.Helper()
	for _, v := range dig(objects["DaemonSet/cmtc-node-agent"], "spec", "template", "spec", "volumes").([]any) {
		if v.(object)["name"] == name {
			return v.(object)
		}
	}
	t.Fatalf("no volume %s", name)
	return nil
}

func hasNamespaceRead(objects map[string]object) bool {
	for _, r := range objects["ClusterRole/cmtc-node-agent"]["rules"].([]any) {
		rule := r.(object)
		if reflect.DeepEqual(rule["resources"], []any{"namespaces"}) &&
			reflect.DeepEqual(rule["verbs"], []any{"get", "list", "watch"}) {
			return true
		}
	}
	return false
}
