// Package charts tests the CMTC Helm charts by rendering them with the helm CLI: the cmtc chart against config/default
// (rendered by kubectl kustomize) and the manifests it replaces.
package charts

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type object = map[string]any

// trackInputs reads every file helm and kubectl will read. Go's test cache keys only on files this process opens, so
// without this an edited template would reuse a cached pass.
func trackInputs(t *testing.T) {
	t.Helper()
	for _, dir := range []string{"cmtc", "../config/default", "../config/crd"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			_, err = os.ReadFile(path)
			return err
		})
		if err != nil {
			t.Fatalf("read chart inputs: %v", err)
		}
	}
}

func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	trackInputs(t)
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("%s is required for the chart tests: %v", name, err)
	}
	var out, errOut bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if err != nil {
		return errOut.String(), err
	}
	return out.String(), nil
}

func render(t *testing.T, set ...string) map[string]object {
	t.Helper()
	return renderWith(t, nil, set...)
}

// renderWith passes extra helm arguments, such as --api-versions, before the --set values.
func renderWith(t *testing.T, helmArgs []string, set ...string) map[string]object {
	t.Helper()
	return renderChart(t, "cmtc", "cmtc-system", helmArgs, set...)
}

func renderChart(t *testing.T, chart, namespace string, helmArgs []string, set ...string) map[string]object {
	t.Helper()
	args := append([]string{"template", chart, "./" + chart, "--namespace", namespace}, helmArgs...)
	for _, s := range set {
		args = append(args, "--set", s)
	}
	out, err := run(t, "helm", args...)
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", set, err, out)
	}
	return parse(t, out)
}

func renderFails(t *testing.T, want string, set ...string) {
	t.Helper()
	renderFailsWith(t, nil, want, set...)
}

func renderFailsWith(t *testing.T, helmArgs []string, want string, set ...string) {
	t.Helper()
	renderChartFails(t, "cmtc", "cmtc-system", helmArgs, want, set...)
}

func renderChartFails(t *testing.T, chart, namespace string, helmArgs []string, want string, set ...string) {
	t.Helper()
	args := append([]string{"template", chart, "./" + chart, "--namespace", namespace}, helmArgs...)
	for _, s := range set {
		args = append(args, "--set", s)
	}
	out, err := run(t, "helm", args...)
	if err == nil || !strings.Contains(out, want) {
		t.Fatalf("helm template %v: want an error containing %q, got err=%v\n%s", set, want, err, out)
	}
}

func parse(t *testing.T, stream string) map[string]object {
	t.Helper()
	objects := map[string]object{}
	for _, doc := range strings.Split(stream, "\n---") {
		var o object
		if err := yaml.Unmarshal([]byte(doc), &o); err != nil {
			t.Fatalf("parse: %v\n%s", err, doc)
		}
		if o == nil {
			continue
		}
		if _, dup := objects[key(o)]; dup {
			t.Fatalf("%s is rendered twice", key(o))
		}
		objects[key(o)] = o
	}
	return objects
}

func key(o object) string {
	return o["kind"].(string) + "/" + o["metadata"].(object)["name"].(string)
}

func dig(o any, path ...string) any {
	for _, p := range path {
		m, ok := o.(object)
		if !ok {
			return nil
		}
		o = m[p]
	}
	return o
}

// normalize removes what the chart adds on purpose: Helm's labels, the explicit namespace and the CRD keep policy.
func normalize(o object) object {
	c := object{}
	b, _ := yaml.Marshal(o)
	_ = yaml.Unmarshal(b, &c)
	meta := c["metadata"].(object)
	delete(meta, "namespace")
	delete(meta, "annotations")
	if labels, ok := meta["labels"].(object); ok {
		for _, l := range []string{"app.kubernetes.io/part-of", "app.kubernetes.io/managed-by", "app.kubernetes.io/instance", "helm.sh/chart"} {
			delete(labels, l)
		}
		if len(labels) == 0 {
			delete(meta, "labels")
		}
	}
	return c
}

func podSpecs(objects map[string]object) map[string]object {
	return map[string]object{
		"controller": dig(objects["Deployment/cmtc-controller"], "spec", "template", "spec").(object),
		"node-agent": dig(objects["DaemonSet/cmtc-node-agent"], "spec", "template", "spec").(object),
	}
}

func TestKubernetesRenderMatchesConfigDefault(t *testing.T) {
	kustomized, err := run(t, "kubectl", "kustomize", "../config/default")
	if err != nil {
		t.Fatalf("kubectl kustomize: %v\n%s", err, kustomized)
	}
	want := parse(t, strings.NewReplacer("CLUSTER_NAME", "cmtc-a").Replace(kustomized))
	got := render(t, "clusterName=cmtc-a", "image.repository=cmtc", "image.tag=dev")
	if len(got) != len(want) {
		t.Errorf("object count: chart %d, config/default %d", len(got), len(want))
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("%s: missing from the chart", k)
			continue
		}
		if !reflect.DeepEqual(normalize(g), normalize(w)) {
			gb, _ := yaml.Marshal(normalize(g))
			wb, _ := yaml.Marshal(normalize(w))
			t.Errorf("%s differs\nchart:\n%s\nconfig/default:\n%s", k, gb, wb)
		}
	}
	if dig(got["CustomResourceDefinition/namespacemtlspolicies.security.cmtc.io"], "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
		t.Error("the CRD must carry helm.sh/resource-policy: keep")
	}
}

func TestOpenShiftLeavesTheUIDToTheSCC(t *testing.T) {
	got := render(t, "clusterName=cmtc-a", "image.tag=x", "global.openshift=true")
	for name, spec := range podSpecs(got) {
		sc := spec["securityContext"].(object)
		if _, ok := sc["runAsUser"]; ok {
			t.Errorf("%s: runAsUser is set on OpenShift: %v", name, sc)
		}
		if sc["runAsNonRoot"] != true || dig(sc, "seccompProfile", "type") != "RuntimeDefault" {
			t.Errorf("%s: pod security context lost runAsNonRoot or RuntimeDefault: %v", name, sc)
		}
		ctr := spec["containers"].([]any)[0].(object)["securityContext"].(object)
		if ctr["allowPrivilegeEscalation"] != false || ctr["readOnlyRootFilesystem"] != true ||
			!reflect.DeepEqual(dig(ctr, "capabilities", "drop"), []any{"ALL"}) {
			t.Errorf("%s: container security context weakened: %v", name, ctr)
		}
	}
	var namespaces []string
	for _, f := range dig(got["NetworkPolicy/cmtc-metrics"], "spec", "ingress").([]any)[0].(object)["from"].([]any) {
		namespaces = append(namespaces, dig(f, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name").(string))
	}
	if want := []string{"openshift-monitoring", "openshift-user-workload-monitoring", "cmtc-system"}; !reflect.DeepEqual(namespaces, want) {
		t.Errorf("metrics namespaces on OpenShift: got %v, want %v", namespaces, want)
	}
	for name, spec := range podSpecs(render(t, "clusterName=cmtc-a", "image.tag=x")) {
		if dig(spec, "securityContext", "runAsUser") != float64(65532) {
			t.Errorf("%s: Kubernetes render must keep runAsUser 65532", name)
		}
	}
}

// The values that reproduce the live cmtc-a controller (2026-10-26).
func TestIssuerProfileMatchesTheLiveController(t *testing.T) {
	root := "0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c"
	got := render(t, "clusterName=cmtc-a", "image.tag=x",
		"controller.issuerProfile.enabled=true",
		"controller.issuerProfile.source=cmtc-issuer-approval-g5",
		"controller.issuerProfile.sourceUID=cac0eada-02d3-459e-ad60-1058bbdbd5dd",
		"controller.issuerProfile.outputUID=fbc7b3c2-00f1-4787-a149-fca76e274c4e",
		"controller.issuerProfile.rootSHA256[0]="+root,
		"controller.issuerProfile.minimumGeneration=5",
		"controller.issuerProfile.readers[0].namespace=kube-system",
		"controller.issuerProfile.readers[0].name=cilium")
	args := dig(got["Deployment/cmtc-controller"], "spec", "template", "spec").(object)["containers"].([]any)[0].(object)["args"]
	want := []any{"--mode=controller", "--cluster-name=cmtc-a", "--issuer-profile-producer=true",
		"--issuer-profile-namespace=cmtc-system", "--issuer-profile-source=cmtc-issuer-approval-g5",
		"--issuer-profile-output=cmtc-issuer-publication", "--issuer-profile-source-uid=cac0eada-02d3-459e-ad60-1058bbdbd5dd",
		"--issuer-profile-output-uid=fbc7b3c2-00f1-4787-a149-fca76e274c4e", "--issuer-profile-root-sha256=" + root,
		"--issuer-profile-minimum-generation=5"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("controller args:\ngot  %v\nwant %v", args, want)
	}
	access := []any{
		object{"apiGroups": []any{""}, "resources": []any{"configmaps"}, "resourceNames": []any{"cmtc-issuer-approval-g5"}, "verbs": []any{"get"}},
		object{"apiGroups": []any{""}, "resources": []any{"configmaps"}, "resourceNames": []any{"cmtc-issuer-publication"}, "verbs": []any{"get", "update"}},
	}
	if rules := got["Role/cmtc-issuer-profile-access"]["rules"]; !reflect.DeepEqual(rules, access) {
		t.Errorf("controller Role rules: %v", rules)
	}
	readers := []any{object{"apiGroups": []any{""}, "resources": []any{"configmaps"},
		"resourceNames": []any{"cmtc-issuer-approval-g5", "cmtc-issuer-publication"}, "verbs": []any{"get"}}}
	if rules := got["Role/cmtc-issuer-profile-readers"]["rules"]; !reflect.DeepEqual(rules, readers) {
		t.Errorf("reader Role rules: %v", rules)
	}
	subjects := []any{object{"kind": "ServiceAccount", "name": "cilium", "namespace": "kube-system"}}
	if s := got["RoleBinding/cmtc-issuer-profile-readers"]["subjects"]; !reflect.DeepEqual(s, subjects) {
		t.Errorf("reader RoleBinding subjects: %v", s)
	}
}

func TestImageDigestIsPreferred(t *testing.T) {
	digest := "sha256:e2f036654104acf5f78fd4af38871d3af6f853f685e7a872fabfe8565f75b7d8"
	got := render(t, "clusterName=cmtc-a", "image.tag=ignored", "image.digest="+digest)
	for name, spec := range podSpecs(got) {
		if image := spec["containers"].([]any)[0].(object)["image"]; image != "ghcr.io/ephico2real2/cmtc@"+digest {
			t.Errorf("%s: image %v", name, image)
		}
	}
}

func TestInvalidValuesFail(t *testing.T) {
	renderFails(t, "clusterName is required", "image.tag=x")
	renderFails(t, "is not a DNS label", "clusterName=Bad_Name", "image.tag=x")
	renderFails(t, "set image.digest (preferred) or image.tag", "clusterName=cmtc-a")
	renderFails(t, "is not sha256:<64 hex>", "clusterName=cmtc-a", "image.digest=latest")
	renderFails(t, "needs at least one root pin", "clusterName=cmtc-a", "image.tag=x",
		"controller.issuerProfile.enabled=true", "controller.issuerProfile.sourceUID=a", "controller.issuerProfile.outputUID=b")
	renderFails(t, "is not 64 lowercase hex characters", "clusterName=cmtc-a", "image.tag=x",
		"controller.issuerProfile.enabled=true", "controller.issuerProfile.sourceUID=a", "controller.issuerProfile.outputUID=b",
		"controller.issuerProfile.rootSHA256[0]=ABC")
	renderFails(t, "sourceUID is required", "clusterName=cmtc-a", "image.tag=x",
		"controller.issuerProfile.enabled=true", "controller.issuerProfile.rootSHA256[0]="+strings.Repeat("a", 64))
}

func TestTrustIsOwnedByTheChart(t *testing.T) {
	for k := range render(t, "clusterName=cmtc-a", "image.tag=x") {
		if strings.HasPrefix(k, "Certificate/") || strings.HasPrefix(k, "ClusterIssuer/") || strings.HasPrefix(k, "Bundle/") {
			t.Errorf("%s rendered without trust.enabled", k)
		}
	}
	// helm template has no cluster to ask, so the test names the cert-manager and trust-manager APIs.
	trustAPIs := []string{"--api-versions", "cert-manager.io/v1/Certificate", "--api-versions", "trust.cert-manager.io/v1alpha1/Bundle"}
	got := renderWith(t, trustAPIs, "clusterName=cmtc-a", "image.tag=x", "trust.enabled=true")
	cert, issuer, bundle := got["Certificate/cmtc-a-spire-intermediate"], got["ClusterIssuer/cmtc-a-spire-intermediate"], got["Bundle/cmtc-mesh-root"]
	if cert == nil || issuer == nil || bundle == nil {
		t.Fatalf("trust objects missing: certificate %v, issuer %v, bundle %v", cert != nil, issuer != nil, bundle != nil)
	}
	for path, want := range map[string]any{
		"metadata.namespace": "cert-manager", "spec.isCA": true, "spec.commonName": "cmtc-a SPIRE intermediate CA",
		"spec.duration": "26280h", "spec.renewBefore": "8760h", "spec.secretName": "cmtc-a-spire-intermediate",
		"spec.privateKey.algorithm": "ECDSA", "spec.privateKey.rotationPolicy": "Always",
		"spec.issuerRef.name": "cmtc-mesh-root", "spec.issuerRef.kind": "ClusterIssuer",
	} {
		if v := dig(cert, strings.Split(path, ".")...); v != want {
			t.Errorf("Certificate %s: %v, want %v", path, v, want)
		}
	}
	if v := dig(issuer, "spec", "ca", "secretName"); v != "cmtc-a-spire-intermediate" {
		t.Errorf("ClusterIssuer spec.ca.secretName: %v", v)
	}
	// Only the issuing root (ca.crt) is copied, and only to namespaces that opted in.
	source := dig(bundle, "spec", "sources").([]any)[0].(object)["secret"]
	if !reflect.DeepEqual(source, object{"name": "cmtc-a-spire-intermediate", "key": "ca.crt"}) {
		t.Errorf("Bundle source: %v", source)
	}
	if v := dig(bundle, "spec", "target", "namespaceSelector", "matchLabels"); !reflect.DeepEqual(v, object{"trust": "enabled"}) {
		t.Errorf("Bundle namespaceSelector.matchLabels: %v", v)
	}
	if v := dig(got["Namespace/cmtc-system"], "metadata", "labels", "trust"); v != "enabled" {
		t.Errorf("the release namespace must opt in to the mesh root: label trust=%v", v)
	}
	renderFailsWith(t, trustAPIs, "trust.bundle.namespaceLabels must name at least one label", "clusterName=cmtc-a", "image.tag=x",
		"trust.enabled=true", "trust.bundle.namespaceLabels=null")
	renderFails(t, "trust.enabled needs cert-manager installed first (no cert-manager.io/v1 Certificate API)",
		"clusterName=cmtc-a", "image.tag=x", "trust.enabled=true")
	certManagerOnly := []string{"--api-versions", "cert-manager.io/v1/Certificate"}
	renderFailsWith(t, certManagerOnly, "trust.enabled needs cert-manager and trust-manager installed first (no trust.cert-manager.io/v1alpha1 Bundle API)",
		"clusterName=cmtc-a", "image.tag=x", "trust.enabled=true")
}

// The issuer approval arbiter (ADR-012): its configuration file carries the administrator's identities, the producer
// follows the slots instead of a fixed source, the readers' Role names the two fixed slots, the peer credential is
// mounted, and the node agent reports from the pins and checkpoint directories as uid 0 with every capability dropped.
func TestIssuerApprovalArbiterIsConfiguredByTheChart(t *testing.T) {
	root := strings.Repeat("a", 64)
	base := []string{"clusterName=cmtc-a", "image.tag=x", "controller.issuerProfile.enabled=true", "controller.issuerProfile.source=cmtc-issuer-approval-g6",
		"controller.issuerProfile.outputUID=fbc7b3c2-00f1-4787-a149-fca76e274c4e", "controller.issuerProfile.rootSHA256[0]=" + root, "controller.issuerProfile.minimumGeneration=6",
		"controller.issuerProfile.readers[0].namespace=kube-system", "controller.issuerProfile.readers[0].name=cilium", "controller.issuerApproval.enabled=true",
		"controller.issuerApproval.clusters[0].name=cmtc-a", "controller.issuerApproval.clusters[0].trustDomain=cmtc-a.mesh.example", "controller.issuerApproval.clusters[0].certificateUID=u-a",
		"controller.issuerApproval.clusters[1].name=cmtc-b", "controller.issuerApproval.clusters[1].trustDomain=cmtc-b.mesh.example", "controller.issuerApproval.clusters[1].certificateUID=u-b",
		"controller.issuerApproval.clusters[1].peerSecret=cmtc-peer-cmtc-b", "controller.issuerApproval.peerReader.enabled=true",
		"nodeAgent.trustReport.enabled=true", "nodeAgent.trustReport.managePins=true"}
	got := render(t, base...)
	controller := dig(got["Deployment/cmtc-controller"], "spec", "template", "spec").(object)
	args := controller["containers"].([]any)[0].(object)["args"]
	want := []any{"--mode=controller", "--cluster-name=cmtc-a", "--issuer-profile-producer=true", "--issuer-profile-namespace=cmtc-system",
		"--issuer-profile-output=cmtc-issuer-publication", "--issuer-profile-output-uid=fbc7b3c2-00f1-4787-a149-fca76e274c4e", "--issuer-profile-root-sha256=" + root,
		"--issuer-profile-minimum-generation=6", "--issuer-approval-config=/etc/cmtc/issuer-approval/config.json"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("controller args:\ngot  %v\nwant %v", args, want)
	}
	var config object
	if err := yaml.Unmarshal([]byte(dig(got["ConfigMap/cmtc-issuer-approval-config"], "data", "config.json").(string)), &config); err != nil {
		t.Fatal(err)
	}
	for path, v := range map[string]any{"namespace": "cmtc-system", "adoptSource": "cmtc-issuer-approval-g6", "output": "cmtc-issuer-publication", "rootConfigMap": "cmtc-mesh-root",
		"certManagerNamespace": "cert-manager", "rootIssuer": "cmtc-mesh-root", "spireNamespace": "cilium-spire", "spireConfigMap": "spire-server", "minimumGeneration": float64(6),
		"horizon": "696h", "renewBefore": "168h", "retirementMargin": "1h", "reportMaxAge": "2m"} {
		if config[path] != v {
			t.Errorf("config %s: %v, want %v", path, config[path], v)
		}
	}
	if !reflect.DeepEqual(config["slots"], []any{"cmtc-issuer-approval-a", "cmtc-issuer-approval-b"}) || !reflect.DeepEqual(config["rootSHA256"], []any{root}) {
		t.Errorf("config slots/roots: %v %v", config["slots"], config["rootSHA256"])
	}
	clusters := []any{
		object{"name": "cmtc-a", "trustDomain": "cmtc-a.mesh.example", "certificate": "cmtc-a-spire-intermediate", "certificateUID": "u-a"},
		object{"name": "cmtc-b", "trustDomain": "cmtc-b.mesh.example", "certificate": "cmtc-b-spire-intermediate", "certificateUID": "u-b", "kubeconfig": "/etc/cmtc/peers/cmtc-b/kubeconfig"},
	}
	if !reflect.DeepEqual(config["clusters"], clusters) {
		t.Errorf("config clusters: %v", config["clusters"])
	}
	volumes := controller["volumes"]
	if !reflect.DeepEqual(volumes, []any{object{"name": "issuer-approval-config", "configMap": object{"name": "cmtc-issuer-approval-config"}},
		object{"name": "peer-cmtc-b", "secret": object{"secretName": "cmtc-peer-cmtc-b", "items": []any{object{"key": "kubeconfig", "path": "kubeconfig"}}}}}) {
		t.Errorf("controller volumes: %v", volumes)
	}
	slots := []any{"cmtc-issuer-approval-a", "cmtc-issuer-approval-b"}
	if r := got["Role/cmtc-issuer-profile-access"]["rules"].([]any)[0]; !reflect.DeepEqual(dig(r, "resourceNames"), append([]any{"cmtc-issuer-approval-g6"}, slots...)) {
		t.Errorf("producer reads the adopted source and the slots: %v", r)
	}
	if r := got["Role/cmtc-issuer-profile-readers"]["rules"].([]any)[0]; !reflect.DeepEqual(dig(r, "resourceNames"), []any{"cmtc-issuer-approval-g6", "cmtc-issuer-approval-a", "cmtc-issuer-approval-b", "cmtc-issuer-publication"}) {
		t.Errorf("readers' Role names the fixed slots: %v", r)
	}
	arbiter := got["Role/cmtc-issuer-approval-arbiter"]["rules"].([]any)
	if !reflect.DeepEqual(dig(arbiter[0], "resourceNames"), slots) || !reflect.DeepEqual(dig(arbiter[0], "verbs"), []any{"get", "delete"}) || !reflect.DeepEqual(dig(arbiter[1], "verbs"), []any{"create"}) {
		t.Errorf("arbiter Role: %v", arbiter)
	}
	for _, name := range []string{"ClusterRole/cmtc-issuer-approval-evidence", "ClusterRole/cmtc-peer-reader"} {
		rules := got[name]["rules"].([]any)
		for _, r := range rules {
			for _, v := range dig(r, "verbs").([]any) {
				if v != "get" && v != "list" && v != "watch" {
					t.Errorf("%s grants %v", name, r)
				}
			}
			if reflect.DeepEqual(dig(r, "resources"), []any{"secrets"}) {
				t.Errorf("%s reads Secrets", name)
			}
		}
	}
	if s := got["RoleBinding/cmtc-issuer-approval-spire-config"]["metadata"].(object)["namespace"]; s != "cilium-spire" {
		t.Errorf("SPIRE config RoleBinding namespace: %v", s)
	}
	policy := dig(got["ValidatingAdmissionPolicy/cmtc-node-trust-report-owner"], "spec").(object)
	if e := dig(policy["matchConditions"].([]any)[0], "expression"); e != "request.userInfo.username == 'system:serviceaccount:cmtc-system:cmtc-node-agent'" {
		t.Errorf("report policy match: %v", e)
	}
	if e := dig(policy["validations"].([]any)[1], "expression"); e != "size(variables.nodeNames) == 1 && variables.nodeNames[0] == variables.reportName" {
		t.Errorf("report policy validation: %v", e)
	}
	// A denial of authority answers 403 (StatusReasonForbidden), not the policy default 422 (StatusReasonInvalid).
	for _, v := range policy["validations"].([]any) {
		if r := dig(v, "reason"); r != "Forbidden" {
			t.Errorf("report policy validation reason: %v", r)
		}
	}
	if r := dig(dig(got["ValidatingAdmissionPolicy/cmtc-issuer-approval-slots"], "spec", "validations").([]any)[0], "reason"); r != "Forbidden" {
		t.Errorf("slot policy validation reason: %v", r)
	}
	if v := dig(got["ValidatingAdmissionPolicyBinding/cmtc-node-trust-report-owner"], "spec", "validationActions"); !reflect.DeepEqual(v, []any{"Deny"}) {
		t.Errorf("report policy binding: %v", v)
	}
	if e := dig(dig(got["ValidatingAdmissionPolicy/cmtc-issuer-approval-slots"], "spec", "validations").([]any)[0], "expression"); e != `object.metadata.name in ["cmtc-issuer-approval-a","cmtc-issuer-approval-b"]` {
		t.Errorf("slot policy validation: %v", e)
	}
	if r := got["ClusterRole/cmtc-node-trust-report"]["rules"].([]any)[0]; !reflect.DeepEqual(dig(r, "verbs"), []any{"get", "create", "update"}) {
		t.Errorf("node agent report verbs: %v", r)
	}
	agent := dig(got["DaemonSet/cmtc-node-agent"], "spec", "template", "spec").(object)
	if sc := agent["securityContext"].(object); sc["runAsUser"] != float64(0) || sc["runAsNonRoot"] != false || dig(sc, "seccompProfile", "type") != "RuntimeDefault" {
		t.Errorf("node agent pod security context: %v", sc)
	}
	container := agent["containers"].([]any)[0].(object)
	if !reflect.DeepEqual(dig(container, "securityContext", "capabilities", "drop"), []any{"ALL"}) || dig(container, "securityContext", "readOnlyRootFilesystem") != true {
		t.Errorf("node agent container security context: %v", container["securityContext"])
	}
	agentArgs := []any{"--mode=node", "--cluster-name=cmtc-a", "--node-trust-report=true", "--pins-dir=/etc/cmtc/ztunnel-issuer-pins",
		"--checkpoint-dir=/var/lib/cmtc/ztunnel-issuer-checkpoint", "--manage-pins=true", "--node-root-sha256=" + root}
	if !reflect.DeepEqual(container["args"], agentArgs) {
		t.Errorf("node agent args:\ngot  %v\nwant %v", container["args"], agentArgs)
	}
	mounts := []any{object{"name": "issuer-pins", "mountPath": "/etc/cmtc/ztunnel-issuer-pins", "readOnly": false},
		object{"name": "issuer-checkpoint", "mountPath": "/var/lib/cmtc/ztunnel-issuer-checkpoint", "readOnly": true}}
	if !reflect.DeepEqual(container["volumeMounts"], mounts) {
		t.Errorf("node agent mounts: %v", container["volumeMounts"])
	}
	if v := agent["volumes"]; !reflect.DeepEqual(v, []any{object{"name": "issuer-pins", "hostPath": object{"path": "/etc/cmtc/ztunnel-issuer-pins", "type": "Directory"}},
		object{"name": "issuer-checkpoint", "hostPath": object{"path": "/var/lib/cmtc/ztunnel-issuer-checkpoint", "type": "Directory"}}}) {
		t.Errorf("node agent volumes: %v", v)
	}
	// Without managePins the pins directory is read-only and the agent stays at the image's user.
	plain := dig(render(t, "clusterName=cmtc-a", "image.tag=x", "nodeAgent.trustReport.enabled=true")["DaemonSet/cmtc-node-agent"], "spec", "template", "spec").(object)
	if m := plain["containers"].([]any)[0].(object)["volumeMounts"].([]any)[0]; dig(m, "readOnly") != true {
		t.Errorf("pins mount without managePins: %v", m)
	}
	// Nothing of the arbiter renders when it is off.
	for k := range render(t, "clusterName=cmtc-a", "image.tag=x") {
		if strings.Contains(k, "issuer-approval") || strings.Contains(k, "trust-report") || strings.Contains(k, "peer-reader") || strings.HasPrefix(k, "ValidatingAdmissionPolicy") {
			t.Errorf("%s rendered with the arbiter off", k)
		}
	}
	for _, crd := range []string{"issuerapprovals", "nodetrustreports"} {
		if dig(got["CustomResourceDefinition/"+crd+".security.cmtc.io"], "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
			t.Errorf("the %s CRD must carry helm.sh/resource-policy: keep", crd)
		}
	}
	replace := func(old, new string) []string {
		out := append([]string(nil), base...)
		for i, s := range out {
			if s == old {
				out[i] = new
			}
		}
		return out
	}
	renderFails(t, "needs controller.issuerProfile.enabled", replace("controller.issuerProfile.enabled=true", "controller.issuerProfile.enabled=false")...)
	renderFails(t, "clusters[cmtc-b].peerSecret is required", replace("controller.issuerApproval.clusters[1].peerSecret=cmtc-peer-cmtc-b", "controller.issuerApproval.clusters[1].peerSecret=")...)
	renderFails(t, "clusters[cmtc-a] is the local cluster and takes no peerSecret", append(base, "controller.issuerApproval.clusters[0].peerSecret=x")...)
	renderFails(t, "must include the local cluster", append(replace("controller.issuerApproval.clusters[0].name=cmtc-a", "controller.issuerApproval.clusters[0].name=cmtc-c"), "controller.issuerApproval.clusters[0].peerSecret=cmtc-peer-cmtc-c")...)
	renderFails(t, "clusters[cmtc-b].certificateUID is required", replace("controller.issuerApproval.clusters[1].certificateUID=u-b", "controller.issuerApproval.clusters[1].certificateUID=")...)
	renderFails(t, "collides with the issuer-profile source", append(base, "controller.issuerApproval.slots[0]=cmtc-issuer-approval-g6", "controller.issuerApproval.slots[1]=cmtc-issuer-approval-b")...)
	renderFails(t, "managePins needs rootSHA256", "clusterName=cmtc-a", "image.tag=x", "nodeAgent.trustReport.enabled=true", "nodeAgent.trustReport.managePins=true")
}
