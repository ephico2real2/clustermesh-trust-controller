// Package charts tests the CMTC Helm chart by rendering it with the helm CLI and comparing the objects with
// config/default (rendered by kubectl kustomize), the manifests the chart replaces.
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
	args := append([]string{"template", "cmtc", "./cmtc", "--namespace", "cmtc-system"}, helmArgs...)
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
	args := append([]string{"template", "cmtc", "./cmtc", "--namespace", "cmtc-system"}, helmArgs...)
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
