# Cursor two-cluster PKI implementation proposal

> Historical design input. This document is not an accepted implementation or a current runbook. Use [delivery status](../../agile/DELIVERY_STATUS.md) for measured results and open gates.

Session: `2358cd68-fbf8-4652-a025-5566243e07fd`. CLI model verified: Grok 4.7 256K Extra High. Proposal only. Primary review and local qualification are required.

The PKI bootstrap has to follow the real scripts and the direct-root producer limit. I’ll read those interfaces first, then return complete scripts and tests without changing the labs.The Cilium chart can render SPIRE only when `authentication.mutual.spire.enabled` is true. That same flag rewrites the Cilium ConfigMap and agent volume mounts, so this proposal does not Helm-upgrade Cilium. SPIRE is a standalone manifest derived from the chart. The current `lab-identity-init` cannot safely retry and always creates the ztunnel secret, so the proposal adds an explicit `cluster-ca` mode and leaves the legacy mode unchanged. These tests were not executed.

The chart gate is `install/kubernetes/cilium/templates/spire/server/configmap.yaml` line 1: SPIRE objects render only when both `authentication.mutual.spire.enabled` and `authentication.mutual.spire.install.enabled` are true. The same enabled flag writes `mesh-auth-spire-*` at `templates/cilium-configmap.yaml` line 1490 and mounts the agent socket at `templates/cilium-agent/daemonset.yaml` line 313. `templates/validate.yaml` lines 268–269 tie SPIRE to ztunnel only when encryption is already `ztunnel`. Leaving encryption false is not enough, because enabling the SPIRE flag still changes the running agent. The bootstrap snapshots the Cilium release and stops if that snapshot changes.

The qualified producer rejects this hierarchy. `internal/trustprofile/profile.go` lines 339–343 reject any `ChainPEM` and require the issuer to be signed directly by the organizational root. Do not point the producer at these certificates. The SPIRE CA remains the only workload signer. Pod Ready, a SPIRE registration, or an xDS ACK is not Protected.

Pinned images and domains:

| Item | Value |
|---|---|
| cert-manager chart | `v1.21.1` |
| SPIRE server | `ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384` |
| SPIRE agent | `ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481` |
| init image | `docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e` |
| legacy initializer to reject | `a6723c7813b6f52e49184503400742867da0be40b7d70d46ce41681f5b83d5ae` |
| `cmtc-a` | context `kind-cmtc-a`, domain `cmtc-a.mesh.example` |
| `cmtc-b` | context `kind-cmtc-b`, domain `cmtc-b.mesh.example` |

## `cmd/lab-identity-init/main.go`

Keep `initialize` and its tests. Replace `run` and add the cluster-CA path.

```go
func run() error {
	mode, err := selectMode(os.Getenv("LAB_INIT_MODE"))
	if err != nil {
		return err
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch mode {
	case "legacy":
		return initialize(ctx, client, os.Getenv("CLUSTER_NAME"), os.Stdout)
	case "cluster-ca":
		return initializeClusterCA(ctx, client, os.Getenv("CLUSTER_NAME"), os.Stdout)
	default:
		return fmt.Errorf("unsupported LAB_INIT_MODE")
	}
}

func selectMode(mode string) (string, error) {
	switch mode {
	case "", "legacy":
		return "legacy", nil
	case "cluster-ca":
		return "cluster-ca", nil
	default:
		return "", fmt.Errorf("LAB_INIT_MODE must be legacy or cluster-ca")
	}
}

const (
	pkiOwnerLabel = "security.cmtc.io/pki-owner"
	pkiOwnerValue = "cmtc-lab-pki"
	pkiCluster    = "security.cmtc.io/pki-cluster"
	pkiRole       = "security.cmtc.io/pki-role"
	pkiCSR        = "security.cmtc.io/public-csr"
)

func initializeClusterCA(ctx context.Context, client kubernetes.Interface, cluster string, output io.Writer) error {
	if cluster == "" || len(validation.IsDNS1123Subdomain(cluster)) != 0 {
		return fmt.Errorf("CLUSTER_NAME must be a DNS subdomain")
	}
	secrets := client.CoreV1().Secrets("cert-manager")
	existing, err := secrets.Get(ctx, "cluster-intermediate", metav1.GetOptions{})
	if err == nil {
		csr, err := reuseClusterCA(existing, cluster)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(publicRequests{ClusterIssuerCSR: csr})
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	key, csr, err := keyAndRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: cluster + " cluster CA"}})
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-intermediate", Namespace: "cert-manager",
			Labels: map[string]string{pkiOwnerLabel: pkiOwnerValue, pkiCluster: cluster, pkiRole: "cluster-ca"},
			Annotations: map[string]string{pkiCSR: csr},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.key": key},
	}
	if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create cert-manager/cluster-intermediate: %w", err)
		}
		existing, getErr := secrets.Get(ctx, "cluster-intermediate", metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		csr, err = reuseClusterCA(existing, cluster)
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(output).Encode(publicRequests{ClusterIssuerCSR: csr})
}

func reuseClusterCA(secret *corev1.Secret, cluster string) (string, error) {
	if secret.Labels[pkiOwnerLabel] != pkiOwnerValue || secret.Labels[pkiCluster] != cluster || secret.Labels[pkiRole] != "cluster-ca" {
		return "", fmt.Errorf("conflict: cert-manager/cluster-intermediate has another owner")
	}
	for name := range secret.Data {
		if name != "tls.key" && name != "tls.crt" {
			return "", fmt.Errorf("conflict: cert-manager/cluster-intermediate has an unexpected field")
		}
	}
	csr := secret.Annotations[pkiCSR]
	if err := samePublicKey(secret.Data["tls.key"], csr); err != nil {
		return "", fmt.Errorf("conflict: stored cluster CA key does not match its public CSR: %w", err)
	}
	return csr, nil
}

func samePublicKey(keyPEM []byte, csrPEM string) error {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return fmt.Errorf("cluster CA private key is absent")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	signer, ok := parsed.(interface{ Public() crypto.PublicKey })
	if !ok {
		return fmt.Errorf("cluster CA key is not a signer")
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		return fmt.Errorf("public CSR is absent")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	csrBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(keyBytes, csrBytes) {
		return fmt.Errorf("public keys differ")
	}
	return nil
}
```

Add imports `bytes`, `crypto`, and `k8s.io/apimachinery/pkg/api/errors`.

## `cmd/lab-identity-init/main_test.go`

```go
func TestClusterCARetriesTheSamePublicRequest(t *testing.T) {
	client := fake.NewClientset()
	var first bytes.Buffer
	if err := initializeClusterCA(t.Context(), client, "cmtc-a", &first); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("private key escaped")
	}
	var second bytes.Buffer
	if err := initializeClusterCA(t.Context(), client, "cmtc-a", &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("retry minted a new CSR")
	}
	secret, err := client.CoreV1().Secrets("cert-manager").Get(t.Context(), "cluster-intermediate", metav1.GetOptions{})
	if err != nil || len(client.Actions()) == 0 {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().Secrets("kube-system").Get(t.Context(), "cilium-ztunnel-secrets", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("cluster-ca mode created the ztunnel secret", err)
	}
	if secret.Labels["security.cmtc.io/pki-cluster"] != "cmtc-a" || len(secret.Data) != 1 {
		t.Fatal("owned cluster CA secret has the wrong identity or fields")
	}
}

func TestClusterCARejectsAForeignSecret(t *testing.T) {
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cluster-intermediate", Namespace: "cert-manager", UID: "foreign-uid"}}
	client := fake.NewClientset(foreign)
	var output bytes.Buffer
	if err := initializeClusterCA(t.Context(), client, "cmtc-a", &output); err == nil || output.Len() != 0 {
		t.Fatal("foreign secret was overwritten or a CSR was emitted", err)
	}
	got, _ := client.CoreV1().Secrets("cert-manager").Get(t.Context(), "cluster-intermediate", metav1.GetOptions{})
	if got.UID != "foreign-uid" || len(got.Data) != 0 {
		t.Fatal("foreign secret changed")
	}
}

func TestSelectMode(t *testing.T) {
	if mode, err := selectMode(""); err != nil || mode != "legacy" {
		t.Fatal(mode, err)
	}
	if mode, err := selectMode("cluster-ca"); err != nil || mode != "cluster-ca" {
		t.Fatal(mode, err)
	}
	if _, err := selectMode("force"); err == nil {
		t.Fatal("unknown mode was accepted")
	}
}
```

## `scripts/lab/pki/render_spire.py`

```python
#!/usr/bin/env python3
"""Render a standalone SPIRE install derived from Cilium chart v1.15.5 templates."""
import json, sys

SERVER = "ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384"
AGENT = "ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481"
BUSYBOX = "docker.io/library/busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
CLUSTERS = {
    "cmtc-a": {"context": "kind-cmtc-a", "domain": "cmtc-a.mesh.example"},
    "cmtc-b": {"context": "kind-cmtc-b", "domain": "cmtc-b.mesh.example"},
}
LEGACY_INIT_SHA = "a6723c7813b6f52e49184503400742867da0be40b7d70d46ce41681f5b83d5ae"

def server_conf(cluster, domain):
    issuer = cluster + "-cluster-ca"
    return f'''server {{
      bind_address = "0.0.0.0"
      bind_port = "8081"
      socket_path = "/tmp/spire-server/private/api.sock"
      trust_domain = "{domain}"
      data_dir = "/run/spire/data"
      log_level = "INFO"
      ca_key_type = "rsa-4096"
      ca_subject = {{
        country = ["US"],
        organization = ["SPIRE"],
        common_name = "{cluster} SPIRE CA",
      }}
      admin_ids = [
        "spiffe://{domain}/cilium-operator",
      ]
    }}
    plugins {{
      DataStore "sql" {{
        plugin_data {{
          database_type = "sqlite3"
          connection_string = "/run/spire/data/datastore.sqlite3"
        }}
      }}
      NodeAttestor "k8s_psat" {{
        plugin_data {{
          clusters = {{
            "{cluster}" = {{
              use_token_review_api_validation = true
              service_account_allow_list = ["cilium-spire:spire-agent"]
            }}
          }}
        }}
      }}
      KeyManager "disk" {{
        plugin_data {{
          keys_path = "/run/spire/data/keys.json"
        }}
      }}
      UpstreamAuthority "cert-manager" {{
        plugin_data {{
          namespace = "cilium-spire"
          issuer_name = "{issuer}"
          issuer_kind = "ClusterIssuer"
          issuer_group = "cert-manager.io"
        }}
      }}
      Notifier "k8sbundle" {{
        plugin_data {{
          namespace = "cilium-spire"
        }}
      }}
    }}
    health_checks {{
      listener_enabled = true
      bind_address = "0.0.0.0"
      bind_port = "8080"
      live_path = "/live"
      ready_path = "/ready"
    }}
'''

def agent_conf(domain):
    return f'''agent {{
      data_dir = "/run/spire"
      log_level = "ERROR"
      server_address = "spire-server.cilium-spire.svc"
      server_port = "8081"
      socket_path = "/run/spire/sockets/agent.sock"
      trust_bundle_path = "/run/spire/bundle/bundle.crt"
      trust_domain = "{domain}"
    }}
    plugins {{
      NodeAttestor "k8s_psat" {{
        plugin_data {{
          cluster = "{domain.split(".")[0]}"
        }}
      }}
      KeyManager "memory" {{
        plugin_data {{}}
      }}
      WorkloadAttestor "k8s" {{
        plugin_data {{
          skip_kubelet_verification = true
        }}
      }}
    }}
    health_checks {{
      listener_enabled = true
      bind_address = "0.0.0.0"
      bind_port = "4251"
      live_path = "/live"
      ready_path = "/ready"
    }}
'''

def node_entry_script(domain):
    agent_id = f"spiffe://{domain}/ns/cilium-spire/sa/spire-agent"
    return f'''set -e
while ! pgrep spire-server >/dev/null; do sleep 2; done
pid=$(pgrep spire-server)
root=/proc/$pid/root
bin=$root/opt/spire/bin/spire-server
sock=$root/tmp/spire-server/private/api.sock
id="{agent_id}"
sel="-selector k8s_psat:agent_ns:cilium-spire -selector k8s_psat:agent_sa:spire-agent"
while ! "$bin" entry show -socketPath "$sock" >/dev/null 2>&1; do sleep 2; done
if "$bin" entry show -socketPath "$sock" -spiffeID "$id" $sel | grep -q "Found 0 entries"; then
  "$bin" entry create -socketPath "$sock" -spiffeID "$id" $sel -node
fi
'''

def manifest(cluster):
    if cluster not in CLUSTERS:
        raise SystemExit("unknown cluster")
    domain = CLUSTERS[cluster]["domain"]
    labels = f'security.cmtc.io/pki-owner: cmtc-lab-pki\n    security.cmtc.io/pki-cluster: {cluster}'
    return f'''apiVersion: v1
kind: Namespace
metadata:
  name: cilium-spire
  labels:
    {labels}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-server
  namespace: cilium-spire
  labels:
    {labels}
data:
  server.conf: |
{indent(server_conf(cluster, domain), 4)}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent
  namespace: cilium-spire
  labels:
    {labels}
data:
  agent.conf: |
{indent(agent_conf(cluster), 4)}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-bundle
  namespace: cilium-spire
  labels:
    {labels}
data: {{}}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spire-server
  namespace: cilium-spire
  labels:
    {labels}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spire-agent
  namespace: cilium-spire
  labels:
    {labels}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: spire-server
  namespace: cilium-spire
  labels:
    {labels}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: spire-upstreamauthority
  namespace: cilium-spire
  labels:
    {labels}
rules:
- apiGroups: ["cert-manager.io"]
  resources: ["certificaterequests"]
  verbs: ["create", "get", "list", "watch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: spire-server
  namespace: cilium-spire
  labels:
    {labels}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: Role, name: spire-server}}
subjects: [{{kind: ServiceAccount, name: spire-server, namespace: cilium-spire}}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: spire-upstreamauthority
  namespace: cilium-spire
  labels:
    {labels}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: Role, name: spire-upstreamauthority}}
subjects: [{{kind: ServiceAccount, name: spire-server, namespace: cilium-spire}}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cmtc-lab-spire-server
  labels:
    {labels}
rules:
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["nodes", "nodes/proxy"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cmtc-lab-spire-server
  labels:
    {labels}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cmtc-lab-spire-server}}
subjects: [{{kind: ServiceAccount, name: spire-server, namespace: cilium-spire}}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cmtc-lab-spire-agent
  labels:
    {labels}
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "nodes/proxy"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cmtc-lab-spire-agent
  labels:
    {labels}
roleRef: {{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cmtc-lab-spire-agent}}
subjects: [{{kind: ServiceAccount, name: spire-agent, namespace: cilium-spire}}]
---
apiVersion: v1
kind: Service
metadata:
  name: spire-server
  namespace: cilium-spire
  labels:
    {labels}
spec:
  selector: {{app: spire-server}}
  ports:
  - name: grpc
    port: 8081
  - name: http
    port: 8080
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
  namespace: cilium-spire
  labels:
    app: spire-server
    {labels}
spec:
  replicas: 1
  serviceName: spire-server
  selector:
    matchLabels: {{app: spire-server}}
  template:
    metadata:
      labels:
        app: spire-server
        {labels}
    spec:
      serviceAccountName: spire-server
      shareProcessNamespace: true
      securityContext: {{runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000}}
      containers:
      - name: agent-node-entry
        image: "{BUSYBOX}"
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c", {json.dumps(node_entry_script(domain))}]
      - name: spire-server
        image: "{SERVER}"
        imagePullPolicy: IfNotPresent
        args: ["-config", "/run/spire/config/server.conf"]
        ports:
        - name: grpc
          containerPort: 8081
        - name: http
          containerPort: 8080
        volumeMounts:
        - name: spire-config
          mountPath: /run/spire/config
          readOnly: true
        - name: spire-data
          mountPath: /run/spire/data
        - name: spire-server-socket
          mountPath: /tmp/spire-server/private
        readinessProbe:
          httpGet: {{path: /ready, port: http}}
      volumes:
      - name: spire-config
        configMap: {{name: spire-server}}
      - name: spire-data
        emptyDir: {{}}
      - name: spire-server-socket
        emptyDir: {{}}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: cilium-spire
  labels:
    app: spire-agent
    {labels}
spec:
  selector:
    matchLabels: {{app: spire-agent}}
  template:
    metadata:
      labels:
        app: spire-agent
        {labels}
    spec:
      serviceAccountName: spire-agent
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      securityContext: {{runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000}}
      initContainers:
      - name: wait-for-server
        image: "{BUSYBOX}"
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c", "for i in $(seq 1 60); do nc -z spire-server.cilium-spire.svc 8081 && exit 0; sleep 1; done; exit 1"]
      containers:
      - name: spire-agent
        image: "{AGENT}"
        imagePullPolicy: IfNotPresent
        args: ["-config", "/run/spire/config/agent.conf"]
        volumeMounts:
        - name: spire-config
          mountPath: /run/spire/config
          readOnly: true
        - name: spire-bundle
          mountPath: /run/spire/bundle
        - name: spire-agent-socket
          mountPath: /run/spire/sockets
        - name: spire-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
      volumes:
      - name: spire-config
        configMap: {{name: spire-agent}}
      - name: spire-bundle
        configMap: {{name: spire-bundle}}
      - name: spire-agent-socket
        emptyDir: {{}}
      - name: spire-token
        projected:
          sources:
          - serviceAccountToken:
              path: spire-agent
              expirationSeconds: 600
              audience: spire-server
'''

def indent(text, spaces):
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())

def assert_safe(text):
    forbidden = ["encryption.enabled", "encryption.type", "ztunnel-cilium", "mesh-auth-spire", "hostPath", "cilium-agent entry", "cilium-operator entry", "cmtc-mtls"]
    for item in forbidden:
        if item in text:
            raise SystemExit("rendered SPIRE manifest contains " + item)
    for image in (SERVER, AGENT, BUSYBOX):
        if image not in text:
            raise SystemExit("missing pinned image " + image)
    if "runAsUser: 1000" not in text or "emptyDir" not in text:
        raise SystemExit("server socket is not UID 1000 emptyDir")
    if text.count("entry create") != 1 or "-node" not in text:
        raise SystemExit("registration is not limited to the agent node entry")

def main():
    cluster = sys.argv[1]
    text = manifest(cluster)
    assert_safe(text)
    sys.stdout.write(text)

if __name__ == "__main__":
    main()
```

The agent node entry is the chart's agent registration from `files/spire/init.bash`. The Cilium agent and operator entries in that file are omitted. `admin_ids` still names `cilium-operator`, and this install does not create that identity, so there is no admin caller. Workload API stays on the agent `emptyDir`. No workload registration is created.

Fix the agent attestor cluster: it must be the cluster name `cmtc-a`, not the trust domain. In `agent_conf`, use the `cluster` argument. I will correct that in the file as written below by changing the function to take `cluster`.

The block above passes `domain.split(".")[0]`, which is `cmtc-a` for `cmtc-a.mesh.example`. That matches. Keep it.

## `scripts/lab/pki/ownership.py`

```python
#!/usr/bin/env python3
"""Ownership, public-output, and UID-precondition decisions. No cluster calls."""
import json, os, stat

OWNER = "cmtc-lab-pki"
CLUSTERS = {
    "cmtc-a": "kind-cmtc-a",
    "cmtc-b": "kind-cmtc-b",
}

class Refusal(Exception):
    pass

def require_target(cluster, context):
    if cluster == "cmtc-mtls" or context == "kind-cmtc-mtls":
        raise Refusal("cmtc-mtls is forbidden")
    if CLUSTERS.get(cluster) != context:
        raise Refusal("context does not match cluster")

def classify(obj, cluster, role):
    meta = obj.get("metadata") or {}
    labels = meta.get("labels") or {}
    if not meta.get("uid"):
        raise Refusal("object has no UID")
    if labels.get("security.cmtc.io/pki-owner") != OWNER or labels.get("security.cmtc.io/pki-cluster") != cluster or labels.get("security.cmtc.io/pki-role") != role:
        raise Refusal("existing object has another owner")
    return {"uid": meta["uid"], "resourceVersion": meta["resourceVersion"], "reuse": True}

def delete_options(uid, resource_version):
    if not uid or not resource_version:
        raise Refusal("cleanup requires UID and resourceVersion")
    return {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground", "preconditions": {"uid": uid, "resourceVersion": resource_version}}

def certificate_patch(uid, resource_version, certificate_b64):
    if not certificate_b64 or "PRIVATE KEY" in certificate_b64:
        raise Refusal("certificate patch is not public")
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "add", "path": "/data/tls.crt", "value": certificate_b64},
    ]

def assert_public(text):
    for marker in ("PRIVATE KEY", "tls.key", "client-certificate-data", "client-key-data", "BEGIN OPENSSH PRIVATE KEY"):
        if marker in text:
            raise Refusal("output contains private material")

def root_state(path):
    cert, key = os.path.join(path, "root.crt"), os.path.join(path, "root.key")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode != 0o700:
        raise Refusal("root directory mode is not 0700")
    have_cert, have_key = os.path.exists(cert), os.path.exists(key)
    if have_cert != have_key:
        raise Refusal("initialized root is incomplete; refusing to replace it")
    return "reuse" if have_cert else "create"

def cilium_unchanged(before, after):
    if before != after:
        raise Refusal("Cilium release changed")

def issuer_name(cluster):
    return cluster + "-cluster-ca"
```

## `scripts/lab/pki/bootstrap.sh`

```bash
#!/usr/bin/env bash
# Prepare cert-manager and standalone SPIRE on one existing cluster.
# Does not create a cluster, Helm-upgrade Cilium, or enable ztunnel.
set -euo pipefail
cd "$(dirname "$0")/../../.."
cluster=${1:?cluster cmtc-a or cmtc-b}
context=${2:?explicit context}
root_dir=${CMTC_PKI_ROOT_DIR:?host-private root directory}
init_image=${CMTC_PKI_INIT_IMAGE:?rebuilt lab-identity-init image}
init_sha=${CMTC_PKI_INIT_BINARY_SHA256:?binary sha of that image}
legacy_sha=a6723c7813b6f52e49184503400742867da0be40b7d70d46ce41681f5b83d5ae
if [ "$init_sha" = "$legacy_sha" ]; then
  echo "Refusing the legacy initializer. It cannot retry and creates the ztunnel secret." >&2
  exit 1
fi
python3 - "$cluster" "$context" <<'PY'
import sys
from scripts.lab.pki.ownership import require_target
require_target(sys.argv[1], sys.argv[2])
PY
current=$(kubectl --context "$context" config current-context)
if [ "$current" != "$context" ]; then echo "kubectl context mismatch" >&2; exit 1; fi
snap=artifacts/pki/$cluster
mkdir -p "$snap"
umask 077
install -d -m 0700 "$root_dir"
python3 - "$root_dir" <<'PY'
import sys
from scripts.lab.pki.ownership import root_state
print(root_state(sys.argv[1]))
PY
helm --kube-context "$context" -n kube-system get values cilium -o yaml > "$snap/cilium-values.before.yaml"
helm --kube-context "$context" -n kube-system get manifest cilium > "$snap/cilium-manifest.before.yaml"
before=$(sha256sum "$snap/cilium-manifest.before.yaml" | awk '{print $1}')
if helm --kube-context "$context" status cert-manager -n cert-manager >/dev/null 2>&1; then
  helm --kube-context "$context" list -n cert-manager -o json > "$snap/cert-manager-release.json"
  python3 - "$snap/cert-manager-release.json" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1]))
if rows[0]["chart"] != "cert-manager-v1.21.1":
    raise SystemExit("existing cert-manager chart is not v1.21.1")
PY
else
  helm repo add jetstack https://charts.jetstack.io --force-update
  helm --kube-context "$context" upgrade --install cert-manager jetstack/cert-manager \
    --version v1.21.1 -n cert-manager --create-namespace --set crds.enabled=true --wait --timeout 10m
fi
python3 scripts/lab/pki/render_spire.py "$cluster" > "$snap/spire.yaml"
python3 - "$context" "$cluster" "$snap/spire.yaml" <<'PY'
import json,subprocess,sys
from scripts.lab.pki.ownership import Refusal, classify
context, cluster, path = sys.argv[1:]
names = [("v1","namespaces","cilium-spire","namespace"),
         ("cert-manager.io/v1","clusterissuers", cluster+"-cluster-ca","cluster-ca")]
for group, plural, name, role in (("v1","namespaces","cilium-spire","namespace"),):
    raw = subprocess.run(["kubectl","--context",context,"get","--raw",f"/api/v1/namespaces/{name}"],capture_output=True,text=True)
    if raw.returncode != 0 and "NotFound" in raw.stderr:
        continue
    if raw.returncode != 0:
        raise SystemExit(raw.stderr)
    try:
        classify(json.loads(raw.stdout), cluster, role)
    except Refusal as exc:
        raise SystemExit(str(exc))
PY
kubectl --context "$context" apply --server-side --field-manager=cmtc-lab-pki -f "$snap/spire.yaml"
# Cluster CA key stays in cert-manager/cluster-intermediate. The job uses cluster-ca mode.
kubectl --context "$context" -n kube-system apply -f - <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lab-cluster-ca-init
  labels: {security.cmtc.io/pki-owner: cmtc-lab-pki, security.cmtc.io/pki-cluster: $cluster, security.cmtc.io/pki-role: cluster-ca-init}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: lab-cluster-ca-init, namespace: cert-manager, labels: {security.cmtc.io/pki-owner: cmtc-lab-pki, security.cmtc.io/pki-cluster: $cluster}}
rules: [{apiGroups: [""], resources: [secrets], verbs: [get, create]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: lab-cluster-ca-init, namespace: cert-manager, labels: {security.cmtc.io/pki-owner: cmtc-lab-pki, security.cmtc.io/pki-cluster: $cluster}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: lab-cluster-ca-init}
subjects: [{kind: ServiceAccount, name: lab-cluster-ca-init, namespace: kube-system}]
---
apiVersion: batch/v1
kind: Job
metadata: {name: lab-cluster-ca-init, namespace: kube-system, labels: {security.cmtc.io/pki-owner: cmtc-lab-pki, security.cmtc.io/pki-cluster: $cluster}}
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: lab-cluster-ca-init
      containers:
      - name: init
        image: $init_image
        imagePullPolicy: IfNotPresent
        command: [/lab-identity-init]
        env:
        - {name: LAB_INIT_MODE, value: cluster-ca}
        - {name: CLUSTER_NAME, value: $cluster}
YAML
kubectl --context "$context" -n kube-system wait job/lab-cluster-ca-init --for=condition=Complete --timeout=3m
kubectl --context "$context" -n kube-system logs job/lab-cluster-ca-init > "$snap/public-csr.json"
python3 - "$snap/public-csr.json" <<'PY'
import pathlib,sys
from scripts.lab.pki.ownership import assert_public
assert_public(pathlib.Path(sys.argv[1]).read_text())
PY
# Sign with the host root. The root key is not copied into the cluster or this snapshot.
pki=$(mktemp -d "$snap/work.XXXXXX")
chmod 0700 "$pki"
python3 - "$snap/public-csr.json" "$pki/cluster.csr" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[2]).write_text(json.loads(pathlib.Path(sys.argv[1]).read_text())["clusterIssuerCSR"])
PY
if [ ! -f "$root_dir/root.key" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$root_dir/root.key"
  openssl req -x509 -new -key "$root_dir/root.key" -out "$root_dir/root.crt" -days 3650 \
    -subj '/CN=CMTC organizational root' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:2' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'
  chmod 0600 "$root_dir/root.key" "$root_dir/root.crt"
fi
printf 'basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > "$pki/cluster.ext"
openssl x509 -req -in "$pki/cluster.csr" -CA "$root_dir/root.crt" -CAkey "$root_dir/root.key" -CAcreateserial \
  -out "$pki/cluster.crt" -days 825 -extfile "$pki/cluster.ext"
cat "$pki/cluster.crt" "$root_dir/root.crt" > "$pki/cluster.chain.crt"
openssl verify -CAfile "$root_dir/root.crt" "$pki/cluster.crt"
python3 - "$pki/cluster.chain.crt" "$snap/cluster-ca-patch.json" <<'PY'
import base64,json,pathlib,sys
cert=base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode()
# UID and resourceVersion are inserted by the next kubectl read.
pathlib.Path(sys.argv[2]).write_text(json.dumps({"certificateB64": cert}))
PY
kubectl --context "$context" -n cert-manager get secret cluster-intermediate -o json > "$pki/secret-meta.json"
python3 - "$pki/secret-meta.json" "$snap/cluster-ca-patch.json" "$snap/patch.json" <<'PY'
import json,pathlib,sys
from scripts.lab.pki.ownership import certificate_patch, classify
secret=json.loads(pathlib.Path(sys.argv[1]).read_text())
meta=classify(secret, secret["metadata"]["labels"]["security.cmtc.io/pki-cluster"], "cluster-ca")
cert=json.loads(pathlib.Path(sys.argv[2]).read_text())["certificateB64"]
pathlib.Path(sys.argv[3]).write_text(json.dumps(certificate_patch(meta["uid"], meta["resourceVersion"], cert)))
PY
kubectl --context "$context" -n cert-manager patch secret cluster-intermediate --type=json --patch-file "$snap/patch.json"
rm -rf "$pki"
cp "$root_dir/root.crt" "$snap/root.crt"
kubectl --context "$context" apply -f - <<YAML
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: ${cluster}-cluster-ca
  labels: {security.cmtc.io/pki-owner: cmtc-lab-pki, security.cmtc.io/pki-cluster: $cluster, security.cmtc.io/pki-role: cluster-ca}
spec:
  ca: {secretName: cluster-intermediate}
YAML
helm --kube-context "$context" -n kube-system get manifest cilium > "$snap/cilium-manifest.after.yaml"
after=$(sha256sum "$snap/cilium-manifest.after.yaml" | awk '{print $1}')
python3 - "$before" "$after" <<'PY'
import sys
from scripts.lab.pki.ownership import cilium_unchanged
cilium_unchanged(sys.argv[1], sys.argv[2])
PY
echo "Cluster CA is signed. SPIRE objects are applied. Do not enable the issuer-profile producer."
echo "After SPIRE writes cilium-spire/spire-bundle, export only its public bundle and verify root -> cluster CA -> SPIRE CA."
```

The secret JSON is written under the mode-0700 work directory and removed before the script exits. It is not copied to the evidence snapshot. The patch file contains the public certificate only.

One correction belongs in the script: `classify` is called with the cluster taken from the secret label. A foreign label already makes `classify` fail. Pass `"$cluster"` from the shell instead:

```bash
python3 - "$cluster" "$pki/secret-meta.json" "$snap/cluster-ca-patch.json" "$snap/patch.json" <<'PY'
import json,pathlib,sys
from scripts.lab.pki.ownership import certificate_patch, classify
cluster=sys.argv[1]
secret=json.loads(pathlib.Path(sys.argv[2]).read_text())
meta=classify(secret, cluster, "cluster-ca")
cert=json.loads(pathlib.Path(sys.argv[3]).read_text())["certificateB64"]
pathlib.Path(sys.argv[4]).write_text(json.dumps(certificate_patch(meta["uid"], meta["resourceVersion"], cert)))
PY
```

Use that four-argument form when applying the script. The three-argument form in the first block is wrong because it trusts the secret's own cluster label.

## `scripts/lab/pki/test_pki.py`

```python
#!/usr/bin/env python3
import json, os, stat, subprocess, tempfile, unittest
from pathlib import Path
from scripts.lab.pki.ownership import Refusal, assert_public, certificate_patch, cilium_unchanged, classify, delete_options, require_target, root_state
from scripts.lab.pki.render_spire import AGENT, BUSYBOX, LEGACY_INIT_SHA, SERVER, assert_safe, manifest

ROOT = Path(__file__).resolve().parents[3]

class Topology(unittest.TestCase):
    def test_each_cluster_is_standalone_and_pinned(self):
        for cluster, domain in (("cmtc-a", "cmtc-a.mesh.example"), ("cmtc-b", "cmtc-b.mesh.example")):
            text = manifest(cluster)
            assert_safe(text)
            self.assertIn(domain, text)
            self.assertIn(cluster + "-cluster-ca", text)
            self.assertNotIn("cmtc-b.mesh.example" if cluster == "cmtc-a" else "cmtc-a.mesh.example", text)
            self.assertIn(SERVER, text)
            self.assertIn(AGENT, text)
            self.assertIn(BUSYBOX, text)

    def test_socket_uid_and_registration_boundary(self):
        text = manifest("cmtc-a")
        self.assertEqual(text.count("runAsUser: 1000"), 2)
        self.assertNotIn("hostPath", text)
        self.assertEqual(text.count("entry create"), 1)
        self.assertIn("-node", text)
        self.assertNotIn("cilium-agent", text)
        self.assertNotIn("entry create", text.replace("entry create -socketPath \"$sock\" -spiffeID \"$id\" $sel -node", "", 1))

    def test_legacy_initializer_is_rejected_by_the_script(self):
        script = (ROOT / "scripts/lab/pki/bootstrap.sh").read_text()
        self.assertIn(LEGACY_INIT_SHA, script)
        self.assertIn("LAB_INIT_MODE, value: cluster-ca", script)
        self.assertNotIn("helm upgrade cilium", script)
        self.assertNotIn("encryption.enabled=true", script)
        self.assertNotIn("issuer-profile-producer", script)

class Targets(unittest.TestCase):
    def test_wrong_context_and_forbidden_cluster(self):
        with self.assertRaises(Refusal):
            require_target("cmtc-a", "kind-cmtc-b")
        with self.assertRaises(Refusal):
            require_target("cmtc-mtls", "kind-cmtc-mtls")
        require_target("cmtc-b", "kind-cmtc-b")

class Ownership(unittest.TestCase):
    def test_foreign_object_conflicts_and_owned_object_reuses(self):
        foreign = {"metadata": {"uid": "uid-1", "resourceVersion": "3"}}
        with self.assertRaises(Refusal):
            classify(foreign, "cmtc-a", "cluster-ca")
        owned = {"metadata": {"uid": "uid-1", "resourceVersion": "7", "labels": {
            "security.cmtc.io/pki-owner": "cmtc-lab-pki",
            "security.cmtc.io/pki-cluster": "cmtc-a",
            "security.cmtc.io/pki-role": "cluster-ca"}}}
        self.assertEqual(classify(owned, "cmtc-a", "cluster-ca")["uid"], "uid-1")
        with self.assertRaises(Refusal):
            classify(owned, "cmtc-b", "cluster-ca")

    def test_cleanup_and_patch_are_uid_conditional_and_public(self):
        body = delete_options("uid-1", "9")
        self.assertEqual(body["preconditions"], {"uid": "uid-1", "resourceVersion": "9"})
        patch = certificate_patch("uid-1", "9", "Y2VydA==")
        self.assertEqual(patch[0]["value"], "uid-1")
        self.assertEqual(patch[2]["path"], "/data/tls.crt")
        with self.assertRaises(Refusal):
            certificate_patch("uid-1", "9", "-----BEGIN PRIVATE KEY-----")
        with self.assertRaises(Refusal):
            assert_public("PRIVATE KEY")
        assert_public('{"clusterIssuerCSR":"-----BEGIN CERTIFICATE REQUEST-----"}')

    def test_cilium_snapshot_must_match(self):
        cilium_unchanged("abc", "abc")
        with self.assertRaises(Refusal):
            cilium_unchanged("abc", "def")

class Root(unittest.TestCase):
    def test_directory_mode_and_incomplete_root(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            os.chmod(path, 0o700)
            self.assertEqual(root_state(path), "create")
            (path / "root.crt").write_text("public")
            with self.assertRaises(Refusal):
                root_state(path)
            (path / "root.key").write_text("key")
            os.chmod(path / "root.key", 0o600)
            self.assertEqual(root_state(path), "reuse")
            os.chmod(path, 0o755)
            with self.assertRaises(Refusal):
                root_state(path)

class Lineage(unittest.TestCase):
    def test_openssl_pathlen_and_uri_rules(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            subprocess.run(["openssl","ecparam","-name","prime256v1","-genkey","-noout","-out",path/"root.key"], check=True)
            subprocess.run(["openssl","req","-x509","-new","-key",path/"root.key","-out",path/"root.crt","-days","2","-subj","/CN=root","-addext","basicConstraints=critical,CA:TRUE,pathlen:2","-addext","keyUsage=critical,keyCertSign,cRLSign"], check=True)
            subprocess.run(["openssl","ecparam","-name","prime256v1","-genkey","-noout","-out",path/"ca.key"], check=True)
            subprocess.run(["openssl","req","-new","-key",path/"ca.key","-out",path/"ca.csr","-subj","/CN=cmtc-a cluster CA"], check=True)
            (path/"ca.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n")
            subprocess.run(["openssl","x509","-req","-in",path/"ca.csr","-CA",path/"root.crt","-CAkey",path/"root.key","-CAcreateserial","-out",path/"ca.crt","-days","2","-extfile",path/"ca.ext"], check=True)
            subprocess.run(["openssl","verify","-CAfile",path/"root.crt",path/"ca.crt"], check=True)
            text = (path/"ca.crt").read_text()
            assert_public(text)
            self.assertNotIn("PRIVATE KEY", text)

if __name__ == "__main__":
    unittest.main()
```

The second `assertNotIn("entry create")` after replacement is a weak count. The first assertions already require one `entry create` and no `cilium-agent`. Keep the first three assertions. Delete the `replace` assertion when applying the test, or the test fails because the shell script still contains the words `entry create` inside the removed portion only once. After one removal, a second `entry create` must be absent. That assertion is valid. Leave it.

## Commands for the primary

Apply the Go change and the new `scripts/lab/pki` files. Do not run `scripts/lab/mtls/bootstrap.sh`.

```sh
cd /Users/olasumbo/gitRepos/clustermest-trust-controller
go test ./cmd/lab-identity-init ./internal/trustprofile -count=1
python3 -m unittest scripts/lab/pki/test_pki.py
```

Build and import a new image only after those tests pass. Refuse binary SHA `a6723c7813b6f52e49184503400742867da0be40b7d70d46ce41681f5b83d5ae`. Use host Podman, `linux/arm64`, and archive import into the existing kind nodes. Verify the CRI config ID and the running `/lab-identity-init` hash before either Job.

```sh
install -d -m 0700 "$HOME/.cmtc/pki-root"
CMTC_PKI_ROOT_DIR=$HOME/.cmtc/pki-root \
CMTC_PKI_INIT_IMAGE=<new-image> \
CMTC_PKI_INIT_BINARY_SHA256=<new-sha> \
  scripts/lab/pki/bootstrap.sh cmtc-a kind-cmtc-a
CMTC_PKI_ROOT_DIR=$HOME/.cmtc/pki-root \
CMTC_PKI_INIT_IMAGE=<new-image> \
CMTC_PKI_INIT_BINARY_SHA256=<new-sha> \
  scripts/lab/pki/bootstrap.sh cmtc-b kind-cmtc-b
```

The second cluster reuses the same root files. It does not generate a second root. After each SPIRE server is Ready, read only the public bundle and verify three certificates: organizational root path length at least 2, cluster CA path length at least 1, SPIRE CA path length 0, and one URI SAN equal to `spiffe://<cluster>.mesh.example`. Keep the root key in the 0700 directory. Do not copy it into artifacts or either cluster.

These checks do not establish workload mTLS. The producer stays disabled for this chain until the one-parent lineage change is qualified. Ztunnel, encryption, and the ClusterMesh guard stay closed.
