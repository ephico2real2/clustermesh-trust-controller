#!/usr/bin/env bash
# Prove that cert-manager signs a cluster's CA requests only as the approver-policy policies allow (MESH_PKI.md,
# Approval). ztunnel trusts every CA that <cluster>-spire-intermediate signs, so only the SPIRE server may get one, and
# only for its own trust domain. Each case submits a CertificateRequest as a named requester and expects one result:
#   Denied       a policy applies and refuses the request;
#   Unprocessed  no policy applies to this requester, issuer and namespace: the request stays pending, unsigned;
#   Issued       approved and signed (only with --issue).
# The cases that expect Denied or Unprocessed never produce a certificate, so they are safe on a running lab. --issue
# adds the one case that signs a SPIRE-shaped CA; use it only on a disposable cluster (CI), where it also creates the
# SPIRE requester (namespace, ServiceAccount, Role) when it is absent, and removes what it created.
#
# It refuses to start unless cert-manager's own approver is off: with it on, every request below would be signed.
# Keys are made in a private temporary directory, never printed, and removed on exit with the requests.
#
# Usage: approval-check.sh [--issue] [--context CONTEXT] [--root-issuer NAME] [--trust-domain DOMAIN] CLUSTER
set -euo pipefail
issue=false context="" root_issuer=cmtc-mesh-root trust_domain=""
while [ $# -gt 0 ]; do
  case "$1" in
    --issue) issue=true; shift;;
    --context) context=$2; shift 2;;
    --root-issuer) root_issuer=$2; shift 2;;
    --trust-domain) trust_domain=$2; shift 2;;
    -h|--help) sed -n '2,15p' "$0"; exit 0;;
    -*) echo "unknown option $1" >&2; exit 2;;
    *) break;;
  esac
done
[ $# -eq 1 ] || { echo "usage: approval-check.sh [--issue] [--context CONTEXT] CLUSTER" >&2; exit 2; }
cluster=$1
context=${context:-kind-$cluster}
trust_domain=${trust_domain:-$cluster.mesh.example}
spire_ns=cilium-spire spire_sa=spire-server
spire=system:serviceaccount:$spire_ns:$spire_sa
cert_manager=system:serviceaccount:cert-manager:cert-manager
k() { kubectl --context "$context" "$@"; }

args=$(k -n cert-manager get deployment cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}')
case $args in
  *--controllers=-certificaterequests-approver*) ;;
  *) echo "refusing: cert-manager's own approver is on (install it with disableAutoApproval=true)" >&2; exit 1;;
esac
k wait certificaterequestpolicies --all --for=condition=Ready --timeout=2m >/dev/null

umask 077
dir=$(mktemp -d)
requests=() made_role=false made_namespace=false
cleanup() {
  for request in ${requests[@]+"${requests[@]}"}; do k delete certificaterequest -n "${request%%/*}" "${request#*/}" --ignore-not-found >/dev/null; done
  if $made_role; then k -n "$spire_ns" delete rolebinding,role approval-check --ignore-not-found >/dev/null; fi
  if $made_namespace; then k delete namespace "$spire_ns" --ignore-not-found --wait=false >/dev/null; fi
  rm -rf "${dir:?}"
}
trap cleanup EXIT

if $issue && [ "$(k auth can-i create certificaterequests.cert-manager.io -n "$spire_ns" --as="$spire")" != yes ]; then
  if ! k get namespace "$spire_ns" >/dev/null 2>&1; then
    k create namespace "$spire_ns" >/dev/null; made_namespace=true
  fi
  k -n "$spire_ns" get serviceaccount "$spire_sa" >/dev/null 2>&1 || k -n "$spire_ns" create serviceaccount "$spire_sa" >/dev/null
  made_role=true
  k -n "$spire_ns" create role approval-check --verb=create,get,delete --resource=certificaterequests.cert-manager.io >/dev/null
  k -n "$spire_ns" create rolebinding approval-check --role=approval-check --serviceaccount="$spire_ns:$spire_sa" >/dev/null
fi

# request NAME NAMESPACE REQUESTER ISSUER SUBJECT URI: submit a CA request with SPIRE's shape (pkg/server/credtemplate:
# subject from ca_subject plus a serialNumber, one URI SAN, cert sign and CRL sign, the plugin's 24h duration).
request() {
  local name=$1 namespace=$2 requester=$3 issuer=$4 subject=$5 uri=$6
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$dir/$name.key" -subj "$subject" \
    -addext "subjectAltName=URI:$uri" -out "$dir/$name.csr" 2>/dev/null
  k create --as="$requester" -f - >/dev/null <<EOF
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata: {name: approval-check-$name, namespace: $namespace}
spec:
  issuerRef: {name: $issuer, kind: ClusterIssuer, group: cert-manager.io}
  request: $(base64 < "$dir/$name.csr" | tr -d '\n')
  isCA: true
  usages: [cert sign, crl sign]
  duration: 24h
EOF
  requests+=("$namespace/approval-check-$name")
}

# result NAMESPACE NAME: Issued, Denied or Unprocessed, or empty when nothing is decided within 60 seconds.
result() {
  local conditions
  for _ in $(seq 30); do
    conditions=$(k -n "$1" get certificaterequest "$2" -o jsonpath='{range .status.conditions[*]}{.type}={.status} {end}')
    case $conditions in
      *Denied=True*) echo Denied; return;;
      *Ready=True*) echo Issued; return;;
    esac
    if [ -n "$(k -n "$1" get events -o name --field-selector "involvedObject.name=$2,reason=Unprocessed")" ]; then
      echo Unprocessed; return
    fi
    sleep 2
  done
}

spire_subject="/C=US/O=SPIRE/CN=$cluster SPIRE CA/serialNumber=$RANDOM$RANDOM"
expected=()
if $issue; then
  request spire-ca "$spire_ns" "$spire" "$cluster-spire-intermediate" "$spire_subject" "spiffe://$trust_domain"
  expected+=("spire-ca Issued the SPIRE server gets a CA for its own trust domain")
fi
request other-domain "$spire_ns" "$spire" "$cluster-spire-intermediate" "$spire_subject" "spiffe://other.$trust_domain"
expected+=("other-domain Denied the SPIRE server asks for a CA of another trust domain")
request via-cert-manager "$spire_ns" "$cert_manager" "$cluster-spire-intermediate" "$spire_subject" "spiffe://$trust_domain"
expected+=("via-cert-manager Unprocessed a Certificate object in the SPIRE namespace asks for a SPIRE CA")
request other-namespace default "$cert_manager" "$cluster-spire-intermediate" "$spire_subject" "spiffe://$trust_domain"
expected+=("other-namespace Unprocessed a Certificate object in another namespace asks for a SPIRE CA")
request from-root "$spire_ns" "$spire" "$root_issuer" "/CN=$cluster SPIRE intermediate CA" "spiffe://$trust_domain"
expected+=("from-root Unprocessed the SPIRE server asks the mesh root for an intermediate")

failed=0
for line in "${expected[@]}"; do
  read -r name want why <<<"$line"
  namespace=$spire_ns; [ "$name" = other-namespace ] && namespace=default
  got=$(result "$namespace" "approval-check-$name")
  if [ "$got" = "$want" ]; then
    echo "PASS $cluster $name: $want ($why)"
  else
    echo "FAIL $cluster $name: want $want, got ${got:-no decision in 60s} ($why)"; failed=1
  fi
done
exit $failed
