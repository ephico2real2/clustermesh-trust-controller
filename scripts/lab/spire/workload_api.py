#!/usr/bin/env python3
"""Opt-in public-only plan; no API requests, Secret reads, or runtime mutations.

The caller supplies fresh, independently authenticated Kubernetes snapshots and
public kubelet certificates collected through the already pinned kind node.
"""
import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import uuid
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location('spire_renderer', ROOT/'scripts/lab/spire/render_spire.py')
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)
OWNER = 'cmtc-workload-api'
BASE = '/run/cmtc-spire'
KUBELET_CERT_DIR = '/run/cmtc-kubelet'
ADMIN_SOCKET = '/run/spire/sockets/admin/admin.sock'
WORKLOAD_SOCKET = r.AGENT_SOCKET

class Refusal(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise Refusal(message)

def uid(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value, 'canonical UID required')
    return value

def dns(value):
    require(isinstance(value, str) and len(value)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')), 'DNS name required')
    return value

def public_kubelet_certificate(record, now):
    """Exact approved kind serving CA, with a verified current DNS-only leaf.

    Both public hashes are independently collected via the pinned kind node.
    Runtime TLS trusts only that per-node CA and still verifies the node DNS.
    A valid replacement leaf from the same CA/name is ordinary TLS renewal;
    replacing the CA requires an explicit new immutable approval/rollout.
    """
    pem = record['kubeletCertificatePEM']
    require(isinstance(pem, str) and len(pem)<32768 and pem.count('-----BEGIN CERTIFICATE-----')==2 and 'PRIVATE' not in pem, 'exact public leaf and CA certificates required')
    certs=x509.load_pem_x509_certificates(pem.encode())
    require(len(certs)==2 and ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)==pem, 'canonical ordered public chain required')
    leaf,ca=certs
    require(leaf.fingerprint(hashes.SHA256()).hex()==record['kubeletCertificateSHA256'], 'independent leaf pin mismatch')
    require(ca.fingerprint(hashes.SHA256()).hex()==record['kubeletCASHA256'], 'independent CA pin mismatch')
    require(ca.subject==ca.issuer and leaf.issuer==ca.subject, 'exact per-node CA lineage required')
    ca.verify_directly_issued_by(ca);leaf.verify_directly_issued_by(ca)
    require(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca and ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign, 'serving issuer is not an authorized CA')
    require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca and leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature,'serving leaf role mismatch')
    require(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)==[x509.DNSName(record['name'])], 'exact node DNS SAN required')
    require(ExtendedKeyUsageOID.SERVER_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,'serving leaf lacks serverAuth')
    for cert in certs:
        require(cert.not_valid_before_utc<=now and cert.not_valid_after_utc>now+timedelta(minutes=15), 'serving chain not currently usable')
    require(ca.not_valid_before_utc<=leaf.not_valid_before_utc and leaf.not_valid_after_utc<=ca.not_valid_after_utc, 'leaf validity outside approved CA')
    aki=leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    ski=ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    require(aki==ski,'leaf authority key mismatch')
    # Only the CA is trusted at runtime; the observed leaf stays in public
    # evidence and is not treated as a second trust anchor.
    return ca.public_bytes(serialization.Encoding.PEM).decode()

def selectors(pod, namespace_uid, node):
    require(pod['kind']=='Pod' and pod['apiVersion']=='v1', 'actual Pod required')
    m, s = pod['metadata'], pod['spec']
    uid(m['uid']); uid(namespace_uid)
    require(not m.get('deletionTimestamp'), 'deleting Pod refused')
    require(s['nodeName']==node['name'], 'Pod scheduled node mismatch')
    ns, sa = dns(m['namespace']), dns(s.get('serviceAccountName','default'))
    require(pod.get('status',{}).get('phase')=='Running' and pod.get('status',{}).get('containerStatuses') and all(x.get('ready') and x.get('state',{}).get('running') for x in pod['status']['containerStatuses']), 'running ready Pod required')
    return [f'k8s:ns:{ns}',f'k8s:sa:{sa}',f'k8s:pod-uid:{m["uid"]}',f'k8s:node-name:{node["name"]}']

def registration(cluster, domain, cluster_uid, item, node, role):
    pod = item['pod']
    sels = selectors(pod, item['namespaceUID'], node)
    ns, sa = pod['metadata']['namespace'], pod['spec'].get('serviceAccountName','default')
    # Node alias is the existing PSAT-attested alias, not an unverified string.
    parent = r.agent_spiffe_id(domain)
    path = '/ztunnel-proxy' if role=='delegate' else f'/ns/{ns}/sa/{sa}'
    spiffe_id = 'spiffe://'+domain+path
    entry_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'{OWNER}:{cluster_uid}:{node["uid"]}:{pod["metadata"]["uid"]}:{role}'))
    return {'entryID':entry_id,'spiffeID':spiffe_id,'parentID':parent,'selectors':sels,
            'clusterUID':cluster_uid,'nodeUID':node['uid'],'namespaceUID':item['namespaceUID'],'podUID':pod['metadata']['uid'],
            'namespace':ns,'podName':pod['metadata']['name'],'role':role,
            'createArguments':['entry','create','-socketPath',r.SERVER_SOCKET,'-entryID',entry_id,'-parentID',parent,'-spiffeID',spiffe_id,'-x509SVIDTTL','120']+sum((['-selector',x] for x in sels),[]),
            'showArguments':['entry','show','-socketPath',r.SERVER_SOCKET,'-entryID',entry_id,'-output','json']}

# Root init only prepares two exact directories inside its separately mounted
# sockets-only parent. It never chowns an existing object or touches SPIRE data.
PREPARE = r'''set -eu
umask 077
if [ "$(stat -c '%u:%g:%a' /cmtc-node-sockets)" != '0:0:755' ]; then exit 30; fi
for name in agent admin; do
 p=/cmtc-node-sockets/$name
 if [ -e "$p" ] || [ -L "$p" ]; then
  if [ ! -d "$p" ] || [ -L "$p" ]; then exit 31; fi
  if [ "$(stat -c '%u:%g:%a' "$p")" != '1000:1000:700' ]; then exit 32; fi
 else
  mkdir -m 700 "$p"
  chown 1000:1000 "$p"
 fi
done
'''

def make_plan(snapshot, now=None):
    now = now or datetime.now(timezone.utc)
    cluster = snapshot['cluster']; domain = r.require_cluster(cluster, snapshot['domain']); cuid=uid(snapshot['clusterUID'])
    require(snapshot.get('schema')=='cmtc-workload-api-plan-input/v1', 'wrong input schema')
    nodes=snapshot['nodes']; require(1<=len(nodes)<=8, 'bounded explicit nodes required')
    require(set(x['name'] for x in nodes)==set(snapshot['expectedNodes']), 'exact administrator node set required')
    require(len({uid(x['uid']) for x in nodes})==len(nodes), 'duplicate node UID')
    require(len({x['name'] for x in nodes})==len(nodes) and len({x['ip'] for x in nodes})==len(nodes),'duplicate node name/address')
    for node in nodes: dns(node['name']); ipaddress.ip_address(node['ip'])
    anchors={x['name']+'.pem':public_kubelet_certificate(x, now) for x in nodes}
    ds=snapshot['agentDaemonSet']; cm=snapshot['agentConfigMap']; m=ds['metadata']
    require(ds['kind']=='DaemonSet' and m['namespace']==r.NAMESPACE and m['name']=='spire-agent', 'wrong DaemonSet')
    uid(m['uid']); require(m.get('resourceVersion') and not m.get('deletionTimestamp'),'live DaemonSet required')
    require(m.get('labels',{}).get('security.cmtc.io/pki-owner')==r.OWNER and m['labels'].get('security.cmtc.io/pki-cluster')==cluster, 'foreign DaemonSet')
    require(cm['metadata']['namespace']==r.NAMESPACE and cm['metadata']['name']=='spire-agent' and cm['metadata'].get('uid') and cm['data']=={'agent.conf':r.agent_config(cluster,domain)}, 'exact baseline ConfigMap required')
    template=copy.deepcopy(ds['spec']['template']); ps=template['spec']
    require(ps['serviceAccountName']==r.AGENT_ACCOUNT and ps.get('hostPID') is True and ps.get('hostNetwork') is True,'existing node agent boundary required')
    agent=next(x for x in ps['containers'] if x['name']=='spire-agent')
    require(len(ps['containers'])==1 and agent['image']==r.AGENT_IMAGE,'exact current agent image required')
    approved_agent=r.approved_server_image(snapshot['approvedAgentImage'])
    require(approved_agent != r.AGENT_IMAGE,'qualified current-fork agent is required for kernel-only container locator')
    require(snapshot['approvedAgentSource']=='28f6b8d84ade21c6accb32ba9689a3bdf64877ec','exact independently qualified agent source required')
    agent['image']=approved_agent
    require(not any(x.get('name') in ('cmtc-node-sockets','cmtc-kubelet-pins') for x in ps['volumes']),'fixture already installed or foreign collision')
    require(next(x for x in ps['volumes'] if x['name']=='spire-agent-socket')=={'name':'spire-agent-socket','emptyDir':{}},'baseline isolated sockets required')
    entries=[]
    for role,key in [('delegate','delegates'),('workload','workloads')]:
        require(0<=len(snapshot[key])<=32,'bounded explicit '+key+' required')
        for item in snapshot[key]:
            node=next((n for n in nodes if n['name']==item['pod']['spec']['nodeName']),None)
            require(node is not None,'unapproved node')
            if role=='delegate':
                require(item['pod']['metadata']['namespace']==snapshot['delegateNamespace'] and item['pod']['spec']['serviceAccountName']==snapshot['delegateServiceAccount'],'independent delegate namespace/SA required')
            else:
                require(not item['pod']['spec'].get('hostNetwork') and not item['pod']['spec'].get('hostPID') and item['pod']['metadata']['namespace'] not in ('kube-system','cilium-spire','cmtc-system'), 'workload must be an isolated ordinary Pod')
            entries.append(registration(cluster,domain,cuid,item,node,role))
    require(len({x['podUID'] for x in entries})==len(entries),'duplicate Pod or mixed delegate/workload role')
    # No cilium-agent implicit delegate and no operator adminIDs in this fixture.
    conf=r.agent_config(cluster,domain)
    conf=conf.replace(f'  socket_path = "{r.AGENT_SOCKET}"',f'  socket_path = "{WORKLOAD_SOCKET}"\n  admin_socket_path = "{ADMIN_SOCKET}"\n  authorized_delegates = ["spiffe://{domain}/ztunnel-proxy"]')
    conf=conf.replace('      skip_kubelet_verification = true',f'      skip_kubelet_verification = false\n      kubelet_ca_path = "{KUBELET_CERT_DIR}/serving.pem"\n      node_name_env = "CMTC_NODE_NAME"\n      use_new_container_locator = true\n      max_poll_attempts = 4\n      poll_retry_interval = "250ms"')
    require('skip_kubelet_verification = true' not in conf and conf.count('authorized_delegates')==1,'configuration transform refused')
    digest=hashlib.sha256(json.dumps({'config':conf,'anchors':anchors},sort_keys=True).encode()).hexdigest()[:16]
    cname='cmtc-workload-api-'+digest; aname='cmtc-kubelet-pins-'+digest
    def configmap(name,data):
        return {'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':name,'namespace':r.NAMESPACE,'labels':{'security.cmtc.io/workload-api-owner':OWNER,'security.cmtc.io/pki-cluster':cluster}},'immutable':True,'data':data}
    vols=ps['volumes']; vols[:]=[x for x in vols if x['name']!='spire-agent-socket']
    next(x for x in vols if x['name']=='spire-config')['configMap']['name']=cname
    host=BASE+'/'+cluster
    vols.extend([{'name':'cmtc-node-sockets','hostPath':{'path':host,'type':'DirectoryOrCreate'}},{'name':'cmtc-kubelet-pins','configMap':{'name':aname}}])
    agent['env']=agent.get('env',[])+[{'name':'CMTC_NODE_NAME','valueFrom':{'fieldRef':{'fieldPath':'spec.nodeName'}}}]
    aliases=copy.deepcopy(ps.get('hostAliases',[]))
    require(not any(n['name'] in a.get('hostnames',[]) for n in nodes for a in aliases),'preexisting node DNS alias refused')
    ps['hostAliases']=aliases+[{'ip':n['ip'],'hostnames':[n['name']]} for n in nodes]
    mounts=agent['volumeMounts'];mounts[:]=[x for x in mounts if x['name']!='spire-agent-socket']
    mounts.extend([{'name':'cmtc-node-sockets','mountPath':'/run/spire/sockets/agent','subPath':'agent'}, {'name':'cmtc-node-sockets','mountPath':'/run/spire/sockets/admin','subPath':'admin'}, {'name':'cmtc-kubelet-pins','mountPath':KUBELET_CERT_DIR+'/serving.pem','subPathExpr':'$(CMTC_NODE_NAME).pem','readOnly':True}])
    ps['initContainers'].append({'name':'prepare-node-sockets','image':r.BUSYBOX_IMAGE,'imagePullPolicy':'IfNotPresent','command':['/bin/sh','-ec',PREPARE], 'securityContext':{'runAsUser':0,'runAsGroup':0,'runAsNonRoot':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL'],'add':['CHOWN']}}, 'volumeMounts':[{'name':'cmtc-node-sockets','mountPath':'/cmtc-node-sockets'}]})
    template.setdefault('metadata',{}).setdefault('annotations',{})['security.cmtc.io/workload-api-config']=digest
    patch=[{'op':'test','path':'/metadata/uid','value':m['uid']},{'op':'test','path':'/metadata/resourceVersion','value':m['resourceVersion']},{'op':'test','path':'/spec/template','value':ds['spec']['template']},{'op':'replace','path':'/spec/template','value':template}]
    return {'schema':'cmtc-workload-api-plan/v1','cluster':cluster,'clusterUID':cuid,'domain':domain,'nodes':[{k:n[k] for k in ('name','uid','ip','kubeletCertificateSHA256','kubeletCASHA256')} for n in nodes], 'configMaps':[configmap(cname,{'agent.conf':conf}),configmap(aname,anchors)],'approvedAgentImage':approved_agent,'approvedAgentSource':snapshot['approvedAgentSource'],'agentDaemonSetUID':m['uid'],'originalTemplate':ds['spec']['template'],'newTemplate':template,'daemonSetPatch':patch,'registrations':entries,'nodeHostSockets':host,'workloadSocket':host+'/agent/agent.sock','adminSocket':host+'/admin/admin.sock','qualified':False,'protectionAvailable':False}

def compare_entry(actual, wanted):
    """Validate an actual `entry show -output json` record; no string matching."""
    def sid(value):return 'spiffe://'+value['trust_domain']+value['path']
    require(actual['id']==wanted['entryID'] and sid(actual['spiffe_id'])==wanted['spiffeID'] and sid(actual['parent_id'])==wanted['parentID'],'entry identity changed')
    got=[x['type']+':'+x['value'] for x in actual['selectors']]
    require(len(got)==len(set(got)) and sorted(got)==sorted(wanted['selectors']),'exact selector mismatch')
    require(not actual.get('admin') and not actual.get('downstream') and not actual.get('dns_names') and not actual.get('federates_with') and not actual.get('store_svid'),'unexpected entry authority')
    require(actual['x509_svid_ttl']==120,'unexpected SVID TTL')

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--snapshot',required=True,type=Path);args=a.parse_args()
    print(json.dumps(make_plan(json.loads(args.snapshot.read_text())),indent=2))


def probe_pod(cluster, node, image, *, namespace='cmtc-workload-api-lab', service_account='node-probe'):
    """One trusted node diagnostic process; no datapath listeners/capabilities.

    Pod creation precedes exact PodUID delegate registration. `hold` never
    fetches a credential; all bounded `fetch` executions occur afterward.
    """
    r.require_cluster(cluster,None);dns(node['name']);uid(node['uid']);image=r.approved_server_image(image)
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':'node-probe-'+node['name'],'namespace':dns(namespace),'labels':{'security.cmtc.io/workload-api-owner':OWNER}},'spec':{'nodeName':node['name'],'serviceAccountName':dns(service_account),'automountServiceAccountToken':False,'restartPolicy':'Never','activeDeadlineSeconds':1800,'hostUsers':True,'hostPID':True,'securityContext':{'runAsUser':1000,'runAsGroup':0,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'probe','image':image,'imagePullPolicy':'Never','command':['/usr/local/bin/spire-workload-check','hold'],'workingDir':'/','securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'env':[{'name':'SPIRE_ENABLED','value':'true'},{'name':'SPIRE_ADMIN_ENDPOINT_SOCKET','value':'unix://'+ADMIN_SOCKET},{'name':'CONTAINER_RUNTIME_SOCK_PATH','value':'/run/containerd/containerd.sock'},{'name':'CLUSTER_DOMAIN','value':r.CLUSTERS[cluster]},{'name':'TRUST_DOMAIN','value':r.CLUSTERS[cluster]},{'name':'CLUSTER_ID','value':cluster},{'name':'NODE_NAME','valueFrom':{'fieldRef':{'fieldPath':'spec.nodeName'}}},{'name':'INSTANCE_IP','valueFrom':{'fieldRef':{'fieldPath':'status.podIP'}}},{'name':'ISTIO_META_DNS_CAPTURE','value':'false'},{'name':'SPIRE_TIMEOUT','value':'10s'}],'volumeMounts':[{'name':'spire-admin','mountPath':'/run/spire/sockets/admin','readOnly':True},{'name':'cri','mountPath':'/run/containerd/containerd.sock','readOnly':True}]}],'volumes':[{'name':'spire-admin','hostPath':{'path':BASE+'/'+cluster+'/admin','type':'Directory'}},{'name':'cri','hostPath':{'path':'/run/containerd/containerd.sock','type':'Socket'}}]}}


def public_kubelet_command(node, *, profile='cmtc-cilium'):
    """Read public leaf only through the independently bound kind node.

    Run only after API NodeUID and actual Colima/kind container identity checks.
    Only CERTIFICATE PEM blocks leave the node, never a combined raw PEM.
    """
    dns(node['name']);uid(node['uid'])
    require(profile=='cmtc-cilium','owned runtime profile only')
    script="""set -eu
command -v awk >/dev/null || exit 31
for p in /var/lib/kubelet/pki/kubelet.crt /var/lib/kubelet/pki/kubelet-server-current.pem; do
 if [ -f "$p" ]; then
  exec awk '/^-----BEGIN CERTIFICATE-----$/{emit=1} emit{print} /^-----END CERTIFICATE-----$/{emit=0}' "$p"
 fi
done
printf 'kubelet public serving certificate unavailable\n' >&2
exit 32
"""
    return ['colima','ssh','--profile',profile,'--','docker','exec',node['name'],'/bin/sh','-ec',script]

if __name__=='__main__':main()
