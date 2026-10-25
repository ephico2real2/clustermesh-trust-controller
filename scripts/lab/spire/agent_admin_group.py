#!/usr/bin/env python3
"""Pure opt-in patch producer for the existing owned SPIRE agent fixture.

No API/runtime calls. This is an agent Admin Delegated Identity socket profile;
it never changes the SPIRE server Admin socket or an application mount.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import re
import uuid

ROOT=Path(__file__).resolve().parents[3]
def _workload_api():
    # Kernel DAC tests need only the shell profile. Load certificate-planning
    # dependencies only when a caller actually renders a Kubernetes patch.
    spec=importlib.util.spec_from_file_location('owned_workload_api',ROOT/'scripts/lab/spire/workload_api.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

# Root init retains the existing narrow CHOWN capability for initial creation.
# An existing old admin directory is only inspected here. Its UID1000 owner
# performs the group transition in the following capability-free init step.
PREPARE=r'''set -eu
umask 077
[ "$(stat -c '%u:%g:%a' /cmtc-node-sockets)" = '0:0:755' ] || exit 30
p=/cmtc-node-sockets/agent
if [ -e "$p" ] || [ -L "$p" ]; then
 [ -d "$p" ] && [ ! -L "$p" ] || exit 31
 [ "$(stat -c '%u:%g:%a' "$p")" = '1000:1000:700' ] || exit 32
else
 mkdir -m 700 "$p"
 chown 1000:1000 "$p"
fi
p=/cmtc-node-sockets/admin
if [ -e "$p" ] || [ -L "$p" ]; then
 [ -d "$p" ] && [ ! -L "$p" ] || exit 33
 case "$(stat -c '%u:%g:%a' "$p")" in
  1000:1000:700|1000:1337:700|1000:1337:710) ;;
  *) exit 34 ;;
 esac
else
 mkdir -m 700 "$p"
 chmod 710 "$p"
 chown 1000:1337 "$p"
fi
'''
MIGRATE=r'''set -eu
p=/cmtc-node-sockets/admin
[ "$(id -u)" = '1000' ] && [ "$(id -g)" = '1337' ] || exit 40
[ -d "$p" ] && [ ! -L "$p" ] || exit 41
case "$(stat -c '%u:%g:%a' "$p")" in
 1000:1000:700)
  chgrp 1337 "$p"
  chmod 710 "$p"
  ;;
 1000:1337:700) chmod 710 "$p" ;;
 1000:1337:710) ;;
 *) exit 42 ;;
esac
[ "$(stat -c '%u:%g:%a' "$p")" = '1000:1337:710' ] || exit 43
'''

def require(value,message):
    if not value:raise ValueError(message)

def render(ds,*,cluster,expected_uid,expected_rv,expected_image):
    w=_workload_api()
    require(cluster in ('cmtc-a','cmtc-b'),'only owned existing ClusterMesh labs')
    require(str(uuid.UUID(expected_uid))==expected_uid and uuid.UUID(expected_uid).int != 0 and expected_rv,'independent UID/RV pins required')
    require(re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',expected_image),'qualified immutable agent image required')
    m=ds['metadata'];require(ds['apiVersion']=='apps/v1' and ds['kind']=='DaemonSet' and m['name']=='spire-agent' and m['namespace']=='cilium-spire','wrong target')
    require(m['uid']==expected_uid and m['resourceVersion']==expected_rv and not m.get('deletionTimestamp'),'agent incarnation changed')
    require(m['labels'].get('security.cmtc.io/pki-owner')==w.r.OWNER and m['labels'].get('security.cmtc.io/pki-cluster')==cluster,'foreign daemonset')
    template=copy.deepcopy(ds['spec']['template']);p=template['spec']
    require(re.fullmatch(r'[0-9a-f]{16}',template.get('metadata',{}).get('annotations',{}).get('security.cmtc.io/workload-api-config','')),'verified workload API fixture required')
    require(p.get('hostPID') is True and p.get('hostNetwork') is True and p['serviceAccountName']=='spire-agent','node attestation boundary changed')
    require(p['securityContext']==w.r.POD_SECURITY,'unexpected pod credential profile')
    require(len(p['containers'])==1 and p['containers'][0]['name']=='spire-agent','unexpected agent container set')
    agent=p['containers'][0];require(agent['image']==expected_image,'agent image differs')
    security=agent.get('securityContext',{})
    require(not any(k in security for k in ('runAsUser','runAsGroup','privileged','capabilities')),'unreviewed agent credential overrides')
    volumes={v['name']:v for v in p['volumes']}
    require(volumes.get('cmtc-node-sockets')=={'name':'cmtc-node-sockets','hostPath':{'path':w.BASE+'/'+cluster,'type':'DirectoryOrCreate'}},'foreign socket volume')
    mounts={m.get('subPath'):m for m in agent['volumeMounts'] if m['name']=='cmtc-node-sockets'}
    require(mounts.get('admin')=={'name':'cmtc-node-sockets','mountPath':'/run/spire/sockets/admin','subPath':'admin'},'unexpected Admin mount')
    require(mounts.get('agent')=={'name':'cmtc-node-sockets','mountPath':'/run/spire/sockets/agent','subPath':'agent'},'unexpected Workload mount')
    init=next((x for x in p['initContainers'] if x['name']=='prepare-node-sockets'),None)
    require(init is not None and init['command']==['/bin/sh','-ec',w.PREPARE],'unreviewed socket initializer')
    require(init['securityContext']=={'runAsUser':0,'runAsGroup':0,'runAsNonRoot':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL'],'add':['CHOWN']}},'initializer privilege changed')
    require(not any(x['name']=='prepare-admin-proxy-group' for x in p['initContainers']),'group profile already present')
    init['command']=['/bin/sh','-ec',PREPARE]
    # No root/DAC capability is needed: UID1000 owns the directory and GID1337
    # is its configured primary group, so chgrp is an ordinary owner operation.
    p['initContainers'].append({'name':'prepare-admin-proxy-group','image':w.r.BUSYBOX_IMAGE,'imagePullPolicy':'IfNotPresent','workingDir':'/','command':['/bin/sh','-ec',MIGRATE],'securityContext':{'runAsUser':1000,'runAsGroup':1337,'runAsNonRoot':True,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'cmtc-node-sockets','mountPath':'/cmtc-node-sockets'}]})
    agent.setdefault('securityContext',{})['runAsGroup']=1337
    digest=hashlib.sha256((PREPARE+MIGRATE).encode()).hexdigest()
    template.setdefault('metadata',{}).setdefault('annotations',{})['security.cmtc.io/agent-admin-proxy-group']=digest
    patch=[{'op':'test','path':'/metadata/uid','value':expected_uid},{'op':'test','path':'/metadata/resourceVersion','value':expected_rv},{'op':'test','path':'/spec/template','value':ds['spec']['template']},{'op':'replace','path':'/spec/template','value':template}]
    return {'schema':'cmtc-agent-admin-group/v1','cluster':cluster,'agentDaemonSetUID':expected_uid,'sourceImage':expected_image,'patch':patch,'newTemplate':template,'originalTemplate':ds['spec']['template'],'qualified':False,'protectionAvailable':False}
