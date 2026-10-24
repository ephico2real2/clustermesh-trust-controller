#!/usr/bin/env python3
"""Helm post-renderer for the isolated CMTC-101 cert-manager trust fixture."""
import sys
import yaml

objects = list(yaml.safe_load_all(sys.stdin))
found = False
server_found = False
for obj in objects:
    if obj and obj['kind'] == 'StatefulSet' and obj['metadata']['name'] == 'spire-server':
        pod = obj['spec']['template']['spec']
        # SPIRE 1.15.5 runs as UID 1000. Its admin API is pod-local; a
        # root-owned hostPath is neither writable by that user nor necessary.
        # Use the same UID for the registration sidecar's /proc binary access.
        pod['securityContext'] = {'runAsUser': 1000, 'runAsGroup': 1000, 'fsGroup': 1000}
        sockets = [v for v in pod['volumes'] if v['name'] == 'spire-server-socket']
        assert len(sockets) == 1 and 'hostPath' in sockets[0]
        sockets[0].pop('hostPath')
        sockets[0]['emptyDir'] = {}
        server_found = True
    if obj and obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'spire-server':
        conf = obj['data']['server.conf']
        marker = '    plugins {\n' if '    plugins {\n' in conf else 'plugins {\n'
        assert marker in conf and 'UpstreamAuthority ' not in conf
        conf = conf.replace(marker, marker + '''
      UpstreamAuthority "cert-manager" {
        plugin_data {
          namespace = "cilium-spire"
          issuer_name = "cmtc-spike-intermediate"
          issuer_kind = "ClusterIssuer"
          issuer_group = "cert-manager.io"
        }
      }
''', 1)
        obj['data']['server.conf'] = conf
        found = True
assert found, 'Expected SPIRE server ConfigMap is missing; refusing a self-signed fallback'
assert server_found, 'Expected SPIRE server StatefulSet is missing'
objects += [
    {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'spire-upstreamauthority', 'namespace': 'cilium-spire'},
     'rules': [{'apiGroups': ['cert-manager.io'], 'resources': ['certificaterequests'], 'verbs': ['create', 'get', 'list', 'watch', 'delete']}]},
    {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name': 'spire-upstreamauthority', 'namespace': 'cilium-spire'},
     'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'spire-upstreamauthority'},
     'subjects': [{'kind': 'ServiceAccount', 'name': 'spire-server', 'namespace': 'cilium-spire'}]}
]
yaml.safe_dump_all([o for o in objects if o], sys.stdout, sort_keys=False)
