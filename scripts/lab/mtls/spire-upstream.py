#!/usr/bin/env python3
"""Helm post-renderer for the isolated CMTC-101 cert-manager trust fixture."""
import sys
import yaml

objects = list(yaml.safe_load_all(sys.stdin))
found = False
for obj in objects:
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
objects += [
    {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'spire-upstreamauthority', 'namespace': 'cilium-spire'},
     'rules': [{'apiGroups': ['cert-manager.io'], 'resources': ['certificaterequests'], 'verbs': ['create', 'get', 'list', 'watch', 'delete']}]},
    {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name': 'spire-upstreamauthority', 'namespace': 'cilium-spire'},
     'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'spire-upstreamauthority'},
     'subjects': [{'kind': 'ServiceAccount', 'name': 'spire-server', 'namespace': 'cilium-spire'}]}
]
yaml.safe_dump_all([o for o in objects if o], sys.stdout, sort_keys=False)
