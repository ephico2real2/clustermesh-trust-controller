#!/usr/bin/env python3
"""Generate the narrow Observe API schema. No target-only fields are silently promised."""
import json
from pathlib import Path

selector = {
    "type": "object",
    "properties": {
        "matchLabels": {"type": "object", "maxProperties": 128, "additionalProperties": {"type": "string", "maxLength": 63}},
        "matchExpressions": {"type": "array", "maxItems": 64, "items": {"type": "object", "required": ["key", "operator"], "properties": {
            "key": {"type": "string", "maxLength": 253},
            "operator": {"type": "string", "enum": ["In", "NotIn", "Exists", "DoesNotExist"]},
            "values": {"type": "array", "maxItems": 128, "items": {"type": "string", "maxLength": 63}},
        }}},
    },
    "x-kubernetes-validations": [{"rule": "(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)", "message": "empty selectors are not allowed"}],
}
selectors = {"type": "array", "maxItems": 64, "items": selector}
names = {"type": "array", "maxItems": 1024, "items": {"type": "string", "maxLength": 63, "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"}}
condition = {"type": "object", "required": ["type", "status", "reason", "message", "lastTransitionTime"], "properties": {
    "type": {"type": "string"}, "status": {"type": "string", "enum": ["True", "False", "Unknown"]},
    "reason": {"type": "string"}, "message": {"type": "string"},
    "observedGeneration": {"type": "integer", "format": "int64"}, "lastTransitionTime": {"type": "string", "format": "date-time"},
}}
spec = {"type": "object", "required": ["enrollment", "enforcement"], "properties": {
    "enrollment": {"type": "object", "required": ["selectionMode"], "properties": {"selectionMode": {"type": "string", "enum": ["AllEligible", "MatchSelectors"]}}},
    "enforcement": {"type": "object", "required": ["mode"], "properties": {"mode": {"type": "string", "enum": ["Observe"]}}},
    "inclusions": {"type": "object", "properties": {"namespaceSelectors": selectors}},
    "exclusions": {"type": "object", "properties": {"namespaces": names, "namespaceSelectors": selectors}},
    "additionalPlatformNamespaces": names,
}, "x-kubernetes-validations": [
    {"rule": "self.enrollment.selectionMode != 'MatchSelectors' || (has(self.inclusions) && has(self.inclusions.namespaceSelectors) && size(self.inclusions.namespaceSelectors) > 0)", "message": "MatchSelectors requires inclusion selectors"},
    {"rule": "self.enrollment.selectionMode != 'AllEligible' || !has(self.inclusions) || !has(self.inclusions.namespaceSelectors) || size(self.inclusions.namespaceSelectors) == 0", "message": "AllEligible cannot specify inclusion selectors"},
]}
status = {"type": "object", "properties": {
    "observedGeneration": {"type": "integer", "format": "int64"},
    **{name: {"type": "integer", "format": "int32", "minimum": 0} for name in ["selected", "excluded", "platform", "unselected", "labeled"]},
    "conditions": {"type": "array", "x-kubernetes-list-type": "map", "x-kubernetes-list-map-keys": ["type"], "items": condition},
}}
crd = {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": "namespacemtlspolicies.security.cmtc.io"}, "spec": {
    "group": "security.cmtc.io", "scope": "Cluster", "names": {"kind": "NamespaceMTLSPolicy", "plural": "namespacemtlspolicies", "singular": "namespacemtlspolicy", "shortNames": ["nmp"]},
    "versions": [{"name": "v1alpha1", "served": True, "storage": True, "subresources": {"status": {}},
        "schema": {"openAPIV3Schema": {"type": "object", "required": ["spec"], "properties": {"apiVersion": {"type": "string"}, "kind": {"type": "string"}, "metadata": {"type": "object"}, "spec": spec, "status": status}}},
        "additionalPrinterColumns": [{"name": "Selected", "type": "integer", "jsonPath": ".status.selected"}, {"name": "Evaluation", "type": "string", "jsonPath": ".status.conditions[?(@.type=='EvaluationReady')].status"}, {"name": "Enforcement", "type": "string", "jsonPath": ".status.conditions[?(@.type=='EnforcementVerified')].status"}],
    }],
}}
root = Path(__file__).resolve().parents[1]
path = root / "config/crd/security.cmtc.io_namespacemtlspolicies.yaml"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(crd, indent=2) + "\n")

# The chart's copy. Helm keeps the CRD on uninstall, because deleting it deletes every NamespaceMTLSPolicy.
chart_crd = json.loads(json.dumps(crd))
chart_crd["metadata"]["annotations"] = {"helm.sh/resource-policy": "keep"}
chart_path = root / "charts/cmtc/templates/crd-namespacemtlspolicies.yaml"
chart_path.parent.mkdir(parents=True, exist_ok=True)
chart_path.write_text("{{- if .Values.crds.enabled }}\n" + json.dumps(chart_crd, indent=2) + "\n{{- end }}\n")
