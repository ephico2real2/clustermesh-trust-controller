"""Fail-closed validator for the unrendered, audited fence DaemonSet template.

Call BEFORE run ownership labels, selected-node constraints, image or immutable
ConfigMap names are rendered. This is a narrow opt-in lab profile, not admission
control or authentication against a malicious host/root operator.
"""
from copy import deepcopy


class FenceTemplateError(ValueError):
    pass


def expected_fence_template(*, fanout=False):
    container = {
        "name": "fence", "image": "IMAGE_NOT_BUILT", "imagePullPolicy": "Never",
        "command": ["/cmtc-bpf-fence"], "args": ["--config=/config/$(NODE_NAME).json", "--metrics-listen=$(NODE_IP):18084"],
        "ports": [{"name": "metrics", "containerPort": 18084, "protocol": "TCP"}],
        "env": [
            {"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
            {"name": "NODE_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}},
            {"name": "CLUSTER_NAME", "value": "CLUSTER_NAME"},
            {"name": "CMTC_FENCE_CONFIG", "value": "/config/$(NODE_NAME).json"},
            {"name": "CMTC_FENCE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
        ],
        "securityContext": {"privileged": True, "runAsUser": 0, "readOnlyRootFilesystem": True},
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}},
        "volumeMounts": [
            {"name": "config", "mountPath": "/config", "readOnly": True},
            {"name": "pins", "mountPath": "/cmtc-pins"},
            {"name": "locks", "mountPath": "/cmtc-locks"},
        ],
    }
    for key, kind, period, failures in (
        ("startupProbe", "live", 1, 30), ("readinessProbe", "ready", 2, 1),
        ("livenessProbe", "live", 5, 3),
    ):
        container[key] = {"exec": {"command": ["/cmtc-bpf-fence", "--health-check=" + kind]},
                          "timeoutSeconds": 3, "periodSeconds": period, "failureThreshold": failures}
    if fanout:
        for mount in container["volumeMounts"][1:]:
            mount["subPathExpr"] = "$(NODE_NAME)"
    return {
        "apiVersion": "apps/v1", "kind": "DaemonSet",
        "metadata": {"name": "cmtc-bpf-fence", "namespace": "cmtc-system"},
        "spec": {
            "updateStrategy": {"type": "OnDelete"},
            "selector": {"matchLabels": {"app.kubernetes.io/name": "cmtc-bpf-fence"}},
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "cmtc-bpf-fence", "security.cmtc.io/metrics": "true"}},
                "spec": {
                    "hostNetwork": True, "automountServiceAccountToken": False,
                    "nodeSelector": {"security.cmtc.io/bpf-fence-lab": "true"},
                    "tolerations": [{"operator": "Exists"}], "terminationGracePeriodSeconds": 10,
                    "containers": [container],
                    "volumes": [
                        {"name": "config", "configMap": {"name": "cmtc-bpf-fence-RUN"}},
                        {"name": "pins", "hostPath": {"path": "/sys/fs/bpf/cmtc-fence-RUN", "type": "Directory"}},
                        {"name": "locks", "hostPath": {"path": "/run/cmtc-fence-RUN", "type": "Directory"}},
                    ],
                },
            },
        },
    }


def _compare(actual, expected, path):
    # bool is an int subclass: exact types prevent false == 0 style acceptance.
    if type(actual) is not type(expected):
        raise FenceTemplateError(f"{path}: expected {type(expected).__name__}, got {type(actual).__name__}")
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            raise FenceTemplateError(f"{path}: unexpected or missing fields: {sorted(actual.keys() ^ expected.keys())}")
        for key in expected:
            _compare(actual[key], expected[key], path + "." + key)
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise FenceTemplateError(f"{path}: unexpected list length")
        for i, (a, e) in enumerate(zip(actual, expected)):
            _compare(a, e, f"{path}[{i}]")
    elif actual != expected:
        raise FenceTemplateError(f"{path}: value does not match audited opt-in profile")


def validate_fence_template(template, *, fanout=False):
    """Validate exact unrendered profile, returning a private copy for rendering.

    fanout=True permits ONLY NODE_NAME subPathExpr on private pins/locks mounts.
    Each node child must still be pre-created/audited 0700 by the harness; this
    function intentionally makes no claim about host filesystem contents.
    """
    _compare(template, expected_fence_template(fanout=fanout), "DaemonSet")
    return deepcopy(template)
