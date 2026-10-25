"""Pure tests; no Kubernetes, runtime, root or network access."""
import unittest
from fence_manifest_contract import FenceTemplateError, expected_fence_template, validate_fence_template


class FenceTemplateTests(unittest.TestCase):
    def test_exact_profile_and_private_result(self):
        for fanout in (False, True):
            template = expected_fence_template(fanout=fanout)
            got = validate_fence_template(template, fanout=fanout)
            got["spec"]["template"]["spec"]["containers"][0]["image"] = "changed"
            self.assertEqual(template["spec"]["template"]["spec"]["containers"][0]["image"], "IMAGE_NOT_BUILT")

    def test_widened_or_ambiguous_profile_refused(self):
        def pod(t): return t["spec"]["template"]["spec"]
        def c(t): return pod(t)["containers"][0]
        mutations = {
            "hostPID": lambda t: pod(t).update(hostPID=True),
            "hostIPC": lambda t: pod(t).update(hostIPC=True),
            "serviceAccountToken": lambda t: pod(t).update(automountServiceAccountToken=True),
            "unexpectedSA": lambda t: pod(t).update(serviceAccountName="privileged"),
            "hostRoot": lambda t: pod(t)["volumes"][1]["hostPath"].update(path="/"),
            "createHostRoot": lambda t: pod(t)["volumes"][1]["hostPath"].update(type="DirectoryOrCreate"),
            "extraMount": lambda t: c(t)["volumeMounts"].append({"name":"pins","mountPath":"/sys"}),
            "extraVolume": lambda t: pod(t)["volumes"].append({"name":"root","hostPath":{"path":"/"}}),
            "extraSidecar": lambda t: pod(t)["containers"].append(c(t).copy()),
            "initContainer": lambda t: pod(t).update(initContainers=[]),
            "mutableELF": lambda t: c(t)["args"].append("--elf=/config/other.o"),
            "alternateCommand": lambda t: c(t).update(command=["/bin/sh"]),
            "pulledImage": lambda t: c(t).update(imagePullPolicy="Always"),
            "httpProbe": lambda t: c(t).update(readinessProbe={"httpGet":{"path":"/readyz","port":18083}}),
            "unboundPodUID": lambda t: c(t)["env"].pop(),
            "shortProbeTimeout": lambda t: c(t)["readinessProbe"].update(timeoutSeconds=1),
            "automaticRollingUpdate": lambda t: t["spec"].update(updateStrategy={"type":"RollingUpdate"}),
            "allNodes": lambda t: pod(t).update(nodeSelector={}),
            "unsafeSubPath": lambda t: c(t)["volumeMounts"][1].update(subPath="../../"),
            "wrongSubPathExpr": lambda t: c(t)["volumeMounts"][1].update(subPathExpr="$(CLUSTER_NAME)"),
            "numericTokenFalse": lambda t: pod(t).update(automountServiceAccountToken=0),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                template = expected_fence_template()
                mutate(template)
                with self.assertRaises(FenceTemplateError): validate_fence_template(template)

    def test_fanout_subpaths_require_explicit_contract(self):
        template = expected_fence_template(fanout=True)
        with self.assertRaises(FenceTemplateError): validate_fence_template(template)
        validate_fence_template(template, fanout=True)
        template["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][1]["subPathExpr"]="$(POD_UID)"
        with self.assertRaises(FenceTemplateError): validate_fence_template(template, fanout=True)


if __name__ == "__main__": unittest.main()
