"""YAML through Helm, so the tests need Helm and the Python standard library, and nothing else.

Python has no YAML parser of its own. Helm parses YAML with sigs.k8s.io/yaml, the parser Kubernetes reads these
manifests with: load() writes the documents into a throwaway chart whose one template returns them as JSON.
render() runs helm template on the v2 chart.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

V2 = pathlib.Path(__file__).resolve().parent.parent
CHART = V2 / "deploy" / "chart"
HELM = os.environ.get("HELM", "helm")

# A document Helm cannot parse comes back as {"Error": ...} from fromYaml: the template turns it into a failure.
_TEMPLATE = """{{- $out := dict }}
{{- range $path, $_ := .Files.Glob "docs/*.yaml" }}
{{- $doc := $.Files.Get $path | fromYaml }}
{{- if hasKey $doc "Error" }}{{ fail (printf "%s: %s" $path $doc.Error) }}{{ end }}
{{- $_ := set $out (base $path) $doc }}
{{- end }}
{{- toJson $out }}
"""


def available():
    return shutil.which(HELM) is not None


def load(documents):
    """The YAML documents (each a str holding one mapping), parsed, in order."""
    with tempfile.TemporaryDirectory() as work:
        chart = pathlib.Path(work)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: yaml-to-json\nversion: 0.0.1\n")
        (chart / "templates").mkdir()
        (chart / "templates" / "out.yaml").write_text(_TEMPLATE)
        (chart / "docs").mkdir()
        for i, document in enumerate(documents):
            (chart / "docs" / f"{i:05d}.yaml").write_text(document)
        out = subprocess.run([HELM, "template", "y", str(chart)], check=True, capture_output=True, text=True).stdout
    # helm prints "---" and "# Source: ..." before the template's output.
    body = out.split("\n", 2)[2] if out.startswith("---") else out
    parsed = json.loads(body)
    return [parsed[f"{i:05d}.yaml"] for i in range(len(documents))]


def split(stream):
    """The documents of a multi-document stream such as helm template prints: a "---" line at column 0 starts one
    (block scalars are indented, so no content line can be exactly "---")."""
    parts = re.split(r"(?m)^---[ \t]*$", stream)
    return [p for p in parts if p.strip() and not all(l.startswith("#") or not l.strip() for l in p.splitlines())]


def render(*values, namespace="monitoring", files=()):
    """helm template of the v2 chart with --values files, then --set values, as a list of parsed objects."""
    command = [HELM, "template", "cmtc-obs", str(CHART), "--namespace", namespace]
    for file in files:
        command += ["--values", str(file)]
    for value in values:
        command += ["--set", value]
    out = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    return load(split(out))
