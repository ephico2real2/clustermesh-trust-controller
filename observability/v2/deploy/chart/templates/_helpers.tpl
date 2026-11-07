{{/*
The metric_relabel_configs regex of a keep list: the names, plus the series a histogram or an OpenMetrics counter
adds to its family name. Prometheus anchors the regex.
*/}}
{{- define "cmtc-obs.keep" -}}
({{ join "|" . }})(_bucket|_sum|_count|_total)?
{{- end }}

{{- define "cmtc-obs.labels" -}}
app.kubernetes.io/name: cmtc-observability
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/* Fails the render when clusterName is missing: every series would lose its cluster label. */}}
{{- define "cmtc-obs.cluster" -}}
{{- required "clusterName is required: the cluster label of every series" .Values.clusterName -}}
{{- end }}

{{/*
The namespaces this release's Prometheus discovers Pods in (kind): the namespace of every enabled Pod job, and the
release namespace for the self-scrape. prometheus-rbac.yaml grants pods get/list/watch in these only.
*/}}
{{- define "cmtc-obs.podNamespaces" -}}
{{- $j := .Values.jobs }}
{{- $namespaces := list }}
{{- range $key := list "cmtc" "ciliumAgent" "ztunnel" "coredns" "certManager" "trustManager" "spireServer" "spireAgent" }}
{{- $job := index $j $key }}
{{- if $job.enabled }}{{ $namespaces = append $namespaces $job.namespace }}{{ end }}
{{- end }}
{{- if $j.prometheus.enabled }}{{ $namespaces = append $namespaces .Release.Namespace }}{{ end }}
{{- toYaml ($namespaces | uniq) }}
{{- end }}

{{/*
OpenShift's platform monitoring scrapes CoreDNS and the kubelet under its own job names. Rewrites the job selectors
of a rule file or a dashboard: called with (dict "text" <content> "jobs" .Values.openshift.platformJobs "q" <quote>),
where q is the quote the text writes around a label value: `"` in a rule file, `\"` inside a JSON string.
*/}}
{{- define "cmtc-obs.openshiftJobs" -}}
{{- $q := .q }}
{{- $dns := .jobs.coredns }}
{{- $kubelet := .jobs.cadvisor }}
{{- $text := .text }}
{{- $text = replace (printf "job=%scoredns%s" $q $q) (printf "job=%s%s%s" $q $dns $q) $text }}
{{- $text = replace (printf "job=%scadvisor%s" $q $q) (printf "job=%s%s%s, metrics_path=%s/metrics/cadvisor%s" $q $kubelet $q $q $q) $text }}
{{- $text = replace "|coredns|" (printf "|%s|" $dns) $text }}
{{- $text = replace "|cadvisor|" (printf "|%s|" $kubelet) $text }}
{{- $text = replace (printf "|cadvisor%s" $q) (printf "|%s%s" $kubelet $q) $text }}
{{- $text }}
{{- end }}

{{/*
The rule files to load, as a dict of file name to content: files/rules/*.rules.yaml, plus files/rules/proposed/
when rules.includeProposed. Rendered, not copied:
- the lines between "# expected-clusters:begin" and "# expected-clusters:end" list hub.expectedClusters (default:
  clusterName alone);
- on OpenShift, the lines between "# expected-nodes:begin" and "# expected-nodes:end" read the nodes from
  kube_node_info, and the platform's job names replace coredns and cadvisor.
tests/test_deploy.py renders both platforms and checks every replacement.
*/}}
{{- define "cmtc-obs.ruleFiles" -}}
{{- $clusters := .Values.hub.expectedClusters | default (list (include "cmtc-obs.cluster" .)) }}
{{- $expected := list "  # expected-clusters:begin" "  - record: cmtc:expected_cluster:info" "    expr: |-" }}
{{- range $i, $cluster := $clusters }}
{{- $expected = append $expected (printf "      %slabel_replace(vector(1), \"cluster\", %q, \"\", \"\")" (ternary "" "or " (eq $i 0)) $cluster) }}
{{- end }}
{{- $expected = append $expected "  # expected-clusters:end" }}
{{- $nodes := list "  # expected-nodes:begin" "  - record: cmtc:expected_node:info" "    expr: group by (cluster, node) (kube_node_info)" "  # expected-nodes:end" }}
{{- $files := dict }}
{{- range $path, $_ := .Files.Glob "files/rules/*.rules.yaml" }}
{{- $_ := set $files (base $path) ($.Files.Get $path) }}
{{- end }}
{{- if .Values.rules.includeProposed }}
{{- range $path, $_ := .Files.Glob "files/rules/proposed/*.rules.yaml" }}
{{- $_ := set $files (printf "proposed-%s" (base $path)) ($.Files.Get $path) }}
{{- end }}
{{- end }}
{{- range $name, $content := $files }}
{{- $content = regexReplaceAll "(?s)  # expected-clusters:begin\n.*?  # expected-clusters:end" $content (join "\n" $expected) }}
{{- if $.Values.global.openshift }}
{{- $content = regexReplaceAll "(?s)  # expected-nodes:begin\n.*?  # expected-nodes:end" $content (join "\n" $nodes) }}
{{- $content = include "cmtc-obs.openshiftJobs" (dict "text" $content "jobs" $.Values.openshift.platformJobs "q" "\"") }}
{{- end }}
{{- $_ := set $files $name $content }}
{{- end }}
{{- toYaml $files }}
{{- end }}

{{/*
The dashboards of files/dashboards/<kind>/, as a dict of file name to content. Every query names one of the two lab
clusters, so that each cluster keeps one colour (cmtc-a in the first, cmtc-b in the second); dashboards.clusters
names the clusters drawn in their place. On OpenShift, the platform's job names replace coredns and cadvisor.
Called with (dict "root" $ "kind" "grafana"|"perses").
*/}}
{{- define "cmtc-obs.dashboards" -}}
{{- $root := .root }}
{{- $clusters := $root.Values.dashboards.clusters }}
{{- $files := dict }}
{{- range $path, $_ := $root.Files.Glob (printf "files/dashboards/%s/*.json" .kind) }}
{{- $content := $root.Files.Get $path }}
{{- $content = replace "cluster=\\\"cmtc-a\\\"" (printf "cluster=\\\"%s\\\"" (index $clusters 0)) $content }}
{{- $content = replace "cluster=\\\"cmtc-b\\\"" (printf "cluster=\\\"%s\\\"" (index $clusters 1)) $content }}
{{- /* An expected-cluster list written with label_replace(vector(1), "cluster", "cmtc-a", "", ""). */}}
{{- $content = replace "\\\"cluster\\\", \\\"cmtc-a\\\"" (printf "\\\"cluster\\\", \\\"%s\\\"" (index $clusters 0)) $content }}
{{- $content = replace "\\\"cluster\\\", \\\"cmtc-b\\\"" (printf "\\\"cluster\\\", \\\"%s\\\"" (index $clusters 1)) $content }}
{{- /* A table colours its cluster column by value: the keys of Grafana's value mappings, and the values of the
     cell conditions percli writes for Perses. */}}
{{- $content = replace "\"cmtc-a\": {" (printf "%q: {" (index $clusters 0)) $content }}
{{- $content = replace "\"cmtc-b\": {" (printf "%q: {" (index $clusters 1)) $content }}
{{- $content = replace "\"value\": \"cmtc-a\"" (printf "\"value\": %q" (index $clusters 0)) $content }}
{{- $content = replace "\"value\": \"cmtc-b\"" (printf "\"value\": %q" (index $clusters 1)) $content }}
{{- if $root.Values.global.openshift }}
{{- $content = include "cmtc-obs.openshiftJobs" (dict "text" $content "jobs" $root.Values.openshift.platformJobs "q" "\\\"") }}
{{- end }}
{{- $_ := set $files (base $path) $content }}
{{- end }}
{{- toYaml $files }}
{{- end }}
