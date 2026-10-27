{{- define "cmtc.labels" -}}
app.kubernetes.io/part-of: cmtc
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "cmtc.clusterName" -}}
{{- $name := required "clusterName is required" .Values.clusterName -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name) -}}
{{- fail (printf "clusterName %q is not a DNS label" $name) -}}
{{- end -}}
{{- $name -}}
{{- end }}

{{- define "cmtc.image" -}}
{{- with .Values.image -}}
{{- if .digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .digest) -}}
{{- fail (printf "image.digest %q is not sha256:<64 hex>" .digest) -}}
{{- end -}}
{{- printf "%s@%s" .repository .digest -}}
{{- else if .tag -}}
{{- printf "%s:%s" .repository .tag -}}
{{- else -}}
{{- fail "set image.digest (preferred) or image.tag" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* OpenShift assigns the UID (restricted-v2, MustRunAsRange); a fixed runAsUser outside the range is refused. */}}
{{- define "cmtc.podSecurityContext" -}}
{{- $defaults := dict "runAsNonRoot" true "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- if not .Values.global.openshift -}}
{{- $_ := set $defaults "runAsUser" 65532 -}}
{{- end -}}
{{- toYaml (mergeOverwrite $defaults (deepCopy .Values.podSecurityContext)) -}}
{{- end }}

{{- define "cmtc.securityContext" -}}
{{- $defaults := dict "allowPrivilegeEscalation" false "readOnlyRootFilesystem" true "capabilities" (dict "drop" (list "ALL")) -}}
{{- toYaml (mergeOverwrite $defaults (deepCopy .Values.securityContext)) -}}
{{- end }}

{{- define "cmtc.metricsNamespaces" -}}
{{- $namespaces := .Values.metrics.networkPolicy.allowedNamespaces -}}
{{- if not $namespaces -}}
{{- if .Values.global.openshift -}}
{{- $namespaces = list "openshift-monitoring" "openshift-user-workload-monitoring" -}}
{{- else -}}
{{- $namespaces = list "monitoring" -}}
{{- end -}}
{{- end -}}
{{- toYaml (append $namespaces .Release.Namespace | uniq) -}}
{{- end }}
