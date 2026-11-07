{{- define "cmtc-lab-network.labels" -}}
app.kubernetes.io/name: cmtc-lab-network
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
