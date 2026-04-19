{{/*
Common helpers for the agents-enforcer chart.
Everything in this file is shared by the controller Deployment and
the node-agent DaemonSet so their labels/selectors stay in sync.
*/}}

{{- define "agents-enforcer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agents-enforcer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agents-enforcer.controller.fullname" -}}
{{- printf "%s-controller" (include "agents-enforcer.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agents-enforcer.nodeAgent.fullname" -}}
{{- printf "%s-node-agent" (include "agents-enforcer.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agents-enforcer.labels" -}}
app.kubernetes.io/name: {{ include "agents-enforcer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agents-enforcer
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "agents-enforcer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ include "agents-enforcer.fullname" . }}
{{- else -}}
default
{{- end -}}
{{- end -}}
