{{/*
Expand the name of the chart.
*/}}
{{- define "secureai.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "secureai.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "secureai.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "secureai.labels" -}}
helm.sh/chart: {{ include "secureai.chart" . }}
{{ include "secureai.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — API
*/}}
{{- define "secureai.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secureai.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API component labels
*/}}
{{- define "secureai.apiLabels" -}}
{{ include "secureai.labels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
API selector labels
*/}}
{{- define "secureai.apiSelectorLabels" -}}
{{ include "secureai.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Worker component labels
*/}}
{{- define "secureai.workerLabels" -}}
{{ include "secureai.labels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Worker selector labels
*/}}
{{- define "secureai.workerSelectorLabels" -}}
{{ include "secureai.selectorLabels" . }}
app.kubernetes.io/component: worker
{{- end }}

{{/*
Secret name — uses existingSecret if set, otherwise generates one.
*/}}
{{- define "secureai.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "secureai.fullname" . }}-secrets
{{- end }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "secureai.configMapName" -}}
{{- include "secureai.fullname" . }}-config
{{- end }}
