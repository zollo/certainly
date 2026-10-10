{{/*
Expand the name of the chart.
*/}}
{{- define "certainly.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains chart name it will be used
as a full name.
*/}}
{{- define "certainly.fullname" -}}
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
{{- define "certainly.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "certainly.labels" -}}
helm.sh/chart: {{ include "certainly.chart" . }}
{{ include "certainly.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "certainly.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certainly.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The name of the service account the workloads should use.
*/}}
{{- define "certainly.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "certainly.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Bundled Redis resource name.
*/}}
{{- define "certainly.redis.fullname" -}}
{{- printf "%s-redis" (include "certainly.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Resolve the Redis connection URL the app should use.
When the bundled Redis is enabled, point at its in-cluster Service. Otherwise
use the externally supplied URL. May be empty when the URL is instead provided
through secretEnv / existingSecret, in which case the key is omitted from the
ConfigMap and supplied by the Secret at runtime.
*/}}
{{- define "certainly.redisUrl" -}}
{{- if .Values.redis.enabled -}}
redis://{{ include "certainly.redis.fullname" . }}:6379/0
{{- else -}}
{{- .Values.externalRedis.url -}}
{{- end -}}
{{- end }}

{{/*
Name of the ConfigMap holding non-secret CERTAINLY_* settings.
*/}}
{{- define "certainly.configMapName" -}}
{{- printf "%s-config" (include "certainly.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Name of the Secret holding sensitive CERTAINLY_* settings.
*/}}
{{- define "certainly.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- printf "%s-secret" (include "certainly.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}
