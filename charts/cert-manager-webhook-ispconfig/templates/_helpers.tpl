{{/*
Chart name, overridable via nameOverride.
*/}}
{{- define "webhook.chartName" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name, at most 63 characters. If the release name already contains the
chart name, it is used as is.
*/}}
{{- define "webhook.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart name and version for the helm.sh/chart label.
*/}}
{{- define "webhook.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels. Used in immutable fields (spec.selector), so they must never change
between releases and never include user-supplied labels.
*/}}
{{- define "webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "webhook.chartName" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Standard labels of the chart. They take precedence over user-supplied labels, so that
selectors and the documented `kubectl -l` commands keep working.
*/}}
{{- define "webhook.standardLabels" -}}
{{ include "webhook.selectorLabels" . }}
helm.sh/chart: {{ include "webhook.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
{{- end -}}

{{/*
Renders metadata.labels (common labels plus object-specific labels) and, if not empty,
metadata.annotations (commonAnnotations plus object-specific annotations).
Usage: {{ include "webhook.metadata" (list . .Values.service.labels .Values.service.annotations) }}
*/}}
{{- define "webhook.metadata" -}}
{{- $ctx := index . 0 -}}
{{- $labels := merge (include "webhook.standardLabels" $ctx | fromYaml) (index . 1 | default dict) ($ctx.Values.commonLabels | default dict) -}}
{{- $annotations := merge (dict) (index . 2 | default dict) ($ctx.Values.commonAnnotations | default dict) -}}
labels:
  {{- toYaml $labels | nindent 2 }}
{{- with $annotations }}
annotations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Name of the ServiceAccount the webhook runs as.
*/}}
{{- define "webhook.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "webhook.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Container image reference. A digest takes precedence over the tag.
*/}}
{{- define "webhook.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (toString (.Values.image.tag | default .Chart.AppVersion)) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the APIService this webhook serves.
*/}}
{{- define "webhook.apiServiceName" -}}
{{- printf "v1alpha1.%s" (include "webhook.groupName" .) -}}
{{- end -}}

{{/*
ACME solver API group. Has no default: it must match dns01.webhook.groupName in the issuer.
*/}}
{{- define "webhook.groupName" -}}
{{- required "groupName is required (e.g. acme.example.com); it must match dns01.webhook.groupName in your issuer" .Values.groupName -}}
{{- end -}}

{{/*
webhook.name renders <fullname>-<suffix> within the 63-character limit.

The base is truncated, not the result: webhook.fullname is already truncated to 63
characters, so a trailing "| trunc 63" would cut off the suffix again. With a long release
name, all derived names would then collapse into one (CA and serving certificate in the
same Secret).

Usage: {{ include "webhook.name" (list . "webhook-tls") }}
*/}}
{{- define "webhook.name" -}}
{{- $ctx := index . 0 -}}
{{- $suffix := index . 1 -}}
{{- $base := include "webhook.fullname" $ctx | trunc (int (sub 62 (len $suffix))) | trimSuffix "-" -}}
{{- printf "%s-%s" $base $suffix -}}
{{- end -}}

{{/*
webhook.clusterName renders a name for an object outside the release namespace:
ClusterRole, ClusterRoleBinding and the Role in kube-system.

The namespace is part of the name because webhook.fullname does not contain it. Without it,
two installations with the same release name in different namespaces would describe the
same objects, and the second would take over the bindings of the first.

Not truncated: RBAC names allow 253 characters, and fullname (63) plus namespace (63) plus
suffix stay well below that. Truncating would make long names collide.

Usage: {{ include "webhook.clusterName" (list . "secret-reader") }}
*/}}
{{- define "webhook.clusterName" -}}
{{- $ctx := index . 0 -}}
{{- $suffix := index . 1 -}}
{{- printf "%s-%s-%s" (include "webhook.fullname" $ctx) $ctx.Release.Namespace $suffix -}}
{{- end -}}

{{/*
Secret holding the serving certificate. A Secret given via values wins; otherwise the name
is derived from the release.
*/}}
{{- define "webhook.servingSecretName" -}}
{{- if .Values.webhookTLS.existingSecret -}}
{{- .Values.webhookTLS.existingSecret -}}
{{- else -}}
{{- include "webhook.servingCertificateName" . -}}
{{- end -}}
{{- end -}}

{{/*
Name of the cert-manager Certificate for the serving certificate. Also referenced by the
inject-ca-from annotation of the APIService.
*/}}
{{- define "webhook.servingCertificateName" -}}
{{- include "webhook.name" (list . "webhook-tls") -}}
{{- end -}}

{{/*
Self-signed Issuer that issues the chart's own CA.
*/}}
{{- define "webhook.selfSignedIssuerName" -}}
{{- include "webhook.name" (list . "selfsign") -}}
{{- end -}}

{{/*
Chart-owned CA: Certificate, Secret and Issuer share this name.
*/}}
{{- define "webhook.caName" -}}
{{- include "webhook.name" (list . "ca") -}}
{{- end -}}

{{/*
Role/RoleBinding in kube-system to read the extension-apiserver-authentication ConfigMap.
Lives outside the release namespace, hence the namespace in the name.
*/}}
{{- define "webhook.authReaderName" -}}
{{- include "webhook.clusterName" (list . "auth-reader") -}}
{{- end -}}

{{/*
ClusterRoleBinding to the built-in ClusterRole system:auth-delegator.
*/}}
{{- define "webhook.authDelegatorName" -}}
{{- include "webhook.clusterName" (list . "auth-delegator") -}}
{{- end -}}

{{/*
ClusterRole/ClusterRoleBinding for read access to Secrets (tokenSecretRef).
*/}}
{{- define "webhook.secretReaderName" -}}
{{- include "webhook.clusterName" (list . "secret-reader") -}}
{{- end -}}

{{/*
ClusterRole/ClusterRoleBinding that allows cert-manager to call the solver.
*/}}
{{- define "webhook.domainSolverName" -}}
{{- include "webhook.clusterName" (list . "domain-solver") -}}
{{- end -}}
