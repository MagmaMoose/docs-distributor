{{- define "docs-distributor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "docs-distributor.fullname" -}}
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

{{- define "docs-distributor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "docs-distributor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "docs-distributor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "docs-distributor.labels" -}}
helm.sh/chart: {{ include "docs-distributor.chart" . }}
{{ include "docs-distributor.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "docs-distributor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "docs-distributor.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "docs-distributor.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
The environment variable a source's read token arrives in: DD_SOURCE_TOKEN_<NAME>.
config.yml names the same variable, so the two are derived in one place.
*/}}
{{- define "docs-distributor.sourceTokenEnv" -}}
{{- printf "DD_SOURCE_TOKEN_%s" (. | upper | replace "-" "_") }}
{{- end }}

{{/*
config.yml. Built as a dict and rendered with toYaml, so values cannot inject YAML.
*/}}
{{- define "docs-distributor.config" -}}
{{- $sources := list }}
{{- range .Values.sources }}
{{- $auth := dict "type" (dig "auth" "type" "token" .) "apiUrl" (dig "auth" "apiUrl" "https://api.github.com" .) }}
{{- if eq $auth.type "token" }}
{{- $_ := set $auth "tokenEnv" (include "docs-distributor.sourceTokenEnv" .name) }}
{{- end }}
{{- $src := dict "name" .name "title" (default .name .title) "target" .target "ref" (default "main" .ref) "docsDir" (default "docs" .docsDir) "nav" (default "mkdocs.yml" .nav) "include" (default (list "**/*.md") .include) "exclude" (default (list) .exclude) "auth" $auth }}
{{- if .url }}
{{- $_ := set $src "url" .url }}
{{- end }}
{{- $sources = append $sources $src }}
{{- end }}
{{- $target := dict "repo" .Values.target.repo "branchPrefix" .Values.target.branchPrefix "mkdocs" .Values.target.mkdocs "labels" .Values.target.labels "auth" (dict "type" .Values.target.auth.type "apiUrl" .Values.target.auth.apiUrl) }}
{{- with .Values.target.base }}{{ $_ := set $target "base" . }}{{ end }}
{{- with .Values.target.navAfter }}{{ $_ := set $target "navAfter" . }}{{ end }}
{{- $llm := dict "backend" .Values.llm.backend "model" .Values.llm.model "effort" .Values.llm.effort "thinkingTokens" .Values.llm.thinkingTokens "timeoutSeconds" .Values.llm.timeoutSeconds "batchSize" .Values.llm.batchSize }}
{{- with .Values.llm.baseUrl }}{{ $_ := set $llm "baseUrl" . }}{{ end }}
{{- $report := dict "dir" "/var/lib/docs-distributor/reports" "slackWebhookEnv" "SLACK_WEBHOOK_URL" }}
{{- with .Values.report.issueRepo }}{{ $_ := set $report "issueRepo" . }}{{ end }}
{{- $cfg := dict "target" $target "sources" $sources "llm" $llm "languages" .Values.languages "report" $report "cacheDir" "/var/lib/docs-distributor/cache" "workDir" "/work" }}
{{- toYaml $cfg }}
{{- end }}

{{/*
An env var from a key of the existing Secret. `optional` keys may be absent from it.
*/}}
{{- define "docs-distributor.secretEnv" -}}
{{- $root := index . 0 }}{{ $name := index . 1 }}{{ $key := index . 2 }}{{ $optional := index . 3 }}
{{- if $key }}
- name: {{ $name }}
  valueFrom:
    secretKeyRef:
      name: {{ $root.Values.secrets.existingSecret }}
      key: {{ $key }}
      optional: {{ $optional }}
{{- end }}
{{- end }}
