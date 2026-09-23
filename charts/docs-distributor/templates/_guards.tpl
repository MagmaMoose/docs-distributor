{{/*
Preflight checks. Each describes a mistake that would otherwise surface as a failed run on
some Monday morning, or worse, as a run that "works". `fail` turns each into a readable
`helm template` error. Included once from NOTES.txt, so they run on template, install and
upgrade.
*/}}
{{- define "docs-distributor.guards" -}}

{{- if hasKey .Values "mapping" }}
{{- fail "Do not put the mapping in values. It is the key that undoes the anonymisation, and values are stored in every Helm release. Put it in the Secret named by secrets.existingSecret (secrets.keys.mapping)." }}
{{- end }}

{{- if not .Values.secrets.existingSecret }}
{{- fail "secrets.existingSecret is required: the run cannot anonymise anything without the mapping it holds, and this chart never creates Secrets itself." }}
{{- end }}

{{- if not .Values.secrets.keys.mapping }}
{{- fail "secrets.keys.mapping must name at least one key of the Secret: the mapping file(s)." }}
{{- end }}

{{- /* The rest only applies once there is something to sync; with no sources the
       CronJob renders suspended, so the chart installs before it is configured. */}}
{{- if .Values.sources }}

{{- if not (regexMatch "^[^/]+/[^/]+$" .Values.target.repo) }}
{{- fail "target.repo must be owner/name of the docs repository the pull request is opened on." }}
{{- end }}

{{- $targets := list }}
{{- range .Values.sources }}
{{- if not (regexMatch "^[a-z0-9]+(-[a-z0-9]+)*$" (toString .name)) }}
{{- fail (printf "sources: %q must be lower-case kebab case; it appears in branch names and nav markers." (toString .name)) }}
{{- end }}
{{- if not (hasPrefix "docs/" (toString .target)) }}
{{- fail (printf "sources[%s].target must be a directory under docs/." .name) }}
{{- end }}
{{- if and (eq (dig "auth" "type" "token" .) "token") (not (dig "auth" "tokenSecretKey" "" .)) }}
{{- fail (printf "sources[%s].auth.tokenSecretKey is required for token auth: name the Secret key holding a read-only token (or set auth.type: none for a public source)." .name) }}
{{- end }}
{{- $targets = append $targets .target }}
{{- end }}
{{- if ne (len $targets) (len (uniq $targets)) }}
{{- fail "two sources share a target directory; each would delete the other's pages." }}
{{- end }}

{{- end }}

{{- if and (eq .Values.llm.backend "claude-code") .Values.llm.baseUrl (not .Values.secrets.keys.litellmApiKey) }}
{{- fail "llm.baseUrl routes through a gateway, which needs its virtual key: set secrets.keys.litellmApiKey." }}
{{- end }}

{{- if and (eq .Values.llm.backend "anthropic") (not .Values.secrets.keys.anthropicApiKey) }}
{{- fail "llm.backend=anthropic needs secrets.keys.anthropicApiKey." }}
{{- end }}

{{- if and (not .Values.persistence.enabled) (not .Values.allowEphemeralCache) }}
{{- fail "persistence.enabled is false. Without a persistent LLM cache every run re-asks the model and rewords repaired prose, so the docs repo gets a new diff every week. Enable persistence, or set allowEphemeralCache: true for a throwaway install." }}
{{- end }}

{{- if not .Values.securityContext.readOnlyRootFilesystem }}
{{- fail "securityContext.readOnlyRootFilesystem must stay true: the job's only writable paths are its emptyDirs and its volume, which is what keeps a private checkout from lingering anywhere else." }}
{{- end }}

{{- if not (has .Values.command (list "sync" "plan")) }}
{{- fail "command must be sync or plan." }}
{{- end }}

{{- end }}
