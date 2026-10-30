# cert-manager-webhook-ispconfig

Helm chart for the cert-manager DNS01 solver webhook that solves ACME challenges via the
ISPConfig DDNS token API.

The webhook runs as a Kubernetes extension API server. cert-manager calls it through the
aggregation layer (`APIService v1alpha1.<groupName>`); the webhook then creates and removes
TXT records via the DDNS API.

## Prerequisites

- Kubernetes >= 1.30 (`lifecycle.preStop.sleep` is used for graceful shutdown)
- cert-manager >= 1.12 in the cluster. The chart only needs `cert-manager.io/v1` for
  `Issuer`/`Certificate` and the stable `v1alpha1` webhook API.
- A DDNS token of your ISPConfig installation, restricted to `TXT` records and ideally to
  `_acme-challenge`

## Installation

```bash
helm install cert-manager-webhook-ispconfig \
  oci://ghcr.io/ise-cobra/charts/cert-manager-webhook-ispconfig \
  --namespace cert-manager \
  --set groupName=acme.example.com \
  --set webhook.endpoint=https://ispconfig.example.com
```

`groupName` and `webhook.endpoint` are required and have no default:

- `groupName` is the API group of the solver. Use a domain you own; it must be identical to
  `dns01.webhook.groupName` in your issuer.
- `webhook.endpoint` is the base URL of the ISPConfig DDNS API (the host serving
  `/ddns/update.php`). It can be overridden per issuer via `config.endpoint`.

Installing into the cert-manager namespace is recommended but not required: the RBAC binding
for cert-manager is configured via `certManager.namespace` and `certManager.serviceAccountName`.

## Resources created by the chart

| Resource | Purpose |
|---|---|
| `Deployment`, `Service`, `ServiceAccount`, `PodDisruptionBudget`, `NetworkPolicy` (optional) | Workload |
| `APIService v1alpha1.<groupName>` | Registration with the aggregation layer |
| `Issuer` (selfSigned), `Certificate` (CA), `Issuer` (CA), `Certificate` (serving) | Serving certificate of the webhook |
| `Role`/`RoleBinding` in `kube-system` | Read `extension-apiserver-authentication` |
| `ClusterRoleBinding` to `system:auth-delegator` | Delegated authentication/authorization |
| `ClusterRole`/`ClusterRoleBinding` `…-secret-reader` | `get` on the token Secrets (`tokenSecretRef`) |
| `ClusterRole`/`ClusterRoleBinding` `…-domain-solver` | Allows cert-manager to call the solver |

## Values

### Webhook

| Key | Default | Description |
|---|---|---|
| `groupName` | `""` | **Required.** ACME solver API group; must match the issuer |
| `webhook.securePort` | `8443` | TLS port; rendered as container port `https` |
| `webhook.endpoint` | `""` | **Required.** Default base URL of the DDNS API |
| `webhook.httpTimeout` | `30s` | Default timeout per DDNS call, 1s to 50s |
| `webhook.allowInsecureEndpoint` | `false` | Allows `http://` endpoints (development only) |
| `webhook.log.level` | `info` | `debug`/`info`/`warn`/`error` |
| `webhook.log.format` | `json` | `auto`/`json`/`text` |
| `webhook.otel.endpoint` | `""` | OTLP endpoint; empty disables telemetry |
| `webhook.otel.insecure` | `false` | OTLP without TLS; an `http://` endpoint is clear text regardless |
| `webhook.otel.sampleRatio` | `1.0` | Trace sampling ratio |

### Webhook TLS

| Key | Default | Description |
|---|---|---|
| `webhookTLS.mountPath` | `/etc/webhook/tls` | Mount directory for `tls.crt`/`tls.key` |
| `webhookTLS.existingSecret` | `""` | Existing Secret instead of the derived name (requires `certManager.enabled=false`) |
| `webhookTLS.certManager.enabled` | `true` | Creates the Issuers and the CA and serving Certificates |
| `webhookTLS.certManager.privateKey.algorithm` | `ECDSA` | Key algorithm |
| `webhookTLS.certManager.privateKey.size` | `256` | Key size or curve size |
| `webhookTLS.certManager.ca.duration` | `43800h` | Validity of the chart-owned CA |
| `webhookTLS.certManager.ca.renewBefore` | `8760h` | CA renewal lead time |
| `webhookTLS.certManager.serving.duration` | `8760h` | Validity of the serving certificate |
| `webhookTLS.certManager.serving.renewBefore` | `720h` | Serving certificate renewal lead time |

### APIService

| Key | Default | Description |
|---|---|---|
| `apiService.groupPriorityMinimum` | `1000` | Priority of the API group |
| `apiService.versionPriority` | `15` | Priority of the version |
| `apiService.caBundle` | `""` | Base64 CA bundle; only needed without cert-manager TLS |
| `apiService.annotations` | `{}` | Additional annotations |

### cert-manager and RBAC

| Key | Default | Description |
|---|---|---|
| `certManager.namespace` | `cert-manager` | Namespace of the cert-manager installation |
| `certManager.serviceAccountName` | `cert-manager` | ServiceAccount of the cert-manager controller |
| `rbac.create` | `true` | Creates all RBAC objects |
| `rbac.secretResourceNames` | `[ispconfig-ddns-token]` | Secret names the webhook may `get`. Must not be empty (see [Security](#security)) |
| `rbac.acknowledgeUnrestrictedSecretAccess` | `false` | Explicit opt-in for an empty `secretResourceNames` |

### Image

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/ise-cobra/cert-manager-webhook-ispconfig` | Container image |
| `image.tag` | `""` | Empty = `.Chart.AppVersion` |
| `image.digest` | `""` | Takes precedence over `tag` |
| `image.pullPolicy` | `IfNotPresent` | Pull policy |
| `image.pullSecrets` | `[]` | Pull secrets |

### Workload

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `2` | Number of replicas |
| `resources.requests` | `10m` / `32Mi` | The service only issues a few HTTP requests per challenge |
| `resources.limits` | `200m` / `128Mi` | Upper bound |
| `livenessProbe` | `GET /livez` via HTTPS | Liveness |
| `readinessProbe` | `GET /readyz` via HTTPS | Readiness |
| `startupProbe` | `GET /healthz` via HTTPS | Startup |
| `podSecurityContext` | `runAsNonRoot`, UID/GID/fsGroup `65532`, `RuntimeDefault` | `65532` is the `nonroot` user of the distroless image |
| `containerSecurityContext` | `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `drop: [ALL]` | Container hardening |
| `podSpread.enabled` | `true` | Spreads replicas across nodes via `topologySpreadConstraints` |
| `podSpread.topologyKey` | `kubernetes.io/hostname` | Topology key |
| `podSpread.whenUnsatisfiable` | `ScheduleAnyway` | Behavior if the constraint cannot be met |
| `topologySpreadConstraints` | `[]` | Raw constraints; replace `podSpread` |
| `affinity`, `nodeSelector`, `tolerations`, `priorityClassName` | empty | Scheduling |
| `terminationGracePeriodSeconds` | `70` | Covers the maximum challenge time budget (see below) |
| `lifecycleHooks.preStop.sleep.seconds` | `5` | Delays SIGTERM until the pod has been removed from the endpoint slice |
| `extraEnvVars` | `[]` | Additional environment variables |
| `volumes`, `volumeMounts` | `[]` | Additional volumes; the chart adds the TLS Secret and `/tmp` itself |

### Service, ServiceAccount, PDB, NetworkPolicy, metadata

| Key | Default | Description |
|---|---|---|
| `service.type` | `ClusterIP` | Service type |
| `service.ports[0]` | `443` → `https` | The APIService connects to the first port |
| `serviceAccount.create` | `true` | Dedicated ServiceAccount for the RBAC bindings |
| `serviceAccount.name` | `""` | Empty = full name of the release |
| `serviceAccount.automountToken` | `true` | Required for Secret and TokenReview access |
| `podDisruptionBudget.enabled` | `true` | Creates the PDB (only with `replicaCount` > 1) |
| `podDisruptionBudget.minAvailable` | `1` | At least one replica stays available |
| `podDisruptionBudget.maxUnavailable` | unset | Alternative to `minAvailable`; takes precedence if set |
| `networkPolicy.enabled` | `false` | Egress targets depend on the environment |
| `networkPolicy.ingress`, `networkPolicy.egress` | `[]` | Rules; required for every direction in `policyTypes` when enabled |
| `nameOverride`, `fullnameOverride` | `""` | Name overrides |
| `commonLabels`, `commonAnnotations` | `{}` | Added to every object and to the pod template |
| `deployment.labels`, `service.labels`, `serviceAccount.labels`, … | `{}` | Object-specific labels |
| `deployment.annotations`, `service.annotations`, … | `{}` | Object-specific annotations |
| `podLabels`, `podAnnotations` | `{}` | Pod template metadata (not part of the selector) |

## Complete example

### 1. Secret with the DDNS token

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ispconfig-ddns-token
  namespace: cert-manager
type: Opaque
stringData:
  token: "<DDNS-TOKEN>"
```

For a `ClusterIssuer` the Secret must live in the cluster resource namespace of cert-manager
(by default the namespace of the cert-manager controller). The token must be lowercase hex.

If you use a different Secret name, add it to `rbac.secretResourceNames`.

### 2. ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-ispconfig
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: hostmaster@example.com
    privateKeySecretRef:
      name: letsencrypt-ispconfig-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.example.com
            solverName: ispconfig
            config:
              # optional, overrides webhook.endpoint of the chart
              endpoint: https://ispconfig.example.com
              tokenSecretRef:
                name: ispconfig-ddns-token
                key: token
              # optional, overrides webhook.httpTimeout of the chart
              httpTimeout: 30s
```

Unknown fields in the `config` block are rejected: the webhook decodes strictly.

### 3. Wildcard certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-wildcard
  namespace: default
spec:
  secretName: example-com-wildcard-tls
  issuerRef:
    name: letsencrypt-ispconfig
    kind: ClusterIssuer
  commonName: "*.example.com"
  dnsNames:
    - "example.com"
    - "*.example.com"
```

## Propagation time

The DDNS API only publishes a new TXT record with the next zone reload, in practice after
about **one minute**. cert-manager checks the record itself before the ACME validation
("self check") and retries with backoff, so the first attempts are expected to fail.

By default the self check queries the zone's authoritative nameservers. Only if they are not
reachable from the cluster (egress restrictions, split-horizon DNS), let the cert-manager
controller use recursive resolvers instead. They cache the negative answer of an early check,
which can delay issuance by the zone's negative TTL:

```yaml
# values.yaml of the cert-manager installation
extraArgs:
  - --dns01-recursive-nameservers-only
  - --dns01-recursive-nameservers=1.1.1.1:53,8.8.8.8:53
```

Further notes:

- `webhook.httpTimeout` (or `config.httpTimeout` in the issuer) must exceed the response time
  of the DDNS API; `30s` is sufficient.
- `config.httpTimeout` is capped at **50s**, below the kube-apiserver request timeout of 60s;
  higher values are rejected. The time budget of a challenge is `httpTimeout + 5s` (Secret
  lookup), at most 55s. The 5s `preStop` sleep runs before SIGTERM is delivered, so
  `terminationGracePeriodSeconds: 70` covers the worst case including a 5s telemetry flush and
  does not need to be adjusted when `httpTimeout` is raised.
- With many parallel challenges, `--max-concurrent-challenges` of the cert-manager controller
  limits the load on the DDNS API.

## Running without cert-manager TLS

If the serving certificate comes from another source:

```bash
helm upgrade --install cert-manager-webhook-ispconfig \
  oci://ghcr.io/ise-cobra/charts/cert-manager-webhook-ispconfig \
  --namespace cert-manager \
  --set groupName=acme.example.com \
  --set webhook.endpoint=https://ispconfig.example.com \
  --set webhookTLS.certManager.enabled=false \
  --set webhookTLS.existingSecret=my-webhook-tls \
  --set apiService.caBundle="$(base64 -w0 < ca.crt)"
```

With `webhookTLS.certManager.enabled=false` the chart aborts rendering if
`webhookTLS.existingSecret` is missing (no serving certificate) or if neither
`apiService.caBundle` nor an `inject-ca-from` annotation in `apiService.annotations` is set
(no CA trust anchor; the `APIService` would never become `Available`). The error message names
the value to set.

Note: `helm lint` does not evaluate `fail` and `required`, so it passes even for values that
cannot work; `helm install`, `helm upgrade` and `helm template` abort.

## Security

Anyone allowed to create an `Issuer` chooses via `config.endpoint` where the webhook sends the
token it reads from the referenced Secret. The chart therefore restricts the webhook's Secret
access to `rbac.secretResourceNames` and refuses to render with an empty list unless
`rbac.acknowledgeUnrestrictedSecretAccess=true` is set.

To additionally limit where the webhook can connect to, enable `networkPolicy` and allow egress
only to DNS, the kube-apiserver and your ISPConfig endpoint.

## Metrics

The extension API server serves `/metrics` via HTTPS with the chart's self-issued serving
certificate and requires authentication. The chart does not create a `ServiceMonitor`. To
scrape it with the Prometheus Operator, create a `ServiceMonitor` yourself with a
`tlsConfig` that trusts the chart CA (Secret `<fullname>-ca`, key `ca.crt`), a bearer token
of the Prometheus ServiceAccount, and grant Prometheus a ClusterRole with
`nonResourceURLs: ["/metrics"]` and verb `get`.

## Troubleshooting

```bash
# Is the extension API server registered?
kubectl get apiservice v1alpha1.acme.example.com

# Webhook logs
kubectl -n cert-manager logs -l app.kubernetes.io/name=cert-manager-webhook-ispconfig -f

# Why is the challenge stuck?
kubectl describe challenge -A
```

| Symptom | Cause |
|---|---|
| `APIService` reports `FailedDiscoveryCheck` | Serving certificate missing, `caBundle` empty or pod not `Ready` |
| Pod stays `Ready: false` | TLS Secret not issued yet, or the `Role` in `kube-system` is missing |
| Challenge stays `pending` with `forbidden` | cert-manager lacks `create` on `<groupName>/ispconfig`; check `certManager.namespace`/`serviceAccountName` |
| `secrets … is forbidden` | `rbac.secretResourceNames` does not contain the Secret name |
| `401` from the DDNS API | Token unknown to ISPConfig or revoked |
