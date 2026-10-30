# cert-manager-webhook-ispconfig — contributor and agent guide

## What this is

A cert-manager DNS01 solver webhook for domains whose DNS is managed by ISPConfig. The service is
a Kubernetes extension API server: cert-manager calls `Present` and `CleanUp` through the
aggregation layer, and the webhook creates or removes TXT records via the ISPConfig DDNS token API
([ispconfig-ddns-module](https://github.com/mhofer117/ispconfig-ddns-module)). This makes
wildcard certificates issuable automatically.

## Build / test / run

```shell
go build ./...
go test -race -cover ./...
golangci-lint run
go run ./cmd/webhook --help
```

`go test -race` needs cgo and therefore a C compiler; without one it fails with
`go: -race requires cgo`. Run without `-race` locally then; CI always runs with `-race`.

### Reading the coverage number

`go test -cover ./...` reports a lower total than the production code actually has:
`internal/ispconfig/ddnstest` is a test-double package (regular `.go` files so several test
packages can import it) without tests of its own, and counts as production code at 0 %.

```shell
# production code (stays above 80 %)
go test -coverprofile=coverage.out ./... && grep -v '/ddnstest/' coverage.out > coverage.prod.out
go tool cover -func=coverage.prod.out | tail -1

# the test double itself, measured through the tests that use it
go test -coverpkg=./internal/ispconfig/ddnstest/ ./internal/solver/
```

The uncovered paths in `ddnstest` are intentional: they mirror error responses of the remote side
(`zone` parameter set, `action=update` for TXT, value longer than 255 characters, wrong record
type) that the client must **never** trigger. They are the regression net for exactly those bugs.

End-to-end tests (cert-manager conformance suite) sit behind a build tag because they start real
`etcd` and `kube-apiserver` binaries:

```shell
go test -tags e2e ./e2e/...
```

Prerequisites are in [e2e/README.md](e2e/README.md).

## Architecture

```
cmd/webhook/                    urfave/cli/v3 wiring, signal handling
internal/app/                   configuration validation, start of the extension API server
internal/solver/                cert-manager webhook.Solver adapter
   solver.go                    Name/Present/CleanUp/Initialize
   config.go                    per-issuer configuration, strictly decoded
   secrets.go                   token resolution from the Kubernetes secret
internal/ispconfig/             HTTP client for the DDNS API — the only place with network access
internal/common/logging/        slog setup plus klog/logr bridge
internal/common/observability/  OTel traces and metrics, inactive without an OTLP endpoint
internal/common/version/        version info from -ldflags
e2e/                            conformance suite, build tag `e2e`
charts/cert-manager-webhook-ispconfig/   self-contained Helm chart
openspec/                       specs and change proposals
```

Data flow: `solver` → `ispconfig`. The client interface is defined in the consuming package
`internal/solver`, not in the client package.

Three rules live in exactly one place although three layers need them — at startup, per issuer and
in the client. They are in `internal/ispconfig` because that is where the remote side is known,
and `internal/app` and `internal/solver` call them instead of copying them:

- `ispconfig.ValidateEndpoint` — scheme, host, `http` only when explicitly allowed. Sentinels
  `ErrInvalidEndpoint`/`ErrInsecureEndpoint`; `internal/app` passes the same sentinels on.
- `ispconfig.IsValidToken` — the character set the remote side does not silently strip.
- `ispconfig.RedactedPlaceholder` — the same placeholder in the client and in secret resolution.

**Accepted residual risk:** `ValidateEndpoint` checks scheme and host, but not whether the
`config.endpoint` set by an issuer points to the same host as the startup default. Whoever may
create an issuer in a namespace can make the webhook POST/DELETE to any `https` target (limited
SSRF) and read the — redacted, but up to 512 characters long — error response via
`Status.Message`. Deliberately not restricted in code: a host-bound check would block legitimate
setups with several ISPConfig servers. The mitigation is operational: `networkPolicy.enabled: true`
with egress limited to DNS, the kube-apiserver and the ISPConfig endpoint (default `false` because
the target depends on the environment), plus `rbac.secretResourceNames`.

A fourth rule belongs to the solver: `solver.MaxHTTPTimeout` (50s, below the apiserver request
timeout of 60s) caps the issuer-configurable `httpTimeout`. Without a cap, a value like `24h` would hold a
goroutine and a socket long after the apiserver aborted the request — and a `delete` could reach
ISPConfig before the late `add`, leaving an orphaned TXT record. Adding the secret-resolution time
budget to a value near `MaxInt64` could also overflow and yield an already expired context. The
chart's `terminationGracePeriodSeconds` is sized for this cap.

## Pitfalls

Things to know before the first edit.

### `go get` breaks module resolution here

With this module graph, `go get <module>@<version>` can derail MVS and pull `cert-manager v1.20.3`
down to `v1.20.0-alpha.0` and `grpc` to a `-dev` version. Add modules like this instead:

```shell
go mod edit -require=<module>@<version>
go mod download <module>
```

After every change to `go.mod`, check that it still says
**`github.com/cert-manager/cert-manager v1.20.3`**.

### Coupled versions

`cert-manager` is pinned to **v1.20.3**. The `k8s.io/*` modules are on **v0.35.2** — exactly what
cert-manager v1.20.3 requires; v1.21.x already requires **v0.36.2**. Do not raise these versions
individually: a downgrade breaks compilation, an upgrade produces hard-to-diagnose errors in the
apiserver stack. Moving to cert-manager v1.21.x is a change of its own. Dependabot is configured
to ignore `k8s.io/*` and `sigs.k8s.io/*` entirely and minor/major bumps of cert-manager for that
reason; CI fails if cert-manager leaves `v1.20.x` or `go.mod` is not tidy.

The Go version in `go.mod` and in the `Dockerfile` build stage must be identical; CI checks it.
A Dependabot pull request for a new `golang` patch image therefore fails until `go.mod` is raised
in the same pull request. Base images are pinned by digest, and Dependabot keeps the digests
current.

### `govulncheck`

`govulncheck ./...` must report **0 called** vulnerabilities. It may list vulnerabilities in modules
that are part of the build graph through `k8s.io/apiserver` but whose affected symbols are not
reachable — `etcd` client code (the webhook has no storage backend, `RecommendedOptions.Etcd` is
`nil`) and `cel-go` (no CEL admission, `Admission` is `nil`) — plus GO-2026-5932 in
`golang.org/x/crypto`, for which no fix existed as of October 2026. Raising those modules
individually brings no security benefit and risks incompatibilities; they disappear with the next cert-manager
bump. Re-check reachability whenever storage or admission is enabled.

### The token must never appear anywhere

The DDNS token is sent via HTTP basic auth (user `anonymous`), not as a query parameter — otherwise
it would end up in `*url.Error` on every network error and from there in the logs. Errors from
`Present`/`CleanUp` are also returned to cert-manager as `metav1.Status.Message` and end up in its
logs and events.

Mandatory:

- Never log the full request URL. `net/http` puts it into every transport error (`*url.Error`),
  both in the message **and** in the `URL` field. `Client.stripRequestURL` therefore replaces the
  `*url.Error` with a `transportError` (operation, host, cause) that wraps only the cause —
  otherwise `errors.As` would hand out the URL despite the redacted message. `errors.Is` on
  `context.DeadlineExceeded` keeps working.
- Every error from an HTTP call goes through the redaction function in `internal/ispconfig`.
- No `otelhttp` transport on the DDNS client — it sets `url.full` and would send the token to the
  tracing backend in query mode.
- `span.RecordError` only gets `errorClass(err)`, never the full message: on `403` the response
  body names the record, and `RecordError` puts its text into the span as `exception.message`.
- There is deliberately **no** flag and **no** environment variable for the token.

### Quirks of the remote side

Five details of the DDNS module that cannot be guessed:

- **`add` on an identical existing record** answers `HTTP 200` with a body starting with
  `ERROR:`. Functionally a success, and treated as one.
- **`delete` on a non-existent record** answers `404`. A success for `CleanUp` — otherwise
  challenges would stay in an error state forever.
- **Never send a `zone` parameter.** With `zone`, the module takes `record` literally, and a token
  with `limit_records = _acme-challenge` rejects with `403`.
- **The token must be lowercase hex.** The module silently strips other characters and then
  reports `401` — a configuration error would otherwise look like an authentication failure.
  The format is therefore checked when resolving the secret.
- **All parameters go into the query, not the body.** The module reads `$_GET['token']`, a
  query-only source. The fake in `ddnstest` therefore reads exclusively from `r.URL.Query()`: if
  it read from `r.Form`, it would also accept a form body and confirm exactly the change that
  fails with `401` in production.

The full response handling is specified in
[openspec/specs/ispconfig-ddns-client/spec.md](openspec/specs/ispconfig-ddns-client/spec.md).

**One behaviour of the module is not verified:** whether `add` on an existing TXT name with a
*different* value creates a second value. `ddnstest.RecordStore` accepts multi-value RRsets —
"wildcard and apex at the same time" could not be modelled otherwise, and the conformance test
`DeletingOneRecordRetainsOthers` requires it. If the module does not support this, the core use
case fails in production while the test suite stays green. Verify with a wildcard certificate
against the ACME staging directory before relying on it.

### The chart

- **Names are built via `webhook.name` and `webhook.clusterName`, never via `printf` +
  `trunc 63`.** The fullname is already truncated to 63 characters: appending a suffix and
  truncating afterwards cuts the suffix off, and with a long release name **all** derived names
  collapse into the same value — CA and serving certificate in the same secret. `webhook.name`
  truncates the base instead. `webhook.clusterName` (RBAC objects) does not truncate at all, since
  RBAC names allow 253 characters, and includes the namespace, because the fullname does not: two
  installations with the same release name in different namespaces would otherwise describe the
  same cluster-scoped objects.
- **`_validate.yaml` aborts rendering for configurations that could never work** (empty
  `service.ports`, which the schema already rejects; `existingSecret` together with
  `certManager.enabled`; `certManager.enabled=false` without `existingSecret` or without CA trust
  anchor; an `http://` endpoint without `allowInsecureEndpoint`; `networkPolicy` enabled with an
  empty rule list, which means deny-all) and for two that work but are a security risk:
  `serviceAccount.create=false` without `serviceAccount.name` would bind the RBAC to the
  namespace's `default` ServiceAccount, and an empty `rbac.secretResourceNames` grants the
  ClusterRole `get` on every secret in the cluster — whoever may create an issuer chooses via
  `config.endpoint` where the webhook sends a secret it read from the issuer's namespace (for a
  ClusterIssuer: the cluster resource namespace), including secrets that person cannot read.
  Escape hatch for the latter:
  `rbac.acknowledgeUnrestrictedSecretAccess: true`.
- **`values.schema.json` rejects unknown keys** at the top level and under `webhook` (including
  `log` and `otel`), so typos and removed values fail instead of being ignored.
  It also limits `webhook.httpTimeout` to 1s–50s and `terminationGracePeriodSeconds` to at least
  65 (preStop 5s + challenge 55s + telemetry flush 5s), mirroring the webhook's own startup
  checks and shutdown budget.
- The PodDisruptionBudget is only rendered with `replicaCount` > 1.
- **The APIService port comes from `service.ports[0].port`.** `spec.service.port` is freely
  selectable and must hit the service; a hard-coded `443` would leave an APIService that never
  becomes `Available` once the service port is changed.
- `groupName` and `webhook.endpoint` have **no default**; rendering fails without them.

### Design decisions

1. **Two domain packages, no further layering.** The domain logic is parsing configuration,
   resolving a token, normalising an FQDN and issuing one HTTP call; there is no persistence. A
   separate service layer would only delegate. If the logic grows (zone caching, rate limiting),
   introduce one in a change of its own.
2. **cert-manager's cobra entry point is bypassed.** `cmd.RunWebhookServer` builds a cobra command
   with 81 pflag flags, none of which has an environment variable source, and calls `os.Exit`
   itself. Instead, `server.NewWebhookServerOptions` is filled programmatically and
   `RunWebhookServer(ctx)` is called, so the CLI layer is `urfave/cli/v3` with an env var source
   per flag. `cobra` and `pflag` remain transitive dependencies of cert-manager but are not used by
   our code.
3. **The challenge `Type` is only checked when set.** The cert-manager conformance suite builds the
   `ChallengeRequest` itself and sets neither `Type` nor `Action`. A strict check for `dns-01`
   would break the conformance suite. In production cert-manager always sets `Type` to `dns-01`.
4. **Logging is `log/slog` only**; `log.*` and `fmt.Print*` are forbidden by `forbidigo`.

## Process

- Behaviour changes go through [OpenSpec](https://github.com/Fission-AI/OpenSpec)
  (`openspec list`, `openspec view`) and are test-driven: write a failing test first. Pure bug fixes
  and documentation changes need no spec change unless they change specified behaviour.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- Comments explain why, not what; identifiers, comments, messages and documentation are English.
- Prefer the standard library and existing dependencies; discuss a new dependency in an issue
  first.
- Releases are cut by pushing a tag `vX.Y.Z` (see README, "Releases").
